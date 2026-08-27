// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/identifiers"
	"github.com/google/osv-scanner/v2/internal/utility/severity"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const maxSummaryDates = 100

// SummariesRequest scans one source and returns vulnerability totals at each requested date.
type SummariesRequest struct {
	Repo   string     `json:"repo"`
	Files  []ScanFile `json:"files,omitempty"`
	Commit string     `json:"commit,omitempty"`
	Dates  []string   `json:"dates"`
}

// DatedSummary is a ScanSummary at the requested publication cutoff.
type DatedSummary struct {
	Date string `json:"date"`
	ScanSummary
}

// SummariesResponse contains summaries in the same order as the requested dates.
type SummariesResponse struct {
	Summaries []DatedSummary `json:"summaries"`
}

type requestedSummaryDate struct {
	input  string
	cutoff time.Time
	index  int
}

func handleSummaries(baseAction osvscanner.ScannerActions) http.HandlerFunc {
	return handleSummariesWithScanner(baseAction, osvscanner.DoScan)
}

func handleSummariesWithScanner(
	baseAction osvscanner.ScannerActions,
	scan func(osvscanner.ScannerActions) (models.VulnerabilityResults, error),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		cmdlogger.Infof("Started request method=%s path=%s", r.Method, r.URL.Path)
		defer func() {
			cmdlogger.Infof("Completed request method=%s path=%s duration=%s", r.Method, r.URL.Path, time.Since(started))
		}()

		if r.Method != http.MethodPost {
			http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxScanRequestBytes)
		var req SummariesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		if req.Repo != "" && len(req.Files) > 0 {
			http.Error(w, "Provide either 'repo' or 'files', not both", http.StatusBadRequest)
			return
		}
		if req.Repo == "" && len(req.Files) == 0 {
			http.Error(w, "Missing 'repo' or 'files' in JSON body", http.StatusBadRequest)
			return
		}
		if req.Commit != "" && req.Repo == "" {
			http.Error(w, "'commit' can only be used with 'repo'", http.StatusBadRequest)
			return
		}
		if len(req.Dates) == 0 {
			http.Error(w, "Missing 'dates' in JSON body", http.StatusBadRequest)
			return
		}
		if len(req.Dates) > maxSummaryDates {
			http.Error(w, fmt.Sprintf("Too many dates (maximum %d)", maxSummaryDates), http.StatusBadRequest)
			return
		}

		dates := make([]requestedSummaryDate, len(req.Dates))
		for i, value := range req.Dates {
			cutoff, err := parseScanDate(value)
			if err != nil {
				http.Error(w, fmt.Sprintf("Invalid 'dates[%d]' in JSON body (expected ISO 8601 date or date-time): %v", i, err), http.StatusBadRequest)
				return
			}
			dates[i] = requestedSummaryDate{input: value, cutoff: cutoff, index: i}
		}
		cmdlogger.Infof("Summaries requested for %d dates based on %d files", len(req.Dates), len(req.Files))

		action := cloneScannerActions(baseAction)
		action.Repo = req.Repo
		action.RepoCommit = req.Commit
		// The scan must return all matched vulnerabilities. Publication cutoffs are
		// applied in memory while walking the requested dates chronologically.
		action.VulnPublishedCutoff = time.Time{}

		if len(req.Files) > 0 {
			uploadedRoot, uploadedPaths, err := stageScanFiles(req.Files)
			if err != nil {
				http.Error(w, "Invalid 'files': "+err.Error(), http.StatusBadRequest)
				return
			}
			defer os.RemoveAll(uploadedRoot)

			action.DirectoryPaths = nil
			action.LockfilePaths = uploadedPaths
			action.SBOMPaths = nil
			action.Recursive = true
			action.IncludeManifestDependencies = true
		}

		results, err := scan(action)
		if err != nil && err != osvscanner.ErrVulnerabilitiesFound && err != osvscanner.ErrNoPackagesFound {
			http.Error(w, "Scan failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp := SummariesResponse{Summaries: buildDatedSummaries(&results, dates)}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			cmdlogger.Errorf("Failed to encode summaries: %v", err)
			return
		}
		cmdlogger.Infof("Returned %d summaries in %.3f seconds", len(resp.Summaries), time.Since(started).Seconds())
	}
}

type summaryEvent struct {
	published time.Time
	state     *packageSummaryState
	node      int
}

type packageSummaryState struct {
	summary *ScanSummary

	parent       []int
	size         []int
	active       []bool
	maxScore     []float64
	firstID      []string
	firstIDUnmnt []bool
	tokens       [][]string
	tokenOwner   map[string]int
}

func newPackageSummaryState(summary *ScanSummary, pkg *models.PackageVulns) *packageSummaryState {
	n := len(pkg.Vulnerabilities)
	s := &packageSummaryState{
		summary:      summary,
		parent:       make([]int, n),
		size:         make([]int, n),
		active:       make([]bool, n),
		maxScore:     make([]float64, n),
		firstID:      make([]string, n),
		firstIDUnmnt: make([]bool, n),
		tokens:       make([][]string, n),
		tokenOwner:   make(map[string]int),
	}

	for i, vuln := range pkg.Vulnerabilities {
		s.parent[i] = i
		s.size[i] = 1
		s.maxScore[i], _, _ = severity.CalculateOverallScore(vuln.GetSeverity())
		s.firstID[i] = vuln.GetId()
		s.firstIDUnmnt[i] = vulnerabilityIsInformationalUnmaintained(vuln)
		s.tokens[i] = vulnerabilityGroupTokens(vuln)
	}
	return s
}

func (s *packageSummaryState) find(node int) int {
	for s.parent[node] != node {
		s.parent[node] = s.parent[s.parent[node]]
		node = s.parent[node]
	}
	return node
}

func (s *packageSummaryState) activate(node int) {
	if s.active[node] {
		return
	}
	s.active[node] = true
	s.adjustGroup(node, 1)

	for _, token := range s.tokens[node] {
		if owner, ok := s.tokenOwner[token]; ok {
			s.union(node, owner)
		}
		s.tokenOwner[token] = node
	}
}

func (s *packageSummaryState) union(a, b int) {
	a = s.find(a)
	b = s.find(b)
	if a == b {
		return
	}

	s.adjustGroup(a, -1)
	s.adjustGroup(b, -1)
	if s.size[a] < s.size[b] {
		a, b = b, a
	}
	s.parent[b] = a
	s.size[a] += s.size[b]
	s.maxScore[a] = max(s.maxScore[a], s.maxScore[b])
	if identifiers.IDSortFunc(s.firstID[b], s.firstID[a]) < 0 {
		s.firstID[a] = s.firstID[b]
		s.firstIDUnmnt[a] = s.firstIDUnmnt[b]
	}
	s.adjustGroup(a, 1)
}

func (s *packageSummaryState) adjustGroup(root, delta int) {
	if s.maxScore[root] < 0 {
		if s.firstIDUnmnt[root] {
			s.summary.Unmaintained += delta
		} else {
			s.summary.Unknown += delta
		}
		return
	}

	rating, err := severity.CalculateRating(fmt.Sprintf("%.1f", s.maxScore[root]))
	if err != nil {
		s.summary.Unknown += delta
		return
	}
	switch rating {
	case severity.CriticalRating:
		s.summary.Critical += delta
	case severity.HighRating:
		s.summary.High += delta
	case severity.MediumRating:
		s.summary.Medium += delta
	case severity.LowRating:
		s.summary.Low += delta
	default:
		s.summary.Unknown += delta
	}
}

func vulnerabilityGroupTokens(vuln *osvschema.Vulnerability) []string {
	tokens := append([]string{vuln.GetId()}, vuln.GetAliases()...)
	tokens = append(tokens, vuln.GetUpstream()...)
	if strings.HasPrefix(vuln.GetId(), "USN-") {
		tokens = append(tokens, vuln.GetRelated()...)
	}
	sort.Strings(tokens)
	tokens = slices.Compact(tokens)
	return slices.DeleteFunc(tokens, func(token string) bool { return token == "" })
}

func vulnerabilityIsInformationalUnmaintained(vuln *osvschema.Vulnerability) bool {
	for _, affected := range vuln.GetAffected() {
		ds := affected.GetDatabaseSpecific()
		if ds == nil {
			continue
		}
		if info, ok := ds.GetFields()["informational"]; ok && info != nil && info.GetStringValue() == "unmaintained" {
			return true
		}
	}
	return false
}

func buildDatedSummaries(results *models.VulnerabilityResults, requested []requestedSummaryDate) []DatedSummary {
	orderedDates := append([]requestedSummaryDate(nil), requested...)
	slices.SortStableFunc(orderedDates, func(a, b requestedSummaryDate) int {
		return a.cutoff.Compare(b.cutoff)
	})

	summary := ScanSummary{}
	var initial []summaryEvent
	var events []summaryEvent
	for i := range results.Results {
		for j := range results.Results[i].Packages {
			pkg := &results.Results[i].Packages[j]
			if pkg.Package.Deprecated {
				summary.Unmaintained++
			}
			state := newPackageSummaryState(&summary, pkg)
			for node, vuln := range pkg.Vulnerabilities {
				event := summaryEvent{state: state, node: node}
				if vuln.GetPublished() == nil {
					initial = append(initial, event)
					continue
				}
				event.published = vuln.GetPublished().AsTime()
				events = append(events, event)
			}
		}
	}

	for _, event := range initial {
		event.state.activate(event.node)
	}
	slices.SortStableFunc(events, func(a, b summaryEvent) int {
		return a.published.Compare(b.published)
	})

	response := make([]DatedSummary, len(requested))
	eventIndex := 0
	for _, requestedDate := range orderedDates {
		for eventIndex < len(events) && !events[eventIndex].published.After(requestedDate.cutoff) {
			events[eventIndex].state.activate(events[eventIndex].node)
			eventIndex++
		}
		response[requestedDate.index] = DatedSummary{
			Date:        requestedDate.input,
			ScanSummary: summary,
		}
	}
	return response
}
