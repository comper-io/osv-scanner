package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	scalibrconfig "github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/helper"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/utility/severity"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v3"
)

// ScanSummary holds counts of vulnerabilities by severity and deprecated packages.
type ScanSummary struct {
	Critical     int `json:"critical"`
	High         int `json:"high"`
	Medium       int `json:"medium"`
	Low          int `json:"low"`
	Unknown      int `json:"unknown"`
	Unmaintained int `json:"unmaintained"`
}

// ScanResponse is the server's JSON response, embedding VulnerabilityResults and adding a summary.
type ScanResponse struct {
	Summary ScanSummary `json:"summary"`
	models.VulnerabilityResults
}

type ScanRequest struct {
	Repo string `json:"repo"`
	// Date is an optional ISO 8601 date or date-time (e.g. 2024-01-15 or 2024-01-15T12:00:00Z).
	// When provided, only vulnerabilities that were publicly known
	// (i.e. published) on or before this date will be returned.
	Date string `json:"date,omitempty"`
}

func Command(stdout, stderr io.Writer, clientFactories scalibrconfig.ClientFactories) *cli.Command {
	return &cli.Command{
		Name:        "server",
		Usage:       "Runs osv-scanner in server mode to avoid database reload overhead.",
		Description: "Starts an HTTP server that accepts scan requests via POST /scan.",
		Flags: append([]cli.Flag{
			&cli.StringFlag{
				Name:  "listen",
				Value: "0.0.0.0:8080",
				Usage: "address to listen on (e.g. 0.0.0.0:8080 for all interfaces)",
			},
		}, helper.BuildCommonScanFlags([]string{"lockfile", "sbom", "directory"})...),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			addr := cmd.String("listen")

			scanLicensesAllowlist, err := helper.GetScanLicensesAllowlist(cmd)
			if err != nil {
				return err
			}
			experimentalScannerActions := helper.GetExperimentalScannerActions(cmd)
			scannerAction := helper.GetCommonScannerActions(cmd, scanLicensesAllowlist)
			scannerAction.ExperimentalScannerActions = experimentalScannerActions
			if clientFactories != nil {
				scannerAction.ScalibrConfig = &scalibrconfig.PluginConfig{
					ClientFactories: clientFactories,
				}
			}

			http.HandleFunc("/scan", handleScan(scannerAction))

			cmdlogger.Infof("Server starting on %s", addr)
			cmdlogger.Infof("To scan a repo: curl -X POST -d '{\"repo\": \"/path/to/repo\"}' http://%s/scan", addr)

			return http.ListenAndServe(addr, nil)
		},
	}
}

func handleScan(baseAction osvscanner.ScannerActions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
			return
		}

		var req ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		if req.Repo == "" {
			http.Error(w, "Missing 'repo' in JSON body", http.StatusBadRequest)
			return
		}

		var cutoff time.Time
		if req.Date != "" {
			parsed, err := parseScanDate(req.Date)
			if err != nil {
				http.Error(w, "Invalid 'date' in JSON body (expected ISO 8601 date or date-time): "+err.Error(), http.StatusBadRequest)
				return
			}
			cutoff = parsed
		}

		action := baseAction
		action.Repo = req.Repo
		action.VulnPublishedCutoff = cutoff

		results, err := osvscanner.DoScan(action)
		// We still want to return results even if vulnerabilities are found
		if err != nil && err != osvscanner.ErrVulnerabilitiesFound && err != osvscanner.ErrNoPackagesFound {
			http.Error(w, "Scan failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp := ScanResponse{
			Summary:              buildSummary(&results),
			VulnerabilityResults: results,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			cmdlogger.Errorf("Failed to encode results: %v", err)
		}
	}
}

// parseScanDate parses an ISO 8601 date or date-time for the server scan request.
// Supported forms: date (YYYY-MM-DD), date-time with Z or offset (RFC3339), or date-time in UTC without suffix.
func parseScanDate(s string) (time.Time, error) {
	// Full ISO 8601 / RFC3339 with timezone (e.g. 2024-01-15T12:00:00Z or 2024-01-15T12:00:00+01:00)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}

	// Date only (e.g. 2024-01-15), midnight UTC
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}

	// Date-time without timezone (e.g. 2024-01-15T12:00:00), interpreted as UTC
	if t, err := time.Parse("2006-01-02T15:04:05", s); err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("could not parse date %q", s)
}

// buildSummary walks results and counts vulnerabilities by severity (per group) and deprecated packages.
func buildSummary(results *models.VulnerabilityResults) ScanSummary {
	var s ScanSummary
	for _, pkgSrc := range results.Results {
		for _, pkg := range pkgSrc.Packages {
			if pkg.Package.Deprecated {
				s.Unmaintained++
			}
			for _, group := range pkg.Groups {
				rating, err := severity.CalculateRating(group.MaxSeverity)
				if err != nil {
					s.Unknown++
					continue
				}
				switch rating {
				case severity.CriticalRating:
					s.Critical++
				case severity.HighRating:
					s.High++
				case severity.MediumRating:
					s.Medium++
				case severity.LowRating:
					s.Low++
				default:
					s.Unknown++
				}
			}
		}
	}
	return s
}
