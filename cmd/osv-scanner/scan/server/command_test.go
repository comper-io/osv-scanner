package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
)

func TestHandleScanFiles(t *testing.T) {
	var uploadRoot string
	scan := func(action osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
		if !action.Recursive {
			t.Error("uploaded file scan is not recursive")
		}
		if !action.IncludeManifestDependencies {
			t.Error("uploaded file scan does not include manifest dependencies")
		}
		if action.Repo != "" {
			t.Errorf("action.Repo = %q, want empty", action.Repo)
		}
		if len(action.LockfilePaths) != 2 {
			t.Fatalf("action.LockfilePaths = %v, want two uploaded files", action.LockfilePaths)
		}
		uploadRoot = filepath.Dir(action.LockfilePaths[0])

		wantFiles := map[string]string{
			"package.json":                   `{"name":"app","version":"1.0.0"}`,
			"packages/web/package-lock.json": `{"lockfileVersion":3}`,
		}
		for path, want := range wantFiles {
			got, err := os.ReadFile(filepath.Join(uploadRoot, filepath.FromSlash(path)))
			if err != nil {
				t.Errorf("ReadFile(%q): %v", path, err)
				continue
			}
			if string(got) != want {
				t.Errorf("ReadFile(%q) = %q, want %q", path, got, want)
			}
		}

		return models.VulnerabilityResults{Results: []models.PackageSource{{
			Source: models.SourceInfo{Path: filepath.Join(uploadRoot, "package.json")},
		}}}, nil
	}

	body := `{"files":[` +
		`{"path":"package.json","content":"{\"name\":\"app\",\"version\":\"1.0.0\"}"},` +
		`{"path":"packages/web/package-lock.json","content":"{\"lockfileVersion\":3}"}` +
		`]}`
	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleScanWithScanner(osvscanner.ScannerActions{}, scan).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var response ScanResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("Decode(response): %v", err)
	}
	if got := response.Results[0].Source.Path; got != "package.json" {
		t.Errorf("response source path = %q, want package.json", got)
	}
	if _, err := os.Stat(uploadRoot); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temporary upload root still exists: %v", err)
	}
}

func TestHandleScanRejectsInvalidFileRequests(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "repo and files", body: `{"repo":"repo","files":[{"path":"package.json","content":"{}"}]}`},
		{name: "missing input", body: `{}`},
		{name: "commit without repo", body: `{"commit":"abc","files":[{"path":"package.json","content":"{}"}]}`},
		{name: "parent traversal", body: `{"files":[{"path":"../package.json","content":"{}"}]}`},
		{name: "nested traversal", body: `{"files":[{"path":"a/../../package.json","content":"{}"}]}`},
		{name: "absolute path", body: `{"files":[{"path":"/etc/passwd","content":"x"}]}`},
		{name: "windows path", body: `{"files":[{"path":"C:\\\\temp\\\\package.json","content":"{}"}]}`},
		{name: "duplicate path", body: `{"files":[{"path":"a/../package.json","content":"a"},{"path":"package.json","content":"b"}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			handleScanWithScanner(osvscanner.ScannerActions{}, func(osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
				t.Fatal("scan called for invalid request")
				return models.VulnerabilityResults{}, nil
			}).ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		})
	}
}

func TestHandleScanRepoRemainsSupported(t *testing.T) {
	scan := func(action osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
		if action.Repo != "/repo" || action.RepoCommit != "abc123" {
			t.Errorf("repo action = (%q, %q), want (/repo, abc123)", action.Repo, action.RepoCommit)
		}
		return models.VulnerabilityResults{}, nil
	}
	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(`{"repo":"/repo","commit":"abc123"}`))
	rec := httptest.NewRecorder()
	handleScanWithScanner(osvscanner.ScannerActions{}, scan).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestHandleScanPackageJSONDependencies(t *testing.T) {
	body := `{"files":[{"path":"package.json","content":"{\"name\":\"example-app\",\"version\":\"1.0.0\",\"dependencies\":{\"lodash\":\"^4.17.20\"}}"}]}`
	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleScan(osvscanner.ScannerActions{
		PluginNetworkDisabled: true,
		ShowAllPackages:       true,
	}).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var response ScanResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("Decode(response): %v", err)
	}
	for _, source := range response.Results {
		for _, pkg := range source.Packages {
			if pkg.Package.Name == "lodash" && pkg.Package.Version == "4.17.20" {
				if source.Source.Path != "package.json" {
					t.Errorf("source path = %q, want package.json", source.Source.Path)
				}
				return
			}
		}
	}
	t.Fatalf("lodash@4.17.20 not found in response: %+v", response.Results)
}
