package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/helper"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v3"
)

var (
	accessors   *osvscanner.ExternalAccessors
	accessorsMu sync.Mutex
)

type ScanRequest struct {
	Repo string `json:"repo"`
}

func Command(stdout, stderr io.Writer, client *http.Client) *cli.Command {
	return &cli.Command{
		Name:        "server",
		Usage:       "Runs osv-scanner in server mode to avoid database reload overhead.",
		Description: "Starts an HTTP server that accepts scan requests via POST /scan.",
		Flags: append([]cli.Flag{
			&cli.StringFlag{
				Name:  "listen",
				Value: "localhost:8080",
				Usage: "address to listen on",
			},
		}, helper.BuildCommonScanFlags([]string{"lockfile", "sbom", "directory"})...),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			addr := cmd.String("listen")

			scanLicensesAllowlist, err := helper.GetScanLicensesAllowlist(cmd)
			if err != nil {
				return err
			}
			experimentalScannerActions := helper.GetExperimentalScannerActions(cmd, client)
			scannerAction := helper.GetCommonScannerActions(cmd, scanLicensesAllowlist)
			scannerAction.ExperimentalScannerActions = experimentalScannerActions
			scannerAction.FullLoadLocalDB = true

			a, err := osvscanner.InitializeExternalAccessors(scannerAction)
			if err != nil {
				return err
			}
			accessors = &a

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

		action := baseAction
		action.Repo = req.Repo

		results, err := osvscanner.DoScanWithAccessors(action, *accessors)
		// We still want to return results even if vulnerabilities are found
		if err != nil && err != osvscanner.ErrVulnerabilitiesFound && err != osvscanner.ErrNoPackagesFound {
			http.Error(w, "Scan failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(results); err != nil {
			cmdlogger.Errorf("Failed to encode results: %v", err)
		}
	}
}

