package osvscanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/plugin"
	scanconfig "github.com/google/osv-scanner/v2/internal/config"
)

func Test_networkCapability(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		actions ScannerActions
		want    plugin.Network
	}{
		{
			name: "default_online",
			want: plugin.NetworkOnline,
		},
		{
			name: "offline_vulnerabilities_keeps_network_online",
			actions: ScannerActions{
				CompareOffline: true,
			},
			want: plugin.NetworkOnline,
		},
		{
			name: "plugin_network_disabled_sets_network_offline",
			actions: ScannerActions{
				PluginNetworkDisabled: true,
			},
			want: plugin.NetworkOffline,
		},
		{
			name: "full_offline_sets_network_offline",
			actions: ScannerActions{
				CompareOffline:        true,
				PluginNetworkDisabled: true,
			},
			want: plugin.NetworkOffline,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := networkCapability(tt.actions); got != tt.want {
				t.Errorf("networkCapability(%+v) = %v, want %v", tt.actions, got, tt.want)
			}
		})
	}
}

func TestScanIncludesPackageJSONDependencies(t *testing.T) {
	dir := t.TempDir()
	packageJSON := `{
		"name": "example-app",
		"version": "1.0.0",
		"dependencies": {
			"lodash": "^4.17.20"
		}
	}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(packageJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	manager := &scanconfig.Manager{
		DefaultConfig: scanconfig.Config{},
		ConfigMap:     make(map[string]scanconfig.Config),
	}
	inv, _, err := scan(ExternalAccessors{}, ScannerActions{
		DirectoryPaths:              []string{dir},
		Recursive:                   true,
		PluginNetworkDisabled:       true,
		IncludeManifestDependencies: true,
	}, nil, manager)
	if err != nil {
		t.Fatalf("scan(package.json): %v", err)
	}

	versions := make(map[string]string)
	for _, pkg := range inv.Packages {
		versions[pkg.Name] = pkg.Version
	}
	if got := versions["lodash"]; got != "4.17.20" {
		t.Errorf("lodash version = %q, want 4.17.20; packages: %v", got, versions)
	}
}

func Test_isDescendent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		potentialParent string
		path            string
		recursive       bool
		want            bool
	}{
		{
			name:            "same_path",
			potentialParent: "/a/b",
			path:            "/a/b",
			recursive:       true,
			want:            true,
		},
		{
			name:            "direct_child,_recursive",
			potentialParent: "/a/b",
			path:            "/a/b/c",
			recursive:       true,
			want:            true,
		},
		{
			name:            "direct_child,_non-recursive",
			potentialParent: "/a/b",
			path:            "/a/b/c",
			recursive:       false,
			want:            true,
		},
		{
			name:            "grandchild,_recursive",
			potentialParent: "/a/b",
			path:            "/a/b/c/d",
			recursive:       true,
			want:            true,
		},
		{
			name:            "grandchild,_non-recursive",
			potentialParent: "/a/b",
			path:            "/a/b/c/d",
			recursive:       false,
			want:            false,
		},
		{
			name:            "not_a_descendent",
			potentialParent: "/a/b",
			path:            "/a/c",
			recursive:       true,
			want:            false,
		},
		{
			name:            "different_root",
			potentialParent: "/a/b",
			path:            "/x/y",
			recursive:       true,
			want:            false,
		},
		{
			name:            "relative_path,_direct_child,_recursive",
			potentialParent: "a/b",
			path:            "a/b/c",
			recursive:       true,
			want:            true,
		},
		{
			name:            "relative_path,_grandchild,_non-recursive",
			potentialParent: "a/b",
			path:            "a/b/c/d",
			recursive:       false,
			want:            false,
		},
		{
			name:            "relative_path,_not_a_descendent",
			potentialParent: "a/b",
			path:            "a/c",
			recursive:       true,
			want:            false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Normalize paths for the current OS
			potentialParent := filepath.FromSlash(tt.potentialParent)
			path := filepath.FromSlash(tt.path)
			if got := isDescendent(potentialParent, path, tt.recursive); got != tt.want {
				t.Errorf("isDescendent(%q, %q, %v) = %v, want %v", tt.potentialParent, tt.path, tt.recursive, got, tt.want)
			}
		})
	}
}
