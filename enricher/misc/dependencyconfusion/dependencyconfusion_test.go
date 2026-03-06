// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dependencyconfusion

import (
	"testing"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
)

func TestDependencyConfusionScan(t *testing.T) {

	tests := []struct {
		name               string
		internalNamespaces []string
		internalPackages   []string
		packages           []*extractor.Package
		wantFinding        bool
	}{
		{
			name:               "No_internal_config_means_no_findings",
			internalNamespaces: []string{},
			internalPackages:   []string{},
			packages: []*extractor.Package{
				{
					Name:     "@company/auth",
					Version:  "1.0.0",
					PURLType: purl.TypeNPM,
					Metadata: &metadata.JavascriptPackageJSONMetadata{
						Source: metadata.PublicRegistry,
					},
				},
			},
			wantFinding: false,
		},
		{
			name:               "Internal_package_from_public_registry_VULNERABLE",
			internalNamespaces: []string{"@company/"},
			internalPackages:   []string{"secret-core"},
			packages: []*extractor.Package{
				{
					Name:     "@company/auth",
					Version:  "1.0.0",
					PURLType: purl.TypeNPM,
					Metadata: &metadata.JavascriptPackageJSONMetadata{
						Source: metadata.PublicRegistry, // This is the vector
					},
				},
			},
			wantFinding: true, // Alerts
		},
		{
			name:               "Explicit_internal_package_name_from_public_registry_VULNERABLE",
			internalNamespaces: []string{},
			internalPackages:   []string{"secret-core"},
			packages: []*extractor.Package{
				{
					Name:     "secret-core",
					Version:  "1.0.0",
					PURLType: purl.TypeNPM,
					Metadata: &metadata.JavascriptPackageJSONMetadata{
						Source: metadata.PublicRegistry, // This is the vector
					},
				},
			},
			wantFinding: true, // Alerts
		},
		{
			name:               "Internal_package_from_local_disk_SAFE",
			internalNamespaces: []string{"@company/"},
			internalPackages:   []string{"secret-core"},
			packages: []*extractor.Package{
				{
					Name:     "@company/auth",
					Version:  "1.0.0",
					PURLType: purl.TypeNPM,
					Metadata: &metadata.JavascriptPackageJSONMetadata{
						Source: metadata.Local, // Built internally
					},
				},
			},
			wantFinding: false, // Safe
		},
		{
			name:               "Valid_public_package_from_public_registry_SAFE",
			internalNamespaces: []string{"@company/"},
			internalPackages:   []string{"secret-core"},
			packages: []*extractor.Package{
				{
					Name:     "express",
					Version:  "4.17.1",
					PURLType: purl.TypeNPM,
					Metadata: &metadata.JavascriptPackageJSONMetadata{
						Source: metadata.PublicRegistry, // Unrelated package
					},
				},
			},
			wantFinding: false, // Safe
		},
		{
			name:               "Missing_metadata_handled_gracefully",
			internalNamespaces: []string{"@company/"},
			internalPackages:   []string{"secret-core"},
			packages: []*extractor.Package{
				{
					Name:     "@company/auth",
					Version:  "1.0.0",
					PURLType: purl.TypeNPM,
					Metadata: nil,
				},
			},
			wantFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup config
			cfg := &cpb.PluginConfig{
				PluginSpecific: []*cpb.PluginSpecificConfig{
					{
						Config: &cpb.PluginSpecificConfig_DependencyConfusion{
							DependencyConfusion: &cpb.DependencyConfusionConfig{
								InternalNamespaces: tt.internalNamespaces,
								InternalPackages:   tt.internalPackages,
							},
						},
					},
				},
			}

			d, err := New(cfg)
			if err != nil {
				t.Fatalf("Failed to create enricher: %v", err)
			}

			inv := &inventory.Inventory{Packages: tt.packages}

			fsys := scalibrfs.ScanRoot{}

			err = d.Enrich(t.Context(), &enricher.ScanInput{ScanRoot: &fsys}, inv)
			if err != nil {
				t.Fatalf("Enrich returned unexpected error: %v", err)
			}

			hasFinding := len(inv.GenericFindings) > 0

			if hasFinding != tt.wantFinding {
				t.Errorf("Enrich() returned finding = %v, wantFinding = %v", hasFinding, tt.wantFinding)
			}
		})
	}
}
