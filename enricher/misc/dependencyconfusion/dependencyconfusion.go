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

// Package dependencyconfusion implements an enricher for Dependency Confusion in NPM packages.
package dependencyconfusion

import (
	"context"
	"fmt"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the enricher.
	Name = "misc/dependencyconfusion"
)

// Enricher is a SCALIBR enricher for Dependency Confusion vulnerabilities for internally developed packages.
type Enricher struct {
	internalNamespaces []string
	internalPackages   []string
}

// publicRegistryChecker represents any metadata struct that can indicate its source.
type publicRegistryChecker interface {
	IsPublicRegistry() bool
}

// New returns an enricher.
func New(cfg *cpb.PluginConfig) (enricher.Enricher, error) {
	d := &Enricher{
		internalNamespaces: []string{},
		internalPackages:   []string{},
	}

	if cfg != nil {
		for _, pc := range cfg.PluginSpecific {
			if dc := pc.GetDependencyConfusion(); dc != nil {
				d.internalNamespaces = dc.InternalNamespaces
				d.internalPackages = dc.InternalPackages
			}
		}
	}

	return d, nil
}

// Name of the enricher.
func (Enricher) Name() string { return Name }

// Version of the enricher.
func (Enricher) Version() int { return 0 }

// RequiredPlugins returns a list of Plugins that need to be enabled for this Enricher to run.
func (Enricher) RequiredPlugins() []string {
	return []string{"misc/npm-source"}
}

// Requirements of the Enricher.
func (Enricher) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// Enrich starts the scan to find dependency confusion attacks by querying extracted packages in the inventory.
func (e Enricher) Enrich(ctx context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	if len(e.internalNamespaces) == 0 && len(e.internalPackages) == 0 {
		// Nothing to detect if no internal packages are configured.
		return nil
	}

	var compromisedPackages []string

	for _, pkg := range inv.Packages {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if pkg.Metadata == nil {
			continue // No metadata to check the source
		}

		checker, ok := pkg.Metadata.(publicRegistryChecker)
		if !ok {
			continue // Metadata doesn't implement the generic check
		}

		// Dependency confusion occurs when an INTERNAL package is fetched from the PUBLIC registry.
		if checker.IsPublicRegistry() {
			if e.isInternalPackage(pkg) {
				msg := fmt.Sprintf("Package %q at version %s was resolved from the public registry but matches internal configuration.", pkg.Name, pkg.Version)
				compromisedPackages = append(compromisedPackages, msg)
			}
		}
	}

	if len(compromisedPackages) > 0 {
		target := &inventory.GenericFindingTargetDetails{Extra: strings.Join(compromisedPackages, "\n")}
		finding := e.findingForTarget(target)
		inv.GenericFindings = append(inv.GenericFindings, &finding)
	}

	return nil
}

// findingForTarget returns generic vulnerability information about what is detected.
func (e Enricher) findingForTarget(target *inventory.GenericFindingTargetDetails) inventory.GenericFinding {
	return inventory.GenericFinding{
		Adv: &inventory.GenericFindingAdvisory{
			ID: &inventory.AdvisoryID{
				Publisher: "SCALIBR",
				Reference: "dependency-confusion",
			},
			Title: "Dependency Confusion",
			Description: "An internal package name was resolved and downloaded from a public registry " +
				"instead of your internal registry. This indicates a highly critical " +
				"Dependency Confusion attack where malicious code might be executing in your environment.",
			Recommendation: "Immediately investigate the lockfile and the package source. " +
				"Configure your package manager to route this scope/package exclusively to your internal registry " +
				"and verify your internal package names are explicitly claimed or scoped on public registries.",
			Sev: inventory.SeverityCritical,
		},
		Target: target,
	}
}

// isInternalPackage checks if a given package name matches the configured internal namespaces or explicitly configured internal package names.
func (e Enricher) isInternalPackage(pkg *extractor.Package) bool {
	for _, ns := range e.internalNamespaces {
		if strings.HasPrefix(pkg.Name, ns) {
			return true
		}
	}

	for _, name := range e.internalPackages {
		if pkg.Name == name {
			return true
		}
	}

	return false
}
