package sif

import (
	"testing"

	"github.com/vmfunc/sif/internal/modules"
	"github.com/vmfunc/sif/internal/scan/frameworks"
)

// TestBridgedFingerprintDoubleSurfacesInReportAssembly is the pre-wiring dedup
// check the dialect-bridge spec calls out as its one unverified corner: if a
// scan enables both -framework and the module engine (-all-modules /
// -modules / -module-tags), a bridged fingerprint module now fires through
// TWO independent paths for the same underlying hit:
//
//   - frameworks.DetectFrameworks sees the bridged detector in its registry
//     and reports a *frameworks.FrameworkResult (finding.Flatten -> "framework").
//   - the module engine still runs the same fingerprint module natively and
//     reports its own *modules.Result (finding.Flatten -> the module's own id).
//
// collectFindings (sif.go) flattens every moduleResults entry independently
// with no cross-entry identity check, and finding.Key differs between the two
// paths (key("framework", name) vs key(module, url)), so nothing downstream
// collapses them. This test proves the double-surface directly against the
// real report-assembly code path, without needing to drive an actual scan.
func TestBridgedFingerprintDoubleSurfacesInReportAssembly(t *testing.T) {
	const target = "https://example.test"
	const id = "acme-fingerprint"

	frameworkHit := frameworks.NewFrameworkResult(id, "", 0.9, 0)
	moduleHit := &modules.Result{
		ModuleID: id,
		Target:   target,
		Findings: []modules.Finding{{
			URL:        target + "/",
			Severity:   "low",
			Evidence:   "nginx",
			Confidence: 0.9,
		}},
	}

	moduleResults := []ModuleResult{
		NewModuleResult(frameworkHit),
		NewModuleResult(moduleHit),
	}

	findings := collectFindings(target, moduleResults)
	if len(findings) != 2 {
		t.Fatalf("collectFindings returned %d findings, want 2 (one per surfacing path): %+v", len(findings), findings)
	}

	// both findings trace back to the same underlying detector id but carry
	// different Module/Key, confirming no dedup layer collapses them.
	var sawFramework, sawModule bool
	for _, f := range findings {
		switch f.Module {
		case "framework":
			sawFramework = true
		case id:
			sawModule = true
		}
	}
	if !sawFramework || !sawModule {
		t.Fatalf("expected one finding from each surfacing path, got: %+v", findings)
	}
	if findings[0].Key == findings[1].Key {
		t.Fatalf("findings unexpectedly share a Key %q; a dedup layer may already exist", findings[0].Key)
	}
}
