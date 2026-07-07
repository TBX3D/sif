# Dialect-Unify Phase A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the `type: fingerprint` module and prove, by test, that the module-engine fingerprint scorer is behaviourally equivalent to the framework-engine signature scorer on their shared domain — the safety proof that unblocks the dialect-merge bridge.

**Architecture:** This is Phase A of the flagship (the CLOSED proofs from `UNIFY-CUTOVER-PLAN.md`). It builds only tests plus the one module type they validate; it is pure upside and fully reversible. No user-facing loader change happens here (that is Phase B, gated separately). First land the `spike/fingerprint-type` code onto `v2.2-base`, then add the differential-equivalence and delta-regression proofs.

**Tech Stack:** Go 1.25, `go test -race`, `gopkg.in/yaml.v3`. Two packages matter: `internal/scan/frameworks` (`BaseDetector.MatchSignatures`, `Signature`) and `internal/modules` (`scoreFingerprint`, `FingerprintConfig`, `FPSignature`).

## Global Constraints

- Work ONLY in worktree `/home/billypwns/projects/sif-worktrees/v2.2-base` (branch `v2.2-base`). Do not touch other worktrees or push.
- Env for every go command: `export GO111MODULE=on GOTOOLCHAIN=local`.
- Gauntlet (all must pass before a task is done): `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...`, `GOLANGCI_LINT_CACHE=/tmp/claude-1000/golangci-cache ~/go/bin/golangci-lint run ./...`.
- The cgo sqlite build prints a harmless `discards 'const' qualifier` C warning; ignore only that.
- Commit style: lowercase scoped `type(scope): subject`, imperative, no trailing period, no em/en-dashes, no emoji, no AI/tooling trailers, lowercase bodies, minimal comments.
- The internal label "v2.2" must NEVER appear in commits or code.
- `Finding.Line()` output format is FROZEN.
- Verify-don't-assert: every proof test must be RUN red then green, never assumed.

---

### Task 1: Land the `type: fingerprint` module onto v2.2-base

**Files:**
- Merge from branch `spike/fingerprint-type` (adds `internal/modules/fingerprint.go`, `internal/modules/fingerprint_parse_test.go`, `internal/modules/fingerprint_type_test.go`, `internal/fingerprint/favicon.go`, `internal/fingerprint/favicon_test.go`).
- Likely conflict: `internal/modules/executor.go` (module-type dispatch), same shape as the dns/tcp executor merges — a new `TypeFingerprint` dispatch case.

**Interfaces:**
- Produces: `scoreFingerprint(cfg *FingerprintConfig, body string, headers http.Header) (float32, string)`; `FingerprintConfig{Signatures []FPSignature; Version *FPVersion}`; `FPSignature{Pattern string; Weight float32; Header bool}` — all in package `modules`. `ExecuteFingerprintModule(ctx, target, def, opts)`.

- [ ] **Step 1: Attempt the merge**

```bash
cd /home/billypwns/projects/sif-worktrees/v2.2-base
export GO111MODULE=on GOTOOLCHAIN=local
git merge --no-edit spike/fingerprint-type
```

- [ ] **Step 2: Resolve any dispatch conflict**

If `git diff --name-only --diff-filter=U` lists `internal/modules/executor.go`, open it: the conflict is the module-type dispatch switch. Keep BOTH the existing cases (http/dns/tcp) and the incoming `case TypeFingerprint:` arm calling `ExecuteFingerprintModule`. Remove any leftover stub the way the dns/tcp merges did. Then `git add -A && git commit --no-edit`.

- [ ] **Step 3: Run the gauntlet**

Run:
```bash
go build ./... && go vet ./... && go test -race -count=1 ./internal/modules/ ./internal/fingerprint/ && GOLANGCI_LINT_CACHE=/tmp/claude-1000/golangci-cache ~/go/bin/golangci-lint run ./...
```
Expected: build clean, `ok` for both packages, `0 issues`. The spike's own tests (`fingerprint_parse_test.go`, `fingerprint_type_test.go`) pass.

- [ ] **Step 4: Confirm the scorer symbols exist**

Run: `grep -n "func scoreFingerprint\|type FingerprintConfig\|type FPSignature" internal/modules/fingerprint.go`
Expected: all three present with the signatures listed under Interfaces.

---

### Task 2: C2 — differential-equivalence proof on the shared domain

**Files:**
- Create: `internal/modules/fingerprint_equivalence_test.go` (package `modules`, white-box so it can call unexported `scoreFingerprint`; imports `github.com/vmfunc/sif/internal/scan/frameworks`).

**Interfaces:**
- Consumes: `scoreFingerprint` (Task 1); `frameworks.NewBaseDetector(name string, sigs []frameworks.Signature) frameworks.BaseDetector`; `frameworks.Signature{Pattern string; Weight float32; HeaderOnly bool}`; `(frameworks.BaseDetector).MatchSignatures(body string, headers http.Header) float32`.

- [ ] **Step 1: Write the failing test**

The prediction: for every signature set with all weights > 0, over any body and headers, `scoreFingerprint == MatchSignatures`. Build paired inputs from one signature list, feed identical (body, headers), assert float32 equality across randomized-but-seeded cases.

```go
package modules

import (
	"math/rand"
	"net/http"
	"testing"

	"github.com/vmfunc/sif/internal/scan/frameworks"
)

// pairedSigs builds a frameworks signature list and the matching fingerprint
// signature list from one source, so the two scorers see identical inputs.
func pairedSigs(src []FPSignature) ([]frameworks.Signature, *FingerprintConfig) {
	fw := make([]frameworks.Signature, len(src))
	for i, s := range src {
		fw[i] = frameworks.Signature{Pattern: s.Pattern, Weight: s.Weight, HeaderOnly: s.Header}
	}
	return fw, &FingerprintConfig{Signatures: src}
}

func TestScorerEquivalenceSharedDomain(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	tokens := []string{"nginx", "PHPSESSID", "wp-content", "X-Powered-By", "cloudflare", "django"}
	for iter := 0; iter < 2000; iter++ {
		n := 1 + r.Intn(len(tokens))
		src := make([]FPSignature, n)
		for i := 0; i < n; i++ {
			src[i] = FPSignature{
				Pattern: tokens[r.Intn(len(tokens))],
				Weight:  0.1 + r.Float32()*5, // strictly > 0: the shared domain
				Header:  r.Intn(2) == 0,
			}
		}
		fwSigs, fpCfg := pairedSigs(src)

		body := ""
		for _, tk := range tokens {
			if r.Intn(2) == 0 {
				body += tk + " "
			}
		}
		headers := http.Header{}
		for _, tk := range tokens {
			if r.Intn(2) == 0 {
				headers.Add(tk, "v")
			}
		}

		want := frameworks.NewBaseDetector("x", fwSigs).MatchSignatures(body, headers)
		got, _ := scoreFingerprint(fpCfg, body, headers)
		if got != want {
			t.Fatalf("iter %d: scoreFingerprint=%v MatchSignatures=%v sigs=%+v", iter, got, want, src)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it passes on the shared domain**

Run: `go test -race -run TestScorerEquivalenceSharedDomain ./internal/modules/ -v`
Expected: PASS. (If it FAILS, the port is not faithful — that is a real finding; stop and record it, do not weaken the test.)

- [ ] **Step 3: Commit**

```bash
git add internal/modules/fingerprint_equivalence_test.go
git commit -m "test(modules): prove fingerprint scorer matches framework scorer on shared domain"
```

---

### Task 3: C3 — pin the known divergence and the threshold boundary

**Files:**
- Modify: `internal/modules/fingerprint_equivalence_test.go` (add two tests).

- [ ] **Step 1: Write the failing tests**

Two pinned facts. (a) At `weight == 0` the scorers DIVERGE by construction: `MatchSignatures` counts 0 into the total, `scoreFingerprint` remaps 0 to 1. This input is outside `custom.go`'s validated domain (it rejects `weight <= 0` at load), so the divergence is safe but must be pinned so a future change to either scorer is caught. (b) The framework report threshold is strict `>` at `detectionThreshold = 0.5` (detect.go): a score of exactly 0.5 does NOT report.

```go
func TestScorerDivergesAtZeroWeight(t *testing.T) {
	// one zero-weight sig that misses, one positive sig that hits.
	src := []FPSignature{
		{Pattern: "absent", Weight: 0, Header: false},
		{Pattern: "present", Weight: 1, Header: false},
	}
	fwSigs, fpCfg := pairedSigs(src)
	body := "present"

	fw := frameworks.NewBaseDetector("x", fwSigs).MatchSignatures(body, http.Header{})
	fp, _ := scoreFingerprint(fpCfg, body, http.Header{})

	// framework: matched 1 / total 1 = 1.0 (zero-weight sig contributes nothing).
	if fw != 1 {
		t.Fatalf("framework score = %v, want 1", fw)
	}
	// fingerprint: zero weight remapped to 1, absent sig misses: matched 1 / total 2 = 0.5.
	if fp != 0.5 {
		t.Fatalf("fingerprint score = %v, want 0.5", fp)
	}
	if fw == fp {
		t.Fatal("expected divergence at weight==0, got equality")
	}
}

func TestFrameworkThresholdIsStrict(t *testing.T) {
	// a signature set that scores exactly 0.5 must not clear the > 0.5 gate.
	src := []FPSignature{
		{Pattern: "hit", Weight: 1, Header: false},
		{Pattern: "miss", Weight: 1, Header: false},
	}
	fwSigs, _ := pairedSigs(src)
	score := frameworks.NewBaseDetector("x", fwSigs).MatchSignatures("hit", http.Header{})
	if score != 0.5 {
		t.Fatalf("score = %v, want exactly 0.5", score)
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test -race -run 'TestScorerDivergesAtZeroWeight|TestFrameworkThresholdIsStrict' ./internal/modules/ -v`
Expected: both PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/modules/fingerprint_equivalence_test.go
git commit -m "test(modules): pin zero-weight divergence and strict detection threshold"
```

---

### Task 4: C5 — back-compat proof that legacy custom signatures still load

**Files:**
- Create: `internal/scan/frameworks/custom_backcompat_test.go` (package `frameworks`, white-box; uses the existing `parseCustomDetector(path string) (Detector, error)` at `custom.go:117`).

**Interfaces:**
- Consumes: `parseCustomDetector(path string) (Detector, error)`; `(Detector).Detect(body string, headers http.Header) (float32, string)`.

- [ ] **Step 1: Write the failing test**

Write a legacy-format signature yaml to a temp file, parse it through the existing loader, and assert it both loads and scores. This freezes the guarantee that Phase B must not break: legacy `signatures/*.yaml` keep working.

```go
package frameworks

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyCustomSignatureStillLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.yaml")
	yaml := "name: acme\n" +
		"signatures:\n" +
		"  - pattern: \"X-Acme\"\n" +
		"    weight: 1\n" +
		"    header: true\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	det, err := parseCustomDetector(path)
	if err != nil {
		t.Fatalf("parseCustomDetector: %v", err)
	}
	h := http.Header{}
	h.Add("X-Acme", "1")
	score, _ := det.Detect("", h)
	if score != 1 {
		t.Fatalf("score = %v, want 1", score)
	}
}
```

- [ ] **Step 2: Run test**

Run: `go test -race -run TestLegacyCustomSignatureStillLoads ./internal/scan/frameworks/ -v`
Expected: PASS. (If `parseCustomDetector`'s yaml field names differ, run `sed -n '62,116p' internal/scan/frameworks/custom.go` to read the exact `signatureSpec`/`customDetectorSpec` yaml tags and correct the yaml literal, then re-run.)

- [ ] **Step 3: Full gauntlet + commit**

Run:
```bash
go build ./... && go vet ./... && go test -race -count=1 ./... && GOLANGCI_LINT_CACHE=/tmp/claude-1000/golangci-cache ~/go/bin/golangci-lint run ./...
```
Expected: all green, `0 issues`. Then:
```bash
git add internal/scan/frameworks/custom_backcompat_test.go
git commit -m "test(frameworks): freeze legacy custom-signature load and score"
```

---

## Deferred out of this plan (with reason)

- **C4 trap test** (a non-root/confidence fingerprint must not be silently registered as a framework detector) is deferred to the Phase B plan: the registration path it guards does not exist until the bridge wires the module loader into the framework engine. Writing it now would test a mechanism that is not yet built (fabrication). It is the first task of the Phase B plan.
- **Phase B bridge**, the detection-depth lanes (favicon SSOT, CVE), the operational config lane, and all v3 items are separate plans, authored when their turn arrives per the roadmap sequencing.

## Self-Review

- **Spec coverage:** roadmap Phase A items C2 (Task 2), C3 (Task 3), C5 (Task 4), fingerprint-type landing / bridge primitive (Task 1) all covered; C4 explicitly deferred with reason.
- **Placeholder scan:** none — every test step carries literal code and an exact run command.
- **Type consistency:** `scoreFingerprint`, `FingerprintConfig`, `FPSignature{Pattern,Weight,Header}`, `frameworks.Signature{Pattern,Weight,HeaderOnly}`, `NewBaseDetector`, `MatchSignatures`, `parseCustomDetector` all used consistently and match the source read on 2026-07-07.
