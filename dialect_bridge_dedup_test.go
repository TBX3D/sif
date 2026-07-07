package sif

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/vmfunc/sif/internal/config"
)

// writeFingerprintModule drops a single fingerprint module yaml into
// tmp/modules/<id>.yaml. NewLoader prefers an on-disk modules/ dir over the
// embedded fs, so combined with t.Chdir(tmp) this is the only module the
// loader sees for the test.
func writeFingerprintModule(t *testing.T, tmp, id, yaml string) {
	t.Helper()
	dir := filepath.Join(tmp, "modules")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir modules dir: %v", err)
	}
	path := filepath.Join(dir, id+".yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write module %s: %v", path, err)
	}
}

// neutralSettings returns a Settings baseline with every other scanner
// disabled, so scanTarget only runs framework detection and the module
// engine.
func neutralSettings() *config.Settings {
	return &config.Settings{
		NoScan:  true,
		Dirlist: "none",
		Dnslist: "none",
		Ports:   "none",
	}
}

// TestBridgedFingerprintSingleSurfacesWhenFrameworkOn drives the real
// scanTarget path (real frameworks.DetectFrameworks, real module execute
// loop, real collectFindings) with both -framework and the module engine on,
// and asserts the bridged fingerprint surfaces exactly once: through the
// promoted framework detector, never through the native module run.
func TestBridgedFingerprintSingleSurfacesWhenFrameworkOn(t *testing.T) {
	const id = "acme-fp"
	const token = "AcmeSrvTokenA"

	tmp := t.TempDir()
	writeFingerprintModule(t, tmp, id, fmt.Sprintf(`id: %s
type: fingerprint
info:
  name: Acme
  severity: info
fingerprint:
  signatures:
    - pattern: %s
      weight: 1
`, id, token))
	t.Chdir(tmp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, token)
	}))
	defer srv.Close()

	settings := neutralSettings()
	settings.Framework = true
	settings.Modules = id

	app := &App{settings: settings}
	app.setupDialectBridge()

	if !app.bridged[id] {
		t.Fatalf("expected %q to be bridged, app.bridged = %+v", id, app.bridged)
	}

	ts, err := app.scanTarget(context.Background(), srv.URL, "", false)
	if err != nil {
		t.Fatalf("scanTarget: %v", err)
	}

	var framework, module int
	for _, f := range ts.findings {
		if f.Module == "framework" && f.Key == "framework:"+id {
			framework++
		}
		if f.Module == id {
			module++
		}
	}
	if framework != 1 {
		t.Fatalf("got %d framework findings for %q, want exactly 1: %+v", framework, id, ts.findings)
	}
	if module != 0 {
		t.Fatalf("got %d native module findings for %q, want exactly 0 (bridged module should be skipped): %+v", module, id, ts.findings)
	}
}

// TestFingerprintRunsAsModuleWhenFrameworkOff proves the standalone module
// path is untouched when -framework is off: setupDialectBridge early-returns,
// app.bridged stays nil, and the fingerprint fires through the native module
// engine as it always has.
func TestFingerprintRunsAsModuleWhenFrameworkOff(t *testing.T) {
	const id = "acme-fp-off"
	const token = "AcmeSrvTokenB"

	tmp := t.TempDir()
	writeFingerprintModule(t, tmp, id, fmt.Sprintf(`id: %s
type: fingerprint
info:
  name: AcmeOff
  severity: info
fingerprint:
  signatures:
    - pattern: %s
      weight: 1
`, id, token))
	t.Chdir(tmp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, token)
	}))
	defer srv.Close()

	settings := neutralSettings()
	settings.Framework = false
	settings.Modules = id

	app := &App{settings: settings}
	app.setupDialectBridge()

	if app.bridged != nil {
		t.Fatalf("expected app.bridged to stay nil when framework is off, got %+v", app.bridged)
	}

	ts, err := app.scanTarget(context.Background(), srv.URL, "", false)
	if err != nil {
		t.Fatalf("scanTarget: %v", err)
	}

	var framework, module int
	for _, f := range ts.findings {
		if f.Module == "framework" && f.Key == "framework:"+id {
			framework++
		}
		if f.Module == id {
			module++
		}
	}
	if module != 1 {
		t.Fatalf("got %d native module findings for %q, want exactly 1: %+v", module, id, ts.findings)
	}
	if framework != 0 {
		t.Fatalf("got %d framework findings for %q, want exactly 0 (framework is off): %+v", framework, id, ts.findings)
	}
}

// TestNonBridgeableFingerprintRunsAsModuleWithFrameworkOn proves a
// fingerprint that fails bridgeableToFramework's guard (here: non-root path)
// is never promoted, so it always runs natively as a module even when
// -framework is on and the module engine is also on.
func TestNonBridgeableFingerprintRunsAsModuleWithFrameworkOn(t *testing.T) {
	const id = "acme-np"
	const token = "AcmeSrvTokenC"

	tmp := t.TempDir()
	writeFingerprintModule(t, tmp, id, fmt.Sprintf(`id: %s
type: fingerprint
info:
  name: AcmeNP
  severity: info
fingerprint:
  path: /admin
  signatures:
    - pattern: %s
      weight: 1
`, id, token))
	t.Chdir(tmp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			fmt.Fprint(w, token)
			return
		}
		fmt.Fprint(w, "nothing to see here")
	}))
	defer srv.Close()

	settings := neutralSettings()
	settings.Framework = true
	settings.Modules = id

	app := &App{settings: settings}
	app.setupDialectBridge()

	if app.bridged[id] {
		t.Fatalf("expected %q not to be bridged (non-root path fails the guard), app.bridged = %+v", id, app.bridged)
	}

	ts, err := app.scanTarget(context.Background(), srv.URL, "", false)
	if err != nil {
		t.Fatalf("scanTarget: %v", err)
	}

	var framework, module int
	for _, f := range ts.findings {
		if f.Module == "framework" && f.Key == "framework:"+id {
			framework++
		}
		if f.Module == id {
			module++
		}
	}
	if module != 1 {
		t.Fatalf("got %d native module findings for %q, want exactly 1: %+v", module, id, ts.findings)
	}
	if framework != 0 {
		t.Fatalf("got %d framework findings for %q, want exactly 0 (guard failed, never bridged): %+v", framework, id, ts.findings)
	}
}
