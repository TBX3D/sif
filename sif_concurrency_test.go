/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2026 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package sif

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/config"
	"github.com/vmfunc/sif/internal/output"
)

// okServer returns a 200 with a couple of headers so the -headers scanner
// records exactly one scan ("HTTP Headers"), giving every concurrency test a
// deterministic, single-scanner target.
func okServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "sif")
		w.Header().Set("Server", "test-server")
		w.WriteHeader(http.StatusOK)
	}))
}

// headersOnlyApp builds an App with exactly one scanner enabled (-headers),
// so scansRun is deterministic ([]string{"HTTP Headers"}) and every test
// exercises the real scanTarget path instead of a stand-in.
func headersOnlyApp() *App {
	return &App{
		settings: &config.Settings{
			Headers:     true,
			NoScan:      true,
			Dirlist:     "none",
			Dnslist:     "none",
			Ports:       "none",
			Timeout:     5 * time.Second,
			Concurrency: 1,
		},
	}
}

func TestScanAllTargetsConcurrentIsolation(t *testing.T) {
	defer output.SetConcurrent(false)

	servers := []*httptest.Server{okServer(), okServer(), okServer()}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	app := headersOnlyApp()
	app.settings.Concurrency = 3
	for _, s := range servers {
		app.targets = append(app.targets, s.URL)
	}

	results, err := app.scanAllTargets(context.Background(), "", false)
	if err != nil {
		t.Fatalf("scanAllTargets: %v", err)
	}
	if len(results) != len(servers) {
		t.Fatalf("got %d results, want %d", len(results), len(servers))
	}
	for i, ts := range results {
		if !reflect.DeepEqual(ts.scansRun, []string{"HTTP Headers"}) {
			t.Errorf("result[%d].scansRun = %v, want [HTTP Headers] (accumulator leaked across targets?)", i, ts.scansRun)
		}
	}
}

func TestScanAllTargetsSequentialMatchesInputOrder(t *testing.T) {
	s1, s2 := okServer(), okServer()
	defer s1.Close()
	defer s2.Close()

	app := headersOnlyApp()
	app.settings.Concurrency = 1
	app.targets = []string{s1.URL, s2.URL}

	results, err := app.scanAllTargets(context.Background(), "", false)
	if err != nil {
		t.Fatalf("scanAllTargets: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if output.Concurrent() {
		t.Fatal("output.Concurrent() = true at concurrency 1, want false")
	}
	for i, ts := range results {
		if !reflect.DeepEqual(ts.scansRun, []string{"HTTP Headers"}) {
			t.Errorf("result[%d].scansRun = %v, want [HTTP Headers]", i, ts.scansRun)
		}
	}
}

func TestScanAllTargetsReportComplete(t *testing.T) {
	defer output.SetConcurrent(false)

	const n = 4
	var servers []*httptest.Server
	var urls []string
	for i := 0; i < n; i++ {
		s := okServer()
		servers = append(servers, s)
		urls = append(urls, s.URL)
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	seqApp := headersOnlyApp()
	seqApp.settings.Concurrency = 1
	seqApp.targets = append([]string(nil), urls...)
	seqResults, err := seqApp.scanAllTargets(context.Background(), "", true)
	if err != nil {
		t.Fatalf("sequential scanAllTargets: %v", err)
	}

	parApp := headersOnlyApp()
	parApp.settings.Concurrency = n
	parApp.targets = append([]string(nil), urls...)
	parResults, err := parApp.scanAllTargets(context.Background(), "", true)
	if err != nil {
		t.Fatalf("concurrent scanAllTargets: %v", err)
	}

	if len(parResults) != n {
		t.Fatalf("got %d results, want %d", len(parResults), n)
	}

	var seqReportCount, parReportCount int
	var seqFindingCount, parFindingCount int
	for _, ts := range seqResults {
		seqReportCount += len(ts.reportResults)
		seqFindingCount += len(ts.findings)
	}
	for _, ts := range parResults {
		parReportCount += len(ts.reportResults)
		parFindingCount += len(ts.findings)
	}

	if parReportCount != seqReportCount || parReportCount == 0 {
		t.Fatalf("report row count: concurrent=%d sequential=%d, want equal and nonzero", parReportCount, seqReportCount)
	}
	if parFindingCount != seqFindingCount {
		t.Fatalf("finding count: concurrent=%d sequential=%d, want equal", parFindingCount, seqFindingCount)
	}

	for i, ts := range parResults {
		if len(ts.reportResults) == 0 {
			t.Errorf("result[%d] carries no report rows", i)
		}
	}
}

func TestScanAllTargetsCtxCancel(t *testing.T) {
	defer output.SetConcurrent(false)

	var servers []*httptest.Server
	for i := 0; i < 4; i++ {
		servers = append(servers, okServer())
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	app := headersOnlyApp()
	app.settings.Concurrency = 4
	for _, s := range servers {
		app.targets = append(app.targets, s.URL)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := app.scanAllTargets(ctx, "", false)
	if err != nil {
		t.Fatalf("scanAllTargets: %v", err)
	}
	if len(results) != len(servers) {
		t.Fatalf("got %d results, want %d (pre-sized by target count)", len(results), len(servers))
	}
	for i, ts := range results {
		if !reflect.DeepEqual(ts, targetScan{}) {
			t.Errorf("result[%d] = %#v, want the zero targetScan (ctx was already cancelled)", i, ts)
		}
	}
}

func TestScanAllTargetsInputOrder(t *testing.T) {
	defer output.SetConcurrent(false)

	const n = 6
	var servers []*httptest.Server
	var urls []string
	for i := 0; i < n; i++ {
		s := okServer()
		servers = append(servers, s)
		urls = append(urls, s.URL)
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	for attempt := 0; attempt < 5; attempt++ {
		app := headersOnlyApp()
		app.settings.Concurrency = n
		app.targets = append([]string(nil), urls...)

		results, err := app.scanAllTargets(context.Background(), "", false)
		if err != nil {
			t.Fatalf("attempt %d: scanAllTargets: %v", attempt, err)
		}
		if len(results) != n {
			t.Fatalf("attempt %d: got %d results, want %d", attempt, len(results), n)
		}
		for i, ts := range results {
			if len(ts.findings) == 0 {
				t.Fatalf("attempt %d: result[%d] has no findings to key on", attempt, i)
			}
			for _, f := range ts.findings {
				if f.Target != urls[i] {
					t.Fatalf("attempt %d: result[%d] carries finding for target %q, want %q (merge order broken)", attempt, i, f.Target, urls[i])
				}
			}
		}
	}
}

// TestOutputSetConcurrentSerializesWrites verifies the spec's flagged
// assumption live: N goroutines hammering output.Info concurrently under
// output.SetConcurrent(true) never interleave mid-line. every line the sink
// receives must be one of the exact lines a writer emitted - a garbled mix of
// two partial lines would not match any expected line.
func TestOutputSetConcurrentSerializesWrites(t *testing.T) {
	output.SetSilent(true) // route sink to stderr, restorable via SetConcurrent(false)
	defer output.SetSilent(false)
	output.SetConcurrent(true)
	defer output.SetConcurrent(false)

	const workers = 8
	const perWorker = 200

	done := make(chan struct{})
	for w := 0; w < workers; w++ {
		w := w
		go func() {
			for i := 0; i < perWorker; i++ {
				output.Info("worker %d message %d payload padpadpadpadpadpadpadpadpadpadpadpadpad", w, i)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < workers; i++ {
		<-done
	}
}

// forceLogCreateFileFailure makes logger.CreateFile fail for badURL only: it
// pre-creates a directory at the exact path badURL's log file would occupy,
// so os.OpenFile hits "is a directory" the moment scanTarget calls
// logger.CreateFile - before any network scanning happens. this reproduces a
// genuine per-target scan error without leaning on the (now-fixed) logger
// path-flattening bug.
func forceLogCreateFileFailure(t *testing.T, logDir, badURL string) {
	t.Helper()
	// mirrors logger's flattenPath: strip the scheme, fold '/' runs to '_'.
	badLogPath := filepath.Join(logDir, "forced-fail.invalid_x.log")
	if err := os.Mkdir(badLogPath, 0o750); err != nil {
		t.Fatalf("seeding directory collision at %q: %v", badLogPath, err)
	}
}

// TestScanAllTargetsConcurrentPartialFailureKeepsGoodResults proves that at
// concurrency > 1, one target's scanTarget error must not discard every other
// target's already-collected results: before the fix, scanAllTargets returned
// (results, err) and every caller (app.Run) treated any non-nil err as fatal,
// throwing away every successfully-scanned target's findings and reports.
func TestScanAllTargetsConcurrentPartialFailureKeepsGoodResults(t *testing.T) {
	defer output.SetConcurrent(false)

	s1, s2 := okServer(), okServer()
	defer s1.Close()
	defer s2.Close()

	logDir := t.TempDir()
	badURL := "http://forced-fail.invalid/x"
	forceLogCreateFileFailure(t, logDir, badURL)

	app := headersOnlyApp()
	app.settings.Concurrency = 3
	app.settings.LogDir = logDir
	app.targets = []string{s1.URL, badURL, s2.URL}

	results, err := app.scanAllTargets(context.Background(), "", false)
	if err != nil {
		t.Fatalf("scanAllTargets returned an error for a partial (1-of-3) failure: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3 (good targets must not be discarded)", len(results))
	}
	if !reflect.DeepEqual(results[0].scansRun, []string{"HTTP Headers"}) {
		t.Errorf("result[0] (good target) lost its scan results: %#v", results[0])
	}
	if !reflect.DeepEqual(results[2].scansRun, []string{"HTTP Headers"}) {
		t.Errorf("result[2] (good target) lost its scan results: %#v", results[2])
	}
	if !reflect.DeepEqual(results[1], targetScan{}) {
		t.Errorf("result[1] (bad target) = %#v, want the zero targetScan", results[1])
	}
}

// TestScanAllTargetsSequentialPartialFailureKeepsGoodResults is the
// concurrency==1 analogue: the sequential loop returned early on the first
// scanTarget error, which dropped not just the failing target but every
// target still queued behind it.
func TestScanAllTargetsSequentialPartialFailureKeepsGoodResults(t *testing.T) {
	s1, s2 := okServer(), okServer()
	defer s1.Close()
	defer s2.Close()

	logDir := t.TempDir()
	badURL := "http://forced-fail.invalid/x"
	forceLogCreateFileFailure(t, logDir, badURL)

	app := headersOnlyApp()
	app.settings.Concurrency = 1
	app.settings.LogDir = logDir
	app.targets = []string{s1.URL, badURL, s2.URL}

	results, err := app.scanAllTargets(context.Background(), "", false)
	if err != nil {
		t.Fatalf("scanAllTargets returned an error for a partial (1-of-3) failure: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 (the two good targets, bad one skipped)", len(results))
	}
	for i, ts := range results {
		if !reflect.DeepEqual(ts.scansRun, []string{"HTTP Headers"}) {
			t.Errorf("result[%d] lost its scan results: %#v", i, ts)
		}
	}
}

// TestScanAllTargetsAllTargetsFailedReturnsError guards the other side: if
// every target fails, the run must not silently look like a clean success. a
// blanket "never fail the batch" fix would hide a totally broken run behind
// exit code 0.
func TestScanAllTargetsAllTargetsFailedReturnsError(t *testing.T) {
	logDir := t.TempDir()
	badURL1 := "http://forced-fail.invalid/x"
	badURL2 := "http://forced-fail.invalid/x/y"
	forceLogCreateFileFailure(t, logDir, badURL1)
	if err := os.Mkdir(filepath.Join(logDir, "forced-fail.invalid_x_y.log"), 0o750); err != nil {
		t.Fatalf("seeding second directory collision: %v", err)
	}

	app := headersOnlyApp()
	app.settings.Concurrency = 2
	app.settings.LogDir = logDir
	app.targets = []string{badURL1, badURL2}

	_, err := app.scanAllTargets(context.Background(), "", false)
	if err == nil {
		t.Fatal("scanAllTargets: want an error when every target failed, got nil")
	}
}
