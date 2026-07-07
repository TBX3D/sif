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

package modules

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeResponse builds a minimal *http.Response for matcher/extractor tests.
// it carries no real socket (Body is http.NoBody), so there is nothing to
// close; bodyclose is excluded for test files in .golangci.yml. header drives
// the header/all parts without a live server; matchers read the body string
// argument, not resp.Body.
func fakeResponse(t *testing.T, status int, header http.Header) *http.Response {
	t.Helper()
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: header, Body: http.NoBody}
}

func TestCheckMatcherStatus(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   []int
		expect bool
	}{
		{name: "single match", status: 200, want: []int{200}, expect: true},
		{name: "one of many", status: 404, want: []int{200, 301, 404}, expect: true},
		{name: "no match", status: 500, want: []int{200, 404}, expect: false},
		{name: "empty status list", status: 200, want: nil, expect: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Matcher{Type: "status", Status: tt.want}
			resp := fakeResponse(t, tt.status, nil)
			if got := checkMatcher(m, resp, ""); got != tt.expect {
				t.Errorf("checkMatcher status = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestCheckMatcherWord(t *testing.T) {
	const body = "welcome admin dashboard"

	tests := []struct {
		name      string
		words     []string
		condition string
		expect    bool
	}{
		{name: "and all present", words: []string{"admin", "dashboard"}, condition: "and", expect: true},
		{name: "and one missing", words: []string{"admin", "missing"}, condition: "and", expect: false},
		{name: "default is and", words: []string{"admin", "missing"}, condition: "", expect: false},
		{name: "or one present", words: []string{"missing", "admin"}, condition: "or", expect: true},
		{name: "or none present", words: []string{"missing", "absent"}, condition: "or", expect: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Matcher{Type: "word", Part: "body", Words: tt.words, Condition: tt.condition}
			resp := fakeResponse(t, 200, nil)
			if got := checkMatcher(m, resp, body); got != tt.expect {
				t.Errorf("checkMatcher word = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestCheckMatcherRegex(t *testing.T) {
	const body = "version 1.2.3 build 99"

	tests := []struct {
		name      string
		patterns  []string
		condition string
		expect    bool
	}{
		{name: "and all match", patterns: []string{`version \d`, `build \d+`}, condition: "and", expect: true},
		{name: "and one fails", patterns: []string{`version \d`, `nope\d`}, condition: "and", expect: false},
		{name: "or one matches", patterns: []string{`nope`, `build \d+`}, condition: "or", expect: true},
		{name: "or none match", patterns: []string{`nope`, `zilch`}, condition: "or", expect: false},
		// an invalid pattern under AND must fail closed, not panic.
		{name: "and invalid pattern fails closed", patterns: []string{`version \d`, `(`}, condition: "and", expect: false},
		// under OR an invalid pattern is skipped, a later valid one can still hit.
		{name: "or invalid pattern skipped", patterns: []string{`(`, `build \d+`}, condition: "or", expect: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Matcher{Type: "regex", Part: "body", Regex: tt.patterns, Condition: tt.condition}
			resp := fakeResponse(t, 200, nil)
			if got := checkMatcher(m, resp, body); got != tt.expect {
				t.Errorf("checkMatcher regex = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestCheckMatcherHeaderPart(t *testing.T) {
	header := http.Header{"X-Powered-By": []string{"PHP/8.1"}}
	resp := fakeResponse(t, 200, header)

	m := &Matcher{Type: "word", Part: "header", Words: []string{"PHP/8.1"}}
	if !checkMatcher(m, resp, "body-content") {
		t.Error("expected header-part word matcher to hit on header value")
	}

	// the same word lives only in the header, so a body-part matcher must miss.
	mBody := &Matcher{Type: "word", Part: "body", Words: []string{"PHP/8.1"}}
	if checkMatcher(mBody, resp, "body-content") {
		t.Error("body-part matcher should not see header-only value")
	}
}

func TestCheckMatcherUnknownType(t *testing.T) {
	m := &Matcher{Type: "size", Part: "body"}
	resp := fakeResponse(t, 200, nil)
	if checkMatcher(m, resp, "anything") {
		t.Error("unknown matcher type should not match")
	}
}

func TestCheckMatchers(t *testing.T) {
	resp := fakeResponse(t, 200, http.Header{"Server": []string{"nginx"}})
	const body = "secret token here"

	tests := []struct {
		name     string
		matchers []Matcher
		expect   bool
	}{
		{
			name:     "empty matchers never match",
			matchers: nil,
			expect:   false,
		},
		{
			name: "all matchers pass (AND across matchers)",
			matchers: []Matcher{
				{Type: "status", Status: []int{200}},
				{Type: "word", Part: "body", Words: []string{"secret"}},
			},
			expect: true,
		},
		{
			name: "one matcher fails breaks AND",
			matchers: []Matcher{
				{Type: "status", Status: []int{200}},
				{Type: "word", Part: "body", Words: []string{"absent"}},
			},
			expect: false,
		},
		{
			name: "negative inverts a non-match into a pass",
			matchers: []Matcher{
				{Type: "word", Part: "body", Words: []string{"absent"}, Negative: true},
			},
			expect: true,
		},
		{
			name: "negative inverts a match into a fail",
			matchers: []Matcher{
				{Type: "word", Part: "body", Words: []string{"secret"}, Negative: true},
			},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkMatchers(tt.matchers, "", resp, body); got != tt.expect {
				t.Errorf("checkMatchers = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestCheckWords(t *testing.T) {
	const content = "alpha Beta gamma"

	tests := []struct {
		name       string
		words      []string
		condition  string
		caseInsens bool
		expect     bool
	}{
		{name: "and all present", words: []string{"alpha", "gamma"}, condition: "and", expect: true},
		{name: "and missing", words: []string{"alpha", "delta"}, condition: "and", expect: false},
		{name: "or absent case-sensitive", words: []string{"delta", "beta"}, condition: "or", expect: false},
		{name: "or absent", words: []string{"delta", "epsilon"}, condition: "or", expect: false},
		{name: "empty under and matches vacuously", words: nil, condition: "and", expect: true},
		{name: "empty under or matches nothing", words: nil, condition: "or", expect: false},
		{name: "case mismatch fails by default", words: []string{"beta"}, condition: "or", caseInsens: false, expect: false},
		{name: "case-insensitive folds both sides", words: []string{"beta"}, condition: "or", caseInsens: true, expect: true},
		{name: "case-insensitive folds mixed-case needle", words: []string{"BETA"}, condition: "and", caseInsens: true, expect: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkWords(content, tt.words, tt.condition, tt.caseInsens); got != tt.expect {
				t.Errorf("checkWords = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestCheckRegex(t *testing.T) {
	const content = "id=42 name=root"

	tests := []struct {
		name      string
		patterns  []string
		condition string
		expect    bool
	}{
		{name: "and all match", patterns: []string{`id=\d+`, `name=\w+`}, condition: "and", expect: true},
		{name: "and one fails", patterns: []string{`id=\d+`, `zzz`}, condition: "and", expect: false},
		{name: "or first matches", patterns: []string{`id=\d+`, `zzz`}, condition: "or", expect: true},
		{name: "or none match", patterns: []string{`xxx`, `zzz`}, condition: "or", expect: false},
		{name: "and bad regex fails closed", patterns: []string{`(`}, condition: "and", expect: false},
		{name: "or bad regex skipped then match", patterns: []string{`(`, `name=\w+`}, condition: "or", expect: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkRegex(content, tt.patterns, tt.condition, false); got != tt.expect {
				t.Errorf("checkRegex = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestCheckRegexCaseInsensitive(t *testing.T) {
	const content = "role=AdMiN"

	tests := []struct {
		name       string
		patterns   []string
		condition  string
		caseInsens bool
		expect     bool
	}{
		{name: "case-sensitive misses", patterns: []string{`admin`}, condition: "and", caseInsens: false, expect: false},
		{name: "case-insensitive hits", patterns: []string{`admin`}, condition: "and", caseInsens: true, expect: true},
		{name: "case-insensitive anchored", patterns: []string{`^role=admin$`}, condition: "and", caseInsens: true, expect: true},
		{name: "case-insensitive or", patterns: []string{`zzz`, `admin`}, condition: "or", caseInsens: true, expect: true},
		{name: "case-insensitive and both", patterns: []string{`role`, `admin`}, condition: "and", caseInsens: true, expect: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkRegex(content, tt.patterns, tt.condition, tt.caseInsens); got != tt.expect {
				t.Errorf("checkRegex = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestDecodePart(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		encoding string
		want     string
		wantOK   bool
	}{
		{name: "empty encoding passes through", s: "plain text", encoding: "", want: "plain text", wantOK: true},
		{name: "valid base64", s: "c2VjcmV0", encoding: "base64", want: "secret", wantOK: true},
		{name: "valid hex", s: "736563726574", encoding: "hex", want: "secret", wantOK: true},
		{name: "invalid base64", s: "not-valid-base64!!", encoding: "base64", want: "", wantOK: false},
		{name: "invalid hex", s: "zz", encoding: "hex", want: "", wantOK: false},
		{name: "unknown encoding", s: "anything", encoding: "base32", want: "", wantOK: false},
		{name: "whitespace trimmed base64", s: "  c2VjcmV0  \n", encoding: "base64", want: "secret", wantOK: true},
		{name: "encoding is case-insensitive", s: "c2VjcmV0", encoding: "BASE64", want: "secret", wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := decodePart(tt.s, tt.encoding)
			if ok != tt.wantOK {
				t.Fatalf("decodePart ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Errorf("decodePart = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInRange(t *testing.T) {
	intp := func(n int) *int { return &n }

	tests := []struct {
		name string
		v    int
		min  *int
		max  *int
		want bool
	}{
		{name: "within both bounds", v: 50, min: intp(10), max: intp(100), want: true},
		{name: "below min", v: 5, min: intp(10), max: intp(100), want: false},
		{name: "above max", v: 101, min: intp(10), max: intp(100), want: false},
		{name: "at min inclusive", v: 10, min: intp(10), max: intp(100), want: true},
		{name: "at max inclusive", v: 100, min: intp(10), max: intp(100), want: true},
		{name: "min only, above", v: 1000, min: intp(10), max: nil, want: true},
		{name: "min only, below", v: 5, min: intp(10), max: nil, want: false},
		{name: "max only, below", v: 5, min: nil, max: intp(100), want: true},
		{name: "max only, above", v: 1000, min: nil, max: intp(100), want: false},
		{name: "both nil is vacuously true", v: 12345, min: nil, max: nil, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inRange(tt.v, tt.min, tt.max); got != tt.want {
				t.Errorf("inRange(%d) = %v, want %v", tt.v, got, tt.want)
			}
		})
	}
}

func TestCheckMatcherWordEncoding(t *testing.T) {
	// base64 of "secret-admin"
	const encodedBody = "c2VjcmV0LWFkbWlu"
	resp := fakeResponse(t, 200, nil)

	m := &Matcher{Type: "word", Part: "body", Encoding: "base64", Words: []string{"admin"}}
	if !checkMatcher(m, resp, encodedBody) {
		t.Error("expected base64-decoded body to match word admin")
	}

	mWrong := &Matcher{Type: "word", Part: "body", Encoding: "base64", Words: []string{"nope"}}
	if checkMatcher(mWrong, resp, encodedBody) {
		t.Error("expected no match for absent word after decode")
	}

	mBadBody := &Matcher{Type: "word", Part: "body", Encoding: "base64", Words: []string{"admin"}}
	if checkMatcher(mBadBody, resp, "not valid base64 !!") {
		t.Error("expected non-base64 body to miss rather than match")
	}
}

func TestCheckMatcherWordCaseInsensitive(t *testing.T) {
	const body = "Welcome ADMIN Dashboard"
	resp := fakeResponse(t, 200, nil)

	m := &Matcher{Type: "word", Part: "body", Words: []string{"admin"}}
	if checkMatcher(m, resp, body) {
		t.Error("expected case-sensitive matcher to miss mixed-case word")
	}

	mCI := &Matcher{Type: "word", Part: "body", Words: []string{"admin"}, CaseInsensitive: true}
	if !checkMatcher(mCI, resp, body) {
		t.Error("expected case-insensitive matcher to hit mixed-case word")
	}
}

func TestCheckMatcherRange(t *testing.T) {
	intp := func(n int) *int { return &n }

	t.Run("status source in range", func(t *testing.T) {
		resp := fakeResponse(t, 503, nil)
		m := &Matcher{Type: "range", Source: "status", Min: intp(500), Max: intp(599)}
		if !checkMatcher(m, resp, "") {
			t.Error("expected 503 to be within 500-599")
		}
	})

	t.Run("status source out of range", func(t *testing.T) {
		resp := fakeResponse(t, 200, nil)
		m := &Matcher{Type: "range", Source: "status", Min: intp(500), Max: intp(599)}
		if checkMatcher(m, resp, "") {
			t.Error("expected 200 to be outside 500-599")
		}
	})

	t.Run("size source default", func(t *testing.T) {
		resp := fakeResponse(t, 200, nil)
		m := &Matcher{Type: "range", Min: intp(5), Max: intp(20)}
		if !checkMatcher(m, resp, "twelve chars") {
			t.Error("expected body length within bounds to match")
		}
	})

	t.Run("size source explicit", func(t *testing.T) {
		resp := fakeResponse(t, 200, nil)
		m := &Matcher{Type: "range", Source: "size", Min: intp(1000)}
		if checkMatcher(m, resp, "short") {
			t.Error("expected short body to miss a high min bound")
		}
	})
}

// TestParseYAMLModuleMatcherBackCompat confirms an existing-style matcher (none
// of the new fields set) round-trips with the new fields left at their zero
// values, so a shipped module's parsed struct is unaffected by the schema
// addition.
func TestParseYAMLModuleMatcherBackCompat(t *testing.T) {
	const doc = `id: back-compat
type: http
info:
  severity: info
http:
  method: GET
  paths: ["{{BaseURL}}/"]
  matchers:
    - type: word
      part: body
      words: ["admin"]
      condition: and
`
	dir := t.TempDir()
	path := writeModule(t, dir, "back-compat.yaml", doc)
	def, err := ParseYAMLModule(path)
	if err != nil {
		t.Fatalf("ParseYAMLModule: %v", err)
	}
	if len(def.HTTP.Matchers) != 1 {
		t.Fatalf("got %d matchers, want 1", len(def.HTTP.Matchers))
	}
	m := def.HTTP.Matchers[0]
	if m.CaseInsensitive {
		t.Error("CaseInsensitive should default to false")
	}
	if m.Encoding != "" {
		t.Errorf("Encoding should default to empty, got %q", m.Encoding)
	}
	if m.Source != "" {
		t.Errorf("Source should default to empty, got %q", m.Source)
	}
	if m.Min != nil {
		t.Errorf("Min should default to nil, got %v", *m.Min)
	}
	if m.Max != nil {
		t.Errorf("Max should default to nil, got %v", *m.Max)
	}
}

// TestParseYAMLModuleMatcherNewFields confirms yaml.v3 unmarshals scalars into
// *int (allocating on presence, nil on absence) and parses the new string/bool
// fields, guarding the spec's flagged assumption about *int matcher bounds.
func TestParseYAMLModuleMatcherNewFields(t *testing.T) {
	const doc = `id: new-fields
type: http
info:
  severity: info
http:
  method: GET
  paths: ["{{BaseURL}}/"]
  matchers:
    - type: word
      words: ["admin"]
      case-insensitive: true
      encoding: base64
    - type: range
      source: status
      min: 200
      max: 299
`
	dir := t.TempDir()
	path := writeModule(t, dir, "new-fields.yaml", doc)
	def, err := ParseYAMLModule(path)
	if err != nil {
		t.Fatalf("ParseYAMLModule: %v", err)
	}
	if len(def.HTTP.Matchers) != 2 {
		t.Fatalf("got %d matchers, want 2", len(def.HTTP.Matchers))
	}

	word := def.HTTP.Matchers[0]
	if !word.CaseInsensitive {
		t.Error("expected case-insensitive: true to parse")
	}
	if word.Encoding != "base64" {
		t.Errorf("Encoding = %q, want base64", word.Encoding)
	}

	rng := def.HTTP.Matchers[1]
	if rng.Source != "status" {
		t.Errorf("Source = %q, want status", rng.Source)
	}
	if rng.Min == nil || *rng.Min != 200 {
		t.Fatalf("Min = %v, want *200", rng.Min)
	}
	if rng.Max == nil || *rng.Max != 299 {
		t.Fatalf("Max = %v, want *299", rng.Max)
	}
}

func TestParseYAMLModuleMatcherValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string { return writeModule(t, dir, name, body) }

	badEncoding := write("bad-encoding.yaml", "id: be\ntype: http\nhttp:\n  paths: [\"/\"]\n  matchers:\n    - type: word\n      words: [x]\n      encoding: base32\n")
	if _, err := ParseYAMLModule(badEncoding); err == nil {
		t.Fatal("unknown encoding accepted")
	}

	rangeNoBounds := write("range-no-bounds.yaml", "id: rnb\ntype: http\nhttp:\n  paths: [\"/\"]\n  matchers:\n    - type: range\n")
	if _, err := ParseYAMLModule(rangeNoBounds); err == nil {
		t.Fatal("range matcher with no bounds accepted")
	}

	rangeMinMax := write("range-min-max.yaml", "id: rmm\ntype: http\nhttp:\n  paths: [\"/\"]\n  matchers:\n    - type: range\n      min: 100\n      max: 1\n")
	if _, err := ParseYAMLModule(rangeMinMax); err == nil {
		t.Fatal("range matcher with min>max accepted")
	}

	rangeBadSource := write("range-bad-source.yaml", "id: rbs\ntype: http\nhttp:\n  paths: [\"/\"]\n  matchers:\n    - type: range\n      source: bogus\n      min: 1\n")
	if _, err := ParseYAMLModule(rangeBadSource); err == nil {
		t.Fatal("range matcher with bad source accepted")
	}

	rangeOK := write("range-ok.yaml", "id: rok\ntype: http\nhttp:\n  paths: [\"/\"]\n  matchers:\n    - type: range\n      source: size\n      min: 0\n      max: 1000\n")
	if _, err := ParseYAMLModule(rangeOK); err != nil {
		t.Fatalf("valid range matcher rejected: %v", err)
	}
}

func TestGetPart(t *testing.T) {
	header := http.Header{"Server": []string{"nginx"}}
	resp := fakeResponse(t, 200, header)
	const body = "page body"

	if got := getPart("body", resp, body); got != body {
		t.Errorf("getPart body = %q, want %q", got, body)
	}

	headerPart := getPart("header", resp, body)
	if !strings.Contains(headerPart, "Server") || !strings.Contains(headerPart, "nginx") {
		t.Errorf("getPart header = %q, want it to include the header", headerPart)
	}
	if strings.Contains(headerPart, body) {
		t.Errorf("getPart header should not include body, got %q", headerPart)
	}

	all := getPart("all", resp, body)
	if !strings.Contains(all, "nginx") || !strings.Contains(all, body) {
		t.Errorf("getPart all = %q, want both header and body", all)
	}

	// an unrecognised part falls back to the body.
	if got := getPart("weird", resp, body); got != body {
		t.Errorf("getPart fallback = %q, want body %q", got, body)
	}

	// empty part behaves like "all".
	if got := getPart("", resp, body); !strings.Contains(got, "nginx") || !strings.Contains(got, body) {
		t.Errorf("getPart empty = %q, want both header and body", got)
	}
}

func TestRunExtractors(t *testing.T) {
	resp := fakeResponse(t, 200, http.Header{"X-Token": []string{"abc123"}})
	const body = `{"session":"sess-7788","role":"admin"}`

	tests := []struct {
		name       string
		extractors []Extractor
		wantKey    string
		wantVal    string
		wantNil    bool
	}{
		{
			name:       "no extractors yields nil",
			extractors: nil,
			wantNil:    true,
		},
		{
			name: "regex capture group on body",
			extractors: []Extractor{
				{Type: "regex", Name: "session", Part: "body", Regex: []string{`"session":"([^"]+)"`}, Group: 1},
			},
			wantKey: "session",
			wantVal: "sess-7788",
		},
		{
			name: "group zero is the whole match",
			extractors: []Extractor{
				{Type: "regex", Name: "role", Part: "body", Regex: []string{`role":"admin`}, Group: 0},
			},
			wantKey: "role",
			wantVal: `role":"admin`,
		},
		{
			name: "extract from header part",
			extractors: []Extractor{
				{Type: "regex", Name: "token", Part: "header", Regex: []string{`X-Token: (\S+)`}, Group: 1},
			},
			wantKey: "token",
			wantVal: "abc123",
		},
		{
			name: "first matching pattern wins",
			extractors: []Extractor{
				{Type: "regex", Name: "session", Part: "body", Regex: []string{`nomatch(\d+)`, `"session":"([^"]+)"`}, Group: 1},
			},
			wantKey: "session",
			wantVal: "sess-7788",
		},
		{
			name: "group index out of range is skipped",
			extractors: []Extractor{
				{Type: "regex", Name: "session", Part: "body", Regex: []string{`"session":"([^"]+)"`}, Group: 5},
			},
			wantNil: true,
		},
		{
			name: "invalid pattern is skipped, no capture",
			extractors: []Extractor{
				{Type: "regex", Name: "session", Part: "body", Regex: []string{`(`}, Group: 1},
			},
			wantNil: true,
		},
		{
			name: "unknown extractor type is ignored",
			extractors: []Extractor{
				{Type: "bogus", Name: "session", Part: "body", Regex: []string{`"session":"([^"]+)"`}, Group: 1},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runExtractors(tt.extractors, resp, body)
			if tt.wantNil {
				if len(got) != 0 {
					t.Errorf("runExtractors = %v, want empty", got)
				}
				return
			}
			if got[tt.wantKey] != tt.wantVal {
				t.Errorf("runExtractors[%q] = %q, want %q", tt.wantKey, got[tt.wantKey], tt.wantVal)
			}
		})
	}
}

func TestSubstituteVariables(t *testing.T) {
	tests := []struct {
		name     string
		template string
		baseURL  string
		payload  string
		want     string
	}{
		{
			name:     "baseurl both cases",
			template: "{{BaseURL}}/x and {{baseurl}}/y",
			baseURL:  "http://h",
			want:     "http://h/x and http://h/y",
		},
		{
			name:     "payload both cases",
			template: "q={{payload}}&r={{Payload}}",
			payload:  "<script>",
			want:     "q=<script>&r=<script>",
		},
		{
			name:     "combined base and payload",
			template: "{{BaseURL}}/search?q={{payload}}",
			baseURL:  "http://h",
			payload:  "x",
			want:     "http://h/search?q=x",
		},
		{
			name:     "no placeholders untouched",
			template: "/static/path",
			baseURL:  "http://h",
			want:     "/static/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := substituteVariables(tt.template, tt.baseURL, tt.payload); got != tt.want {
				t.Errorf("substituteVariables = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerateHTTPRequests(t *testing.T) {
	t.Run("paths without payloads", func(t *testing.T) {
		cfg := &HTTPConfig{
			Paths: []string{"{{BaseURL}}/a", "{{BaseURL}}/b"},
		}
		// trailing slash on the target must be trimmed before substitution.
		got, err := generateHTTPRequests("http://h/", cfg)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d requests, want 2", len(got))
		}
		if got[0].Method != "GET" {
			t.Errorf("default method = %q, want GET", got[0].Method)
		}
		if got[0].URL != "http://h/a" || got[1].URL != "http://h/b" {
			t.Errorf("urls = %q,%q", got[0].URL, got[1].URL)
		}
	})

	t.Run("payload expansion is path x payload", func(t *testing.T) {
		cfg := &HTTPConfig{
			Method:   "POST",
			Paths:    []string{"{{BaseURL}}/q?x={{payload}}"},
			Payloads: []string{"1", "2", "3"},
			Body:     "data={{payload}}",
		}
		got, err := generateHTTPRequests("http://h", cfg)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("got %d requests, want 3", len(got))
		}
		for i, want := range []string{"1", "2", "3"} {
			if got[i].Payload != want {
				t.Errorf("req %d payload = %q, want %q", i, got[i].Payload, want)
			}
			if got[i].URL != "http://h/q?x="+want {
				t.Errorf("req %d url = %q", i, got[i].URL)
			}
			if got[i].Body != "data="+want {
				t.Errorf("req %d body = %q", i, got[i].Body)
			}
			if got[i].Method != "POST" {
				t.Errorf("req %d method = %q, want POST", i, got[i].Method)
			}
		}
	})

	t.Run("multiple paths times multiple payloads", func(t *testing.T) {
		cfg := &HTTPConfig{
			Paths:    []string{"{{BaseURL}}/a", "{{BaseURL}}/b"},
			Payloads: []string{"x", "y"},
		}
		got, err := generateHTTPRequests("http://h", cfg)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if len(got) != 4 {
			t.Fatalf("got %d requests, want 4 (2 paths x 2 payloads)", len(got))
		}
	})

	t.Run("wordlist expands {{word}} paths", func(t *testing.T) {
		list := filepath.Join(t.TempDir(), "words.txt")
		if err := os.WriteFile(list, []byte("admin\n\nconfig\nbackup\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := &HTTPConfig{
			Paths:    []string{"{{BaseURL}}/{{word}}", "{{BaseURL}}/.git/HEAD"},
			Wordlist: list,
		}
		got, err := generateHTTPRequests("http://h", cfg)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		// 3 words (the blank line is skipped) fuzz the templated path, then the
		// literal path passes through untouched.
		want := []string{"http://h/admin", "http://h/config", "http://h/backup", "http://h/.git/HEAD"}
		if len(got) != len(want) {
			t.Fatalf("got %d requests, want %d", len(got), len(want))
		}
		for i, w := range want {
			if got[i].URL != w {
				t.Errorf("req %d url = %q, want %q", i, got[i].URL, w)
			}
		}
	})

	t.Run("wordlist crosses with payloads", func(t *testing.T) {
		list := filepath.Join(t.TempDir(), "words.txt")
		if err := os.WriteFile(list, []byte("a\nb\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := &HTTPConfig{
			Paths:    []string{"{{BaseURL}}/{{word}}?q={{payload}}"},
			Wordlist: list,
			Payloads: []string{"1", "2", "3"},
		}
		got, err := generateHTTPRequests("http://h", cfg)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if len(got) != 6 {
			t.Fatalf("got %d requests, want 6 (2 words x 3 payloads)", len(got))
		}
	})

	t.Run("missing wordlist errors", func(t *testing.T) {
		cfg := &HTTPConfig{
			Paths:    []string{"{{BaseURL}}/{{word}}"},
			Wordlist: filepath.Join(t.TempDir(), "nope.txt"),
		}
		if _, err := generateHTTPRequests("http://h", cfg); err == nil {
			t.Fatal("want error for missing wordlist, got nil")
		}
	})
}
