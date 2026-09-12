package jsonc

import (
	"encoding/json"
	"testing"
)

func TestStripTrailingCommas(t *testing.T) {
	// The shape that makes encoding/json reject a real bun.lock.
	src := []byte(`{
  "workspaces": {
    "": {
      "dependencies": {
        "axios": "^1.6.0",
      },
    },
  },
}`)

	if json.Valid(src) {
		t.Fatal("fixture is already strict JSON; it no longer covers the bun.lock case")
	}

	out := Strip(src)
	if !json.Valid(out) {
		t.Fatalf("Strip did not produce valid JSON: %s", out)
	}

	var doc struct {
		Workspaces map[string]struct {
			Dependencies map[string]string `json:"dependencies"`
		} `json:"workspaces"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := doc.Workspaces[""].Dependencies["axios"]; got != "^1.6.0" {
		t.Fatalf("axios range = %q, want ^1.6.0", got)
	}
}

func TestStripTrailingCommasInArrays(t *testing.T) {
	out := Strip([]byte(`{"a":[1,2,3,],"b":[],}`))
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal %s: %v", out, err)
	}
	if len(doc["a"].([]any)) != 3 {
		t.Fatalf("array length = %d, want 3", len(doc["a"].([]any)))
	}
}

func TestStripComments(t *testing.T) {
	src := []byte(`{
  // a line comment
  "a": 1, /* an inline block */
  "b": "keep // this and /* this */ inside the string"
}`)
	out := Strip(src)

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal %s: %v", out, err)
	}
	want := "keep // this and /* this */ inside the string"
	if doc["b"] != want {
		t.Fatalf("string value = %q, want %q", doc["b"], want)
	}
}

func TestStripLeavesStringsWithEscapesAlone(t *testing.T) {
	src := []byte(`{"a":"quote \" then a brace } and a comma ,","b":1}`)
	out := Strip(src)

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal %s: %v", out, err)
	}
	if doc["a"] != `quote " then a brace } and a comma ,` {
		t.Fatalf("escaped string was altered: %q", doc["a"])
	}
}

func TestStripIsIdempotentOnStrictJSON(t *testing.T) {
	src := []byte(`{"a":[1,2],"b":{"c":"d"}}`)
	if got := string(Strip(src)); got != string(src) {
		t.Fatalf("strict JSON was modified:\n got %s\nwant %s", got, src)
	}
}
