// Package placetest builds real path fixtures for the rows of the shared
// path table, conformance/paths/cases.json, below a folder the caller
// passes (normally t.TempDir()). Its own tests run with TEMP and TMP on the
// 8.3 alias of a long, spaced folder (hosted parity).
package placetest

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// Case is one row of conformance/paths/cases.json.
type Case struct {
	ID              string          `json:"id"`
	Case            string          `json:"case"`
	Platform        string          `json:"platform"`
	Requires        string          `json:"requires"`
	CallerNamespace string          `json:"caller_namespace"`
	Setup           string          `json:"setup"`
	A               string          `json:"a"`
	B               string          `json:"b"`
	Op              string          `json:"op"`
	Current         string          `json:"current"`
	Want            string          `json:"want"`
	Refusal         string          `json:"refusal"`
	Cites           string          `json:"cites"`
	Skip            string          `json:"skip"`
	Basis           string          `json:"basis"`
	Python          json.RawMessage `json:"python"`
	External        *External       `json:"external"`
}

// External names a test in another module that a row runs under the 8.3 TEMP.
type External struct {
	Dir string `json:"dir"`
	Pkg string `json:"pkg"`
	Run string `json:"run"`
}

// Table is the parsed fixture table.
type Table struct {
	Rows []Case `json:"rows"`
}

// ForThisPlatform reports whether the row applies to the running platform.
func (c Case) ForThisPlatform() bool {
	return c.Platform == "any" || c.Platform == runtime.GOOS
}

// ErrNoTable reports that cases.json is not above the working folder, as in a
// published copy of the module.
var ErrNoTable = errors.New("placetest: conformance/paths/cases.json not found above the working folder")

// Load reads cases.json from the nearest folder above the working folder that
// holds conformance/paths/cases.json.
func Load() (Table, string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return Table{}, "", err
	}
	for {
		name := filepath.Join(dir, "conformance", "paths", "cases.json")
		if data, err := os.ReadFile(name); err == nil {
			var t Table
			if err := json.Unmarshal(data, &t); err != nil {
				return Table{}, name, err
			}
			return t, name, nil
		}
		up := filepath.Dir(dir)
		if up == dir {
			return Table{}, "", ErrNoTable
		}
		dir = up
	}
}

// TestNetHost is the share host every share fixture names: 192.0.2.1 in
// TEST-NET-1 (RFC 5737), reserved for documentation and answered by no
// machine. A share fixture proves its refusal comes before any open; the
// address keeps a refusal that came too late off every real host.
const TestNetHost = "192.0.2.1"

// LongName is the long, spaced folder name every fixture root uses, so a
// volume with 8.3 generation gives it a short alias.
const LongName = "OA Placetest Long Named Folder"

// Root makes a fresh long, spaced folder below parent.
func Root(parent string) (string, error) {
	return os.MkdirTemp(parent, LongName+" ")
}
