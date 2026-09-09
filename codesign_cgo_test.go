package identity

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// Cross compiling turns cgo off, so every darwin build this gate performs picks
// codesign_nocgo_darwin.go and nothing at all reads codesign_darwin.go - not
// the build, not `go vet -GOOS=darwin`, and not the Mac, which is the owner's
// laptop and not infrastructure. This type-checks the darwin-plus-cgo build of
// the package, with an empty stub standing in for the pseudo-package C.
//
// Its limit, which is the reason the gate still says UNPROVEN for darwin:
// go/types marks every expression whose type comes from C invalid and stops
// there, so what crosses into ai_verify, and the C source itself, are proved by
// a real macOS build and by nothing here.
func TestDarwinCgoBuildTypeChecks(t *testing.T) {
	names := strings.Fields(golist(t, "1", "-f", "{{range .GoFiles}}{{.}} {{end}}{{range .CgoFiles}}{{.}} {{end}}"))
	if !slices.Contains(names, "codesign_darwin.go") {
		t.Fatalf("the darwin cgo build no longer selects codesign_darwin.go, so this test checks nothing; it selects %v", names)
	}

	export := map[string]string{}
	for _, line := range strings.Split(golist(t, "0", "-deps", "-export", "-f", "{{.ImportPath}}\t{{.Export}}"), "\n") {
		if path, file, ok := strings.Cut(strings.TrimSpace(line), "\t"); ok && file != "" {
			export[path] = file
		}
	}

	fset := token.NewFileSet()
	var parsed []*ast.File
	for _, name := range names {
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, file)
	}

	gc := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		file, ok := export[path]
		if !ok {
			return nil, fmt.Errorf("no darwin export data for %s", path)
		}
		return os.Open(file)
	})
	stub := types.NewPackage("C", "C")
	stub.MarkComplete()

	conf := types.Config{
		Sizes: types.SizesFor("gc", "arm64"),
		Error: func(err error) {
			if e, ok := err.(types.Error); ok && strings.HasPrefix(e.Msg, "undefined: C.") {
				return
			}
			t.Error(err)
		},
		Importer: importAs(func(path string) (*types.Package, error) {
			if path == "C" {
				return stub, nil
			}
			return gc.Import(path)
		}),
	}
	conf.Check("identity", fset, parsed, nil)
}

func golist(t *testing.T, cgo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list"}, append(args, ".")...)...)
	cmd.Env = append(os.Environ(), "GOOS=darwin", "GOARCH=arm64", "CGO_ENABLED="+cgo)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %v: %v\n%s", args, err, stderr.String())
	}
	return string(out)
}

type importAs func(string) (*types.Package, error)

func (f importAs) Import(path string) (*types.Package, error) { return f(path) }
