//go:build windows && !oa_source_probe

package identity

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

func TestSourceProcessObservationAbsentFromNormalBuild(t *testing.T) {
	ctx := build.Default
	ctx.BuildTags = nil
	pkg, err := ctx.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range pkg.GoFiles {
		if name == "source_observation_windows.go" {
			t.Fatal("source diagnostic compiled into normal Identity")
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Clean(name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			if f, ok := decl.(*ast.FuncDecl); ok && f.Name.Name == "OpenSourceProcessObservation" {
				t.Fatal("source entry in ordinary API", name)
			}
			if g, ok := decl.(*ast.GenDecl); ok {
				for _, spec := range g.Specs {
					if typ, ok := spec.(*ast.TypeSpec); ok && typ.Name.Name == "SourceProcessObservation" {
						t.Fatal("source observation type in ordinary API", name)
					}
				}
			}
		}
	}
}
