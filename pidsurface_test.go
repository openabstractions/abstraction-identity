package identity

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// barePidName is a parameter or result name that carries a process id.
var barePidName = regexp.MustCompile(`(?i)^(pid|ppid|processid|parentpid)$`)

// integerTypes are the types a bare pid travels as.
var integerTypes = map[string]bool{"int": true, "int32": true, "int64": true, "uint": true, "uint32": true, "uint64": true, "uintptr": true}

// TestNoExportedFunctionTakesABarePid is ID-B5's source check: no exported
// function or method of identity or fileid, on any platform's build, takes or
// returns a process id as a plain integer. A process leaves identity as a
// Binding, a Shared view or the Peer's Process attribute, whose pid carries
// its proof and creation time. A callback whose own parameter is a pid
// (TreeContains, OwnedByTree's answer) names membership of a tree already
// pinned by creation time, so only a function's direct parameters and
// results are read.
func TestNoExportedFunctionTakesABarePid(t *testing.T) {
	fset := token.NewFileSet()
	var files []string
	for _, dir := range []string{".", "fileid"} {
		matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	read := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		read++
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() || !exportedReceiver(fn) {
				continue
			}
			for _, list := range []*ast.FieldList{fn.Type.Params, fn.Type.Results} {
				if list == nil {
					continue
				}
				for _, field := range list.List {
					typ, ok := field.Type.(*ast.Ident)
					if !ok || !integerTypes[typ.Name] {
						continue
					}
					for _, n := range field.Names {
						if barePidName.MatchString(n.Name) {
							t.Errorf("%s: %s takes or returns %s %s, a bare pid (ID-B5)", fset.Position(n.Pos()), fn.Name.Name, n.Name, typ.Name)
						}
					}
				}
			}
		}
	}
	if read < 50 {
		t.Fatalf("read %d source files; the check is not reading the package", read)
	}
}

// exportedReceiver reports whether fn is a function or a method of an
// exported type.
func exportedReceiver(fn *ast.FuncDecl) bool {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return true
	}
	typ := fn.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if index, ok := typ.(*ast.IndexExpr); ok {
		typ = index.X
	}
	id, ok := typ.(*ast.Ident)
	return ok && id.IsExported()
}
