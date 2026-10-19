package identity

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/openabstractions/abstraction-identity/fileid"
	"github.com/openabstractions/abstraction-identity/placetest"
)

// TestFileIDScenarios is a driver for the fileid layer (conformance
// DRIVER.md "fileid"): it applies each testdata/scenarios/fileid-*.txt file
// in a fresh workdir, writes the transcript, and judges every "# expect"
// line against it token by token, "..." last allowing more.
func TestFileIDScenarios(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "scenarios", "fileid-*.txt"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fileid scenarios: %v", err)
	}
	cited := map[string]bool{}
	for _, file := range files {
		file := file
		t.Run(filepath.Base(file), func(t *testing.T) {
			src, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var steps, expects []string
			for _, line := range strings.Split(string(src), "\n") {
				line = strings.TrimRight(line, "\r")
				if strings.HasPrefix(line, "# expect ") {
					expects = append(expects, line)
					if _, _, tags, err := parseExpect(line); err == nil {
						for _, tag := range tags {
							cited[tag] = true
						}
					}
					continue
				}
				if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
					continue
				}
				steps = append(steps, line)
			}
			d := newFileIDDriver(t)
			// Relative Self paths start on the scenario's local volume. The
			// source checkout can be a refused mounted volume under WSL.
			t.Chdir(d.dir)
			for _, s := range steps {
				if strings.HasPrefix(s, "keep ") && d.volatile != "" {
					t.Skip("keep needs a workdir whose file IDs survive a reboot (DRIVER.md): " + d.volatile)
				}
			}
			var answers []string
			for _, line := range steps {
				a := d.apply(line)
				answers = append(answers, a)
				t.Logf("%02d %s -> %s", len(answers), line, a)
			}
			for _, e := range expects {
				n, want, tags, err := parseExpect(e)
				if err != nil {
					t.Errorf("%s: %v", e, err)
					continue
				}
				if n < 1 || n > len(answers) {
					t.Errorf("%s: no step %d", e, n)
					continue
				}
				if !expectHolds(want, answers[n-1]) {
					t.Errorf("step %d: %q, want %q %v", n, answers[n-1], want, tags)
				}
			}
			if d.remote != 0 {
				t.Errorf("%d opens reached at or below a share link", d.remote)
			}
		})
	}
	contract, err := os.ReadFile("CONTRACT.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range regexp.MustCompile(`\*\*\[(ID-F[0-9]+)\]`).FindAllStringSubmatch(string(contract), -1) {
		if !cited["["+id[1]+"]"] {
			t.Errorf("rule %s has no fileid scenario", id[1])
		}
	}
	for tag := range cited {
		if !strings.Contains(string(contract), "**"+tag) {
			t.Errorf("scenario tag %s names no rule in CONTRACT.md", tag)
		}
	}
}

var expectLine = regexp.MustCompile(`^# expect ([0-9]+): (.*?)((?: \[[A-Z]+-[A-Z][0-9]+\])*)$`)

func parseExpect(line string) (int, string, []string, error) {
	m := expectLine.FindStringSubmatch(line)
	if m == nil {
		return 0, "", nil, errors.New("not an expectation")
	}
	n, _ := strconv.Atoi(m[1])
	return n, m[2], strings.Fields(m[3]), nil
}

// expectHolds judges an answer by DRIVER.md's rule: every token of want, in
// order; without a trailing "..." the answer has no other token.
func expectHolds(want, answer string) bool {
	w, a := strings.Fields(want), strings.Fields(answer)
	more := len(w) > 0 && w[len(w)-1] == "..."
	if more {
		w = w[:len(w)-1]
	}
	if !more {
		return strings.Join(w, " ") == strings.Join(a, " ")
	}
	i := 0
	for _, tok := range a {
		if i < len(w) && tok == w[i] {
			i++
		}
	}
	return i == len(w) && len(a) > 0 && len(w) > 0 && a[0] == w[0]
}

// fileIDDriver applies fileid scenario lines. An open strictly below a share
// link, or at or below a share link's target, is stopped before it reaches
// the system and counted for "remotes"; the link itself may be opened, since
// the walk reads it without following it.
type fileIDDriver struct {
	t        *testing.T
	dir      string
	volatile string // why no workdir with persistent file IDs was found
	links    []string
	shares   []string
	kept     map[string]fileid.StoredFileID
	opens    int
	remote   int
}

func newFileIDDriver(t *testing.T) *fileIDDriver {
	dir, volatile := persistentDir(t)
	d := &fileIDDriver{t: t, dir: dir, volatile: volatile, kept: map[string]fileid.StoredFileID{}}
	stop, ok := ObserveOpens(func(path string) {
		d.opens++
		remote := strings.HasPrefix(path, `\\`)
		for _, s := range d.links {
			remote = remote || strings.HasPrefix(path, s+string(filepath.Separator))
		}
		for _, s := range d.shares {
			remote = remote || path == s || strings.HasPrefix(path, s+string(filepath.Separator))
		}
		if remote {
			d.remote++
			panic(errStoppedOpen)
		}
	})
	if !ok {
		t.Fatal("another open observer is set")
	}
	t.Cleanup(stop)
	return d
}

var errStoppedOpen = errors.New("an open below a share link was stopped")

// persistentDir returns a new folder, removed when the test ends, on a file
// system whose file IDs survive a reboot (fileid.Persistent), as DRIVER.md
// asks of the workdir: the test's temporary folder, else one in the working
// folder, the module's checkout. /tmp is tmpfs on Fedora, Arch, Debian 13
// and WSL, whose keys are volatile; the home folder is a stand-in below it
// in tests (personfolders). When none is persistent it returns the
// temporary folder and why.
func persistentDir(t *testing.T) (string, string) {
	t.Helper()
	tmp := t.TempDir()
	candidates := []func() (string, error){
		func() (string, error) { return tmp, nil },
		func() (string, error) { return os.MkdirTemp(".", ".fileid-workdir-") },
	}
	var why []string
	for i, mk := range candidates {
		dir, err := mk()
		if err != nil {
			why = append(why, err.Error())
			continue
		}
		if i > 0 {
			t.Cleanup(func() { os.RemoveAll(dir) })
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			why = append(why, err.Error())
			continue
		}
		id, err := fileid.Resolve(context.Background(), fileid.Self, abs, fileid.Options{})
		if err == nil && id.Durability() == fileid.Persistent {
			return abs, ""
		}
		why = append(why, fmt.Sprintf("%s: %v %v", abs, id.Durability(), err))
	}
	return tmp, strings.Join(why, "; ")
}

func (d *fileIDDriver) path(name string) string {
	return filepath.Join(d.dir, filepath.FromSlash(name))
}

func (d *fileIDDriver) apply(line string) (answer string) {
	defer func() {
		if r := recover(); r != nil {
			if r != errStoppedOpen {
				panic(r)
			}
			answer = "refused stopped-open"
		}
	}()
	f := strings.Fields(line)
	op, args := f[0], f[1:]
	opts := map[string]string{}
	var pos []string
	for _, a := range args {
		if k, v, ok := strings.Cut(a, "="); ok {
			opts[k] = v
		} else {
			pos = append(pos, a)
		}
	}
	need := func(n int) bool { return len(pos) == n }
	ctx := context.Background()
	switch op {
	case "file":
		if !need(1) {
			return "invalid"
		}
		p := d.path(pos[0])
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return "invalid"
		}
		return okOr(os.WriteFile(p, []byte(pos[0]), 0o644))
	case "folder":
		if !need(1) {
			return "invalid"
		}
		return okOr(os.MkdirAll(d.path(pos[0]), 0o755))
	case "link":
		if !need(2) {
			return "invalid"
		}
		return okOr(folderLinkForScenario(d.path(pos[0]), d.path(pos[1])))
	case "sharelink":
		if !need(1) {
			return "invalid"
		}
		link := d.path(pos[0])
		if runtime.GOOS == "windows" {
			if err := placetest.ShareJunction(link); err != nil {
				return "invalid"
			}
			d.t.Cleanup(func() { os.Remove(link) })
			d.links = append(d.links, link)
			return "ok"
		}
		target := link + ".share"
		if err := os.Mkdir(target, 0o755); err != nil {
			return "invalid"
		}
		d.t.Cleanup(markNetworkVolume(target))
		d.links, d.shares = append(d.links, link), append(d.shares, target)
		return okOr(os.Symlink(target, link))
	case "hardlink":
		if !need(2) {
			return "invalid"
		}
		p := d.path(pos[0])
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return "invalid"
		}
		return okOr(os.Link(d.path(pos[1]), p))
	case "replace":
		if !need(1) {
			return "invalid"
		}
		p := d.path(pos[0])
		if err := os.WriteFile(p+".new", []byte("next"), 0o644); err != nil {
			return "invalid"
		}
		return okOr(os.Rename(p+".new", p))
	case "remove":
		if !need(1) {
			return "invalid"
		}
		return okOr(os.Remove(d.path(pos[0])))
	case "resolve":
		if !need(1) {
			return "invalid"
		}
		peer, ok := d.peer(opts["peer"])
		if !ok {
			return "invalid"
		}
		o := fileid.Options{}
		if opts["links"] == "refuse" {
			o.Links = fileid.RefuseLinks
		}
		p := d.path(pos[0])
		if opts["relative"] == "yes" {
			// The same file spelled relative to this process's working folder.
			wd, err := os.Getwd()
			if err != nil {
				return "invalid"
			}
			if p, err = filepath.Rel(wd, p); err != nil {
				return "invalid"
			}
		}
		id, err := fileid.Resolve(ctx, peer, p, o)
		return describeFileID(id, err)
	case "relate":
		if !need(2) {
			return "invalid"
		}
		a, err := fileid.Open(ctx, fileid.Self, d.path(pos[0]), fileid.Options{})
		if err != nil {
			return refusal(err)
		}
		defer a.Close()
		b, err := fileid.Open(ctx, fileid.Self, d.path(pos[1]), fileid.Options{})
		if err != nil {
			return refusal(err)
		}
		defer b.Close()
		r, err := a.Relate(b)
		if err != nil {
			return refusal(err)
		}
		if r.MultiName {
			return "ok " + r.Kind.String() + " multi"
		}
		return "ok " + r.Kind.String()
	case "beneath":
		if !need(2) {
			return "invalid"
		}
		h, err := fileid.Open(ctx, fileid.Self, d.path(pos[0]), fileid.Options{})
		if err != nil {
			return refusal(err)
		}
		defer h.Close()
		in, err := h.Beneath(filepath.FromSlash(pos[1]), fileid.Options{})
		if err != nil {
			return refusal(err)
		}
		defer in.Close()
		return describeFileID(in.FileID(), nil)
	case "create":
		if !need(2) {
			return "invalid"
		}
		h, err := fileid.Open(ctx, fileid.Self, d.path(pos[0]), fileid.Options{})
		if err != nil {
			return refusal(err)
		}
		defer h.Close()
		c, err := fileid.CreateExclusive(h, pos[1])
		if err != nil {
			return refusal(err)
		}
		c.Close()
		return "ok"
	case "safename":
		if !need(1) {
			return "invalid"
		}
		if err := fileid.SafeName(pos[0]); err != nil {
			return refusal(err)
		}
		return "ok"
	case "leaf", "pending":
		if !need(2) {
			return "invalid"
		}
		var keys [2]string
		for i, p := range pos {
			var err error
			if op == "leaf" {
				var l fileid.Leaf
				l, err = fileid.ResolveLeaf(ctx, fileid.Self, d.path(p))
				keys[i] = l.Key()
			} else {
				var pn fileid.PendingName
				pn, err = fileid.Pending(ctx, fileid.Self, d.path(p))
				keys[i] = pn.Key()
			}
			if err != nil {
				return refusal(err)
			}
		}
		if keys[0] == keys[1] {
			return "ok same"
		}
		return "ok different"
	case "keep":
		if !need(2) {
			return "invalid"
		}
		id, err := fileid.Resolve(ctx, fileid.Self, d.path(pos[1]), fileid.Options{})
		if err != nil {
			return refusal(err)
		}
		s, err := id.Stored()
		if err != nil {
			return refusal(err)
		}
		d.kept[pos[0]] = s
		return "ok"
	case "revalidate":
		s, ok := d.kept[strings.Join(pos, "")]
		if !need(1) || !ok {
			return "invalid"
		}
		_, state, err := fileid.Revalidate(ctx, s)
		if err != nil {
			return refusal(err)
		}
		return "ok " + state.String()
	case "samefile":
		if !need(2) {
			return "invalid"
		}
		same, err := SameFile(d.path(pos[0]), d.path(pos[1]))
		if err != nil {
			return refusal(err)
		}
		if same {
			return "ok same"
		}
		return "ok different"
	case "within":
		if !need(2) {
			return "invalid"
		}
		in, err := Within(d.path(pos[0]), d.path(pos[1]))
		if err != nil {
			return refusal(err)
		}
		if in {
			return "ok within"
		}
		return "ok outside"
	case "opens":
		n := d.opens
		d.opens = 0
		return fmt.Sprintf("ok %d", n)
	case "remotes":
		return fmt.Sprintf("ok %d", d.remote)
	}
	return "unknown-op"
}

// peer builds the caller a resolve names: this process, or a synthetic peer
// of one kind.
func (d *fileIDDriver) peer(kind string) (fileid.Peer, bool) {
	switch kind {
	case "", "self":
		return fileid.Self, true
	case "none":
		return (*Peer)(nil), true
	}
	p := sameAccountPeer(d.t)
	switch kind {
	case "same-account":
	case "other-account":
		u, _ := p.User.Get()
		u.SID, u.UID = "S-1-5-21-1-2-3-1001", u.UID+1
		p.User = attr("user", u, ProofKernel, "")
	case "other-platform":
		p.Platform = "plan9"
	case "remote":
		p.Transport = "tls"
	default:
		return nil, false
	}
	return p, true
}

func describeFileID(id fileid.FileID, err error) string {
	if err != nil {
		return refusal(err)
	}
	if id.IsDir() {
		return "ok kind=folder"
	}
	return fmt.Sprintf("ok kind=file links=%d", id.Links())
}

func refusal(err error) string {
	switch {
	case errors.Is(err, fileid.ErrOtherView):
		return "refused other-view"
	case errors.Is(err, ErrNotLocalPath):
		return "refused not-local"
	case errors.Is(err, fileid.ErrLink):
		return "refused link"
	case errors.Is(err, fileid.ErrUnsafeName):
		return "refused unsafe"
	case errors.Is(err, fileid.ErrVolatile):
		return "refused volatile"
	case errors.Is(err, fs.ErrExist):
		return "refused exists"
	case errors.Is(err, fs.ErrNotExist):
		return "missing"
	}
	return "error " + strings.ReplaceAll(err.Error(), " ", "_")
}

func okOr(err error) string {
	if err != nil {
		return "invalid"
	}
	return "ok"
}
