package identity

// The services that named their caller before SubjectOf, transcribed from
// origin/next 0e19c52de. Each function below repeats one site's derivation
// of the caller's account and program from a Peer, statement for statement,
// with the site's own proof levels and its own order of refusals; only the
// return shape differs, an answer string a table can compare. They are the
// recorded behaviour SubjectOf replaced (CQ-3(b)), kept so that the replacing
// code is compared against what each service did and not against a summary
// of it. testdata/subject-of/copies.txt holds their answers for the named
// rows; go test -run TestSubjectCopies -update-subject-copies rewrites it.

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var updateSubjectCopies = flag.Bool("update-subject-copies", false, "rewrite testdata/subject-of/copies.txt from the transcribed copies")

// The needs the copies used: listen.Program (listen/listen.go:51, also
// abstraction-resource's Bound, service/host.go:42) and the inference
// gateway's PeerNeed (adapters/go/gateway/window.go:29). The identity
// package cannot import listen, which imports it.
var (
	copyProgramNeed = Need{User: ProofKernel, Process: ProofKernel, Path: ProofBound}
	copyGatewayNeed = Need{User: ProofBound, Process: ProofBound, Path: ProofBound}
)

// A subjectSite is one place a service derived its caller's subject. old is
// the transcription; owner is the account the service runs as, which the
// owner-checking sites compare against.
type subjectSite struct {
	name string
	old  func(p *Peer, owner string) string
}

func subjectOK(kind, account, program string) string {
	return "ok " + kind + ":" + account + " " + program
}

// subjectCopies lists every site in origin/next 0e19c52de that turned a
// Peer's user into an account string, by module and the line of its
// derivation.
var subjectCopies = []subjectSite{
	// The four SubjectFromPeer copies, verbatim apart from their error text
	// and result type.
	{"rights/go/client/authorization.go:30", copyFromPeer(copyProgramNeed)},
	{"credentials/go/service/host.go:155", copyFromPeer(copyProgramNeed)},
	{"inference/go/service/host.go:276", copyFromPeer(copyProgramNeed)},
	{"resource/go/service/leases_host.go:47", copyFromPeer(copyProgramNeed)},
	{"inference/adapters/go/gateway/window.go:494", copyGateway},
	{"asks/go/application/receiver.go:26", copyAsks},
	{"config/go/service/service.go:171", copyConfig},
	{"facade/go-core/resolution/caller.go:21", copyResolution},
	{"facade/go/runtime/jobs.go:99", copyJobsAuthorize},
	{"facade/go/runtime/jobs.go:129", copyJobsBinding},
	{"facade/go/runtime/host.go:815", copyResolverOwner},
	{"logging/go/service/service.go:203", copyLoggingWrite},
	{"logging/go/service/service.go:260", copyLoggingHistory},
	{"logging/go/service/application_history.go:74", copyLoggingApplication},
	{"model/go/service/service.go:173", copyModelAuthorized},
	{"model/go/service/service.go:224", copyModelSubject},
	{"provider-modelbridge/go/service/host.go:162", copyModelbridge},
	{"storage-over-local-stores/go/service/host.go:145", copyLocalStores},
	{"storage/go/service/service.go:343", copyStorageScope},
	{"job/go/acceptanceprovider/link.go:69", copyJobLink},
	// The sites outside openabstractions-flat, named by their repository
	// path: the two conformance hosts run.py builds from the workspace,
	// serve's OpenCode session check, and the two places that name their
	// own account from Self, given here the peer's user as Self's answer.
	{"conformance/clients/router/server.go:72", copyResolverOwner},
	{"conformance/clients/facade/host.go:91", copyFacadeFixtureOwner},
	{"serve/opencode_session_windows.go:278", copyOpenCodeSession},
	{"serve/runtime_logging.go:25", copySelfLogAccount},
	{"examples/rights-playground/main.go:250", copyPlaygroundAccount},
}

// copyFromPeer is rights client.SubjectFromPeer and its three copies.
func copyFromPeer(need Need) func(*Peer, string) string {
	return func(peer *Peer, _ string) string {
		if peer == nil {
			return "refused"
		}
		if e := peer.Check(need); e != nil {
			return "refused"
		}
		u, e := peer.User.AtLeast(need.User)
		if e != nil {
			return "refused"
		}
		account := ""
		if u.Kind == "windows" {
			account = u.SID
		} else if u.Kind == "posix" && u.UID >= 0 {
			account = strconv.Itoa(u.UID)
		}
		program, e := SubjectProgram(peer, need.Path)
		if e != nil || account == "" {
			return "refused"
		}
		return subjectOK(u.Kind, account, program)
	}
}

// copyGateway is gateway.LoopbackSubject.
func copyGateway(peer *Peer, _ string) string {
	if peer == nil {
		return "refused"
	}
	if err := peer.Check(copyGatewayNeed); err != nil {
		return "refused"
	}
	u, _ := peer.User.Get()
	account := ""
	switch {
	case u.Kind == "windows":
		account = u.SID
	case u.Kind == "posix" && u.UID >= 0:
		account = strconv.Itoa(u.UID)
	}
	program, err := SubjectProgram(peer, ProofClaimed)
	if account == "" || err != nil {
		return "refused"
	}
	return subjectOK(u.Kind, account, program)
}

// copyAsks is asks application.callerScope; the answer carries the inputs of
// the scope hash.
func copyAsks(p *Peer, owner string) string {
	if p == nil {
		return "refused:caller_required"
	}
	u, e := p.User.AtLeast(copyProgramNeed.User)
	if e != nil {
		return "refused:proof"
	}
	principal := ""
	if u.Kind == "windows" {
		principal = u.SID
	} else if u.Kind == "posix" && u.UID >= 0 {
		principal = strconv.Itoa(u.UID)
	}
	if principal == "" || principal != owner {
		return "refused:account acct=" + principal
	}
	path, e := p.Path.AtLeast(copyProgramNeed.Path)
	if e != nil || !filepath.IsAbs(path) {
		return "refused:program"
	}
	return subjectOK(u.Kind, principal, filepath.Clean(path))
}

// copyConfig is config service receiver.authorize, after its Peer read.
func copyConfig(p *Peer, owner string) string {
	u, err := p.User.AtLeast(copyProgramNeed.User)
	if err != nil {
		return "refused:identity_required"
	}
	principal := ""
	if u.Kind == "windows" {
		principal = u.SID
	} else if u.Kind == "posix" {
		principal = strconv.Itoa(u.UID)
	}
	if principal == "" || principal != owner {
		return "refused:wrong_user acct=" + principal
	}
	return subjectOK(u.Kind, principal, "")
}

// copyResolution is resolution.ObserveCaller's account and program, the
// echo of abstraction.facade/caller@1.
func copyResolution(peer *Peer, _ string) string {
	if peer == nil {
		return "refused"
	}
	user, err := peer.User.AtLeast(copyProgramNeed.User)
	if err != nil {
		return "refused"
	}
	program, err := peer.Path.AtLeast(copyProgramNeed.Path)
	if err != nil {
		return "refused"
	}
	if _, err := peer.Process.AtLeast(copyProgramNeed.Process); err != nil {
		return "refused"
	}
	account := user.SID
	if user.Kind != "windows" {
		account = strconv.Itoa(user.UID)
	}
	return subjectOK(user.Kind, account, program)
}

// copyJobsAuthorize is the runtime job host's authorize, without its program
// policy, which every row passes.
func copyJobsAuthorize(peer *Peer, owner string) string {
	if peer == nil {
		return "refused:caller_evidence"
	}
	user, err := peer.User.AtLeast(copyProgramNeed.User)
	if err != nil {
		return "refused:proof"
	}
	principal := ""
	switch user.Kind {
	case "windows":
		principal = user.SID
	case "posix":
		if user.UID >= 0 {
			principal = strconv.Itoa(user.UID)
		}
	}
	if principal == "" || principal != owner {
		return "refused:another_owner acct=" + principal
	}
	path, err := peer.Path.AtLeast(copyProgramNeed.Path)
	if err != nil || path == "" || !filepath.IsAbs(path) {
		return "refused:program"
	}
	return subjectOK(user.Kind, principal, path)
}

// copyJobsBinding is authorizeBinding: authorize, then the subject it binds.
func copyJobsBinding(peer *Peer, owner string) string {
	if a := copyJobsAuthorize(peer, owner); strings.HasPrefix(a, "refused") {
		return a
	}
	user, err := peer.User.AtLeast(copyProgramNeed.User)
	if err != nil {
		return "refused:proof"
	}
	account := user.SID
	if user.Kind == "posix" {
		account = strconv.Itoa(user.UID)
	}
	path, err := peer.Path.AtLeast(copyProgramNeed.Path)
	if err != nil {
		return "refused:program"
	}
	program, err := SubjectProgram(peer, copyProgramNeed.Path)
	if err != nil {
		return "refused:program"
	}
	return subjectOK(user.Kind, account, filepath.Clean(path)+" "+program)
}

// copyResolverOwner is the runtime resolver's owner match for every
// capability but jobs.
func copyResolverOwner(peer *Peer, owner string) string {
	observed, err := peer.User.AtLeast(copyProgramNeed.User)
	if err != nil {
		return "refused"
	}
	if observed.Kind == "windows" {
		if observed.SID == owner {
			return subjectOK(observed.Kind, observed.SID, "")
		}
		return "refused acct=" + observed.SID
	}
	if principal := strconv.Itoa(observed.UID); principal == owner {
		return subjectOK(observed.Kind, principal, "")
	} else {
		return "refused acct=" + principal
	}
}

// copyLoggingWrite is the logging receiver's Write, through the emitter it
// writes for an application history provider.
func copyLoggingWrite(observed *Peer, _ string) string {
	if _, err := observed.Path.AtLeast(copyProgramNeed.Path); err != nil {
		return "refused"
	}
	user, err := observed.User.AtLeast(copyProgramNeed.User)
	if err != nil {
		return "refused"
	}
	if _, err := observed.Process.AtLeast(copyProgramNeed.Process); err != nil {
		return "refused"
	}
	program, err := SubjectProgram(observed, copyProgramNeed.Path)
	if err != nil {
		return "refused"
	}
	account := ""
	if user.Kind == "windows" {
		account = user.SID
	} else if user.Kind == "posix" {
		account = strconv.Itoa(user.UID)
	}
	return subjectOK(user.Kind, account, program)
}

// copyLoggingHistory is the logging receiver's authorizeHistory, without its
// policy, which every row passes.
func copyLoggingHistory(peer *Peer, owner string) string {
	who, err := peer.User.AtLeast(copyProgramNeed.User)
	if err != nil {
		return "refused:identity_required"
	}
	principal := ""
	if who.Kind == "windows" {
		principal = who.SID
	} else if who.Kind == "posix" {
		principal = strconv.Itoa(who.UID)
	}
	if principal == "" || principal != owner {
		return "refused:wrong_user acct=" + principal
	}
	return subjectOK(who.Kind, principal, "")
}

// copyLoggingApplication is the logging receiver's applicationPeer.
func copyLoggingApplication(peer *Peer, owner string) string {
	who, err := peer.User.AtLeast(copyProgramNeed.User)
	if err != nil {
		return "refused:native_account"
	}
	account := ""
	if who.Kind == "windows" {
		account = who.SID
	} else if who.Kind == "posix" {
		account = strconv.Itoa(who.UID)
	}
	program, err := SubjectProgram(peer, copyProgramNeed.Path)
	if err != nil {
		return "refused:native_program"
	}
	if account == "" || account != owner {
		return "refused:wrong_user acct=" + account
	}
	return subjectOK(who.Kind, account, program)
}

// copyModelAuthorized is the model receiver's authorized.
func copyModelAuthorized(p *Peer, owner string) string {
	u, e := p.User.AtLeast(copyProgramNeed.User)
	if e != nil {
		return "refused"
	}
	principal := ""
	if u.Kind == "windows" {
		principal = u.SID
	} else if u.Kind == "posix" {
		principal = strconv.Itoa(u.UID)
	}
	if principal != "" && principal == owner {
		return subjectOK(u.Kind, principal, "")
	}
	return "refused acct=" + principal
}

// copyModelSubject is the model receiver's subject, after its recheck.
func copyModelSubject(p *Peer, owner string) string {
	u, e := p.User.AtLeast(copyProgramNeed.User)
	if e != nil {
		return "refused"
	}
	account := ""
	if u.Kind == "windows" {
		account = u.SID
	} else if u.Kind == "posix" && u.UID >= 0 {
		account = strconv.Itoa(u.UID)
	}
	program, e := p.Path.AtLeast(copyProgramNeed.Path)
	if e != nil || account == "" || account != owner || !filepath.IsAbs(program) {
		return "refused"
	}
	return subjectOK(u.Kind, account, filepath.Clean(program))
}

// copyModelbridge is the modelbridge host's admits, before its program list.
func copyModelbridge(peer *Peer, owner string) string {
	u, err := peer.User.AtLeast(copyProgramNeed.User)
	if err != nil {
		return "refused:identity_required"
	}
	principal := ""
	switch u.Kind {
	case "windows":
		principal = u.SID
	case "posix":
		principal = strconv.Itoa(u.UID)
	}
	if principal == "" || principal != owner {
		return "refused:forbidden acct=" + principal
	}
	program, err := SubjectProgram(peer, copyProgramNeed.Path)
	if err != nil {
		return "refused:identity_required"
	}
	return subjectOK(u.Kind, principal, program)
}

// copyLocalStores is the storage-over-local-stores host's admits.
func copyLocalStores(peer *Peer, owner string) string {
	u, err := peer.User.AtLeast(copyProgramNeed.User)
	if err != nil {
		return "refused:identity_required"
	}
	principal := ""
	switch u.Kind {
	case "windows":
		principal = u.SID
	case "posix":
		principal = strconv.Itoa(u.UID)
	}
	if principal == "" || principal != owner {
		return "refused:forbidden acct=" + principal
	}
	return subjectOK(u.Kind, principal, "")
}

// copyStorageScope is the storage service's callerScope; the answer carries
// the inputs of the scope key.
func copyStorageScope(peer *Peer, owner string) string {
	if peer == nil {
		return "refused"
	}
	u, e := peer.User.AtLeast(copyProgramNeed.User)
	if e != nil {
		return "refused"
	}
	principal := ""
	switch u.Kind {
	case "windows":
		principal = u.SID
	case "posix":
		if u.UID >= 0 {
			principal = strconv.Itoa(u.UID)
		}
	}
	if principal == "" || principal != owner {
		return "refused acct=" + principal
	}
	path, e := peer.Path.AtLeast(copyProgramNeed.Path)
	if e != nil || !filepath.IsAbs(path) {
		return "refused"
	}
	return subjectOK(u.Kind, principal, filepath.Clean(path))
}

// copyJobLink is the job acceptance provider's SameAuthority account half:
// the caller's principal (userPrincipal) compared with the provider's own,
// here owner. The Windows integrity and restriction comparison is not part
// of the account and every row passes it.
func copyJobLink(peer *Peer, owner string) string {
	if peer == nil {
		return "refused"
	}
	user, err := peer.User.AtLeast(ProofKernel)
	if err != nil {
		return "refused"
	}
	account := ""
	if user.Kind == "windows" {
		if user.SID == "" {
			return "refused"
		}
		account = user.SID
	} else {
		if user.UID < 0 {
			return "refused"
		}
		account = strconv.Itoa(user.UID)
	}
	if account == "" || account != owner {
		return "refused acct=" + account
	}
	return subjectOK(user.Kind, account, "")
}

// copyFacadeFixtureOwner is the conformance facade host's resolver owner
// match.
func copyFacadeFixtureOwner(peer *Peer, owner string) string {
	observed, err := peer.User.AtLeast(copyProgramNeed.User)
	if err != nil {
		return "refused"
	}
	if observed.Kind == "windows" {
		if observed.SID == owner {
			return subjectOK(observed.Kind, observed.SID, "")
		}
		return "refused acct=" + observed.SID
	}
	if observed.Kind == "posix" {
		if principal := strconv.Itoa(observed.UID); principal == owner {
			return subjectOK(observed.Kind, principal, "")
		} else {
			return "refused acct=" + principal
		}
	}
	return "refused acct="
}

// copyOpenCodeSession is serve's openCodeNativeSession.authorize up to its
// account comparison, with owner as the launch record's account. The process
// instance half of that comparison does not read the account and is left
// out.
func copyOpenCodeSession(peer *Peer, owner string) string {
	user, err := peer.User.AtLeast(ProofKernel)
	if err != nil {
		return "refused"
	}
	if _, err := peer.Process.AtLeast(ProofKernel); err != nil {
		return "refused"
	}
	if _, err := peer.Path.AtLeast(ProofBound); err != nil {
		return "refused"
	}
	if user.Kind != "windows" || user.SID != owner {
		return "refused"
	}
	return subjectOK(user.Kind, user.SID, "")
}

// copySelfLogAccount is serve's runtimeAttributedLogWriter naming its own
// account.
func copySelfLogAccount(peer *Peer, _ string) string {
	principal, err := peer.User.AtLeast(ProofNone)
	if err != nil {
		return "refused"
	}
	account := ""
	if principal.Kind == "windows" {
		account = principal.SID
	} else if principal.Kind == "posix" {
		account = strconv.Itoa(principal.UID)
	}
	if account == "" {
		return "refused"
	}
	return subjectOK(principal.Kind, account, "")
}

// copyPlaygroundAccount is the rights playground's showIdentity.
func copyPlaygroundAccount(peer *Peer, _ string) string {
	who, err := peer.User.AtLeast(ProofNone)
	if err != nil {
		return "refused"
	}
	account := who.SID
	if who.Kind == "posix" {
		account = strconv.Itoa(who.UID)
	}
	return subjectOK(who.Kind, account, "")
}

// Fixture peers. Every attribute's proof is set directly, as no platform
// binding produces most of these combinations; that is the point.

const (
	fixtureSID   = "S-1-5-21-1000-2000-3000-1001"
	fixtureOwner = "1000"
)

// fixtureProgram is an absolute image path on this platform with no
// component shaped like a short name, so CanonicalProgramPath reads nothing.
func fixtureProgram() string {
	if runtime.GOOS == "windows" {
		return `C:\OAFixture\Programs\app.exe`
	}
	return "/oa-fixture/programs/app"
}

// fixtureMessyProgram names fixtureProgram through a dot-dot component.
func fixtureMessyProgram() string {
	if runtime.GOOS == "windows" {
		return `C:\OAFixture\Other\..\Programs\app.exe`
	}
	return "/oa-fixture/other/../programs/app"
}

type subjectFixture struct {
	user                         *User
	userProof, procProof, pathPr Proof
	path                         string
}

func (f subjectFixture) peer() *Peer {
	p := &Peer{Platform: "fixture", Transport: "fixture"}
	if f.user != nil && f.userProof > ProofNone {
		p.User = attr("user", *f.user, f.userProof, "fixture")
	} else {
		p.User = unknown[User]("user", "fixture")
	}
	if f.procProof > ProofNone {
		p.Process = attr("process", Process{PID: 4242}, f.procProof, "fixture")
	} else {
		p.Process = unknown[Process]("process", "fixture")
	}
	if f.pathPr > ProofNone {
		p.Path = attr("path", f.path, f.pathPr, "fixture")
	} else {
		p.Path = unknown[string]("path", "fixture")
	}
	return p
}

func (f subjectFixture) owner() string {
	if f.user != nil && f.user.Kind == "windows" {
		return fixtureSID
	}
	return fixtureOwner
}

var (
	windowsUser      = &User{Kind: "windows", SID: fixtureSID, UID: -1, GID: -1}
	windowsNoSIDUser = &User{Kind: "windows", UID: -1, GID: -1}
	posixUser        = &User{Kind: "posix", UID: 1000, GID: 1000}
	posixRootUser    = &User{Kind: "posix", UID: 0, GID: 0}
	posixNegUser     = &User{Kind: "posix", UID: -1, GID: -1}
	noKindUser       = &User{UID: 1000, GID: 1000}
)

// best is the evidence every service asks for, met.
func best(u *User, path string) subjectFixture {
	return subjectFixture{u, ProofKernel, ProofKernel, ProofBound, path}
}

// namedSubjectRows are the acceptance rows of CQ-3(b): a Windows SID, a
// POSIX uid, a negative uid, a missing program and each proof level of the
// user, the process and the path.
func namedSubjectRows() []struct {
	name string
	f    *subjectFixture
} {
	type row = struct {
		name string
		f    *subjectFixture
	}
	ptr := func(f subjectFixture) *subjectFixture { return &f }
	rows := []row{
		{"nil-peer", nil},
		{"windows-sid", ptr(best(windowsUser, fixtureProgram()))},
		{"windows-no-sid", ptr(best(windowsNoSIDUser, fixtureProgram()))},
		{"posix-uid", ptr(best(posixUser, fixtureProgram()))},
		{"posix-other-uid", ptr(best(posixRootUser, fixtureProgram()))},
		{"posix-negative-uid", ptr(best(posixNegUser, fixtureProgram()))},
		{"no-kind", ptr(best(noKindUser, fixtureProgram()))},
		{"missing-program", ptr(subjectFixture{posixUser, ProofKernel, ProofKernel, ProofNone, ""})},
		{"relative-program", ptr(best(posixUser, "app"))},
		{"messy-program", ptr(best(posixUser, fixtureMessyProgram()))},
		{"windows-missing-program", ptr(subjectFixture{windowsUser, ProofKernel, ProofKernel, ProofNone, ""})},
	}
	for p := ProofNone; p <= ProofSigned; p++ {
		rows = append(rows,
			row{"user-proof-" + p.String(), ptr(subjectFixture{posixUser, p, ProofKernel, ProofBound, fixtureProgram()})},
			row{"process-proof-" + p.String(), ptr(subjectFixture{posixUser, ProofKernel, p, ProofBound, fixtureProgram()})},
			row{"path-proof-" + p.String(), ptr(subjectFixture{posixUser, ProofKernel, ProofKernel, p, fixtureProgram()})})
	}
	return rows
}

// answer runs one site on one row; a panic is an answer too (a site that
// was never handed a nil peer dereferences it).
func answer(site func(*Peer, string) string, f *subjectFixture) (out string) {
	defer func() {
		if recover() != nil {
			out = "panic"
		}
	}()
	if f == nil {
		return site(nil, fixtureOwner)
	}
	return site(f.peer(), f.owner())
}

// portable replaces this platform's fixture paths so the recorded answers
// read the same on every platform.
func portable(s string) string {
	s = strings.ReplaceAll(s, fixtureMessyProgram(), "<messy>")
	return strings.ReplaceAll(s, fixtureProgram(), "<program>")
}

func recordedSubjectAnswers(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			t.Fatalf("malformed recorded answer %q", line)
		}
		out[parts[0]+"\t"+parts[1]] = parts[2]
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

var copiesPath = filepath.Join("testdata", "subject-of", "copies.txt")

// TestSubjectCopiesRecordedAnswers holds each transcribed copy to the answers
// recorded for it, so a later edit to a transcription shows as a changed
// record rather than a silently moved baseline.
func TestSubjectCopiesRecordedAnswers(t *testing.T) {
	var lines []string
	got := map[string]string{}
	for _, row := range namedSubjectRows() {
		for _, site := range subjectCopies {
			a := portable(answer(site.old, row.f))
			got[row.name+"\t"+site.name] = a
			lines = append(lines, row.name+"\t"+site.name+"\t"+a)
		}
	}
	if *updateSubjectCopies {
		sort.Strings(lines)
		body := "# Answers of the subject copies SubjectOf replaced (origin/next 0e19c52de),\n" +
			"# per named row and site: row<TAB>site<TAB>answer. Written by\n" +
			"# go test -run TestSubjectCopiesRecordedAnswers -update-subject-copies.\n" +
			strings.Join(lines, "\n") + "\n"
		if err := os.MkdirAll(filepath.Dir(copiesPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(copiesPath, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want := recordedSubjectAnswers(t, copiesPath)
	if len(want) != len(got) {
		t.Errorf("recorded %d answers, the copies give %d", len(want), len(got))
	}
	for k, g := range got {
		if w, ok := want[k]; !ok || w != g {
			t.Errorf("%s: copy answers %q, recorded %q", strings.ReplaceAll(k, "\t", " at "), g, w)
		}
	}
}

// subjectGrid is every combination of user, proof levels and program path
// the differential test runs each site over.
func subjectGrid() []subjectFixture {
	users := []*User{nil, windowsUser, windowsNoSIDUser, posixUser, posixRootUser, posixNegUser, noKindUser}
	paths := []string{fixtureProgram(), fixtureMessyProgram(), "app", ""}
	var out []subjectFixture
	for _, u := range users {
		for up := ProofNone; up <= ProofSigned; up++ {
			for pp := ProofNone; pp <= ProofSigned; pp++ {
				for pa := ProofNone; pa <= ProofSigned; pa++ {
					for _, path := range paths {
						out = append(out, subjectFixture{u, up, pp, pa, path})
					}
				}
			}
		}
	}
	return out
}

func (f subjectFixture) String() string {
	kind := "no-user"
	if f.user != nil {
		kind = fmt.Sprintf("%s/sid=%q/uid=%d", f.user.Kind, f.user.SID, f.user.UID)
	}
	return fmt.Sprintf("%s user@%s process@%s path@%s %q", kind, f.userProof, f.procProof, f.pathPr, portable(f.path))
}
