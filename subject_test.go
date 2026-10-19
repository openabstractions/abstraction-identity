package identity

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// [ID-C7] SubjectOf names a Windows caller by its SID and a POSIX caller by
// its uid, refuses a negative uid, a missing SID, a user of no known kind and
// a missing program, and holds every attribute the need names to its proof.
func TestSubjectOf(t *testing.T) {
	program := fixtureProgram()
	userOnly := Need{User: ProofKernel}
	ptr := func(f subjectFixture) *subjectFixture { return &f }
	for _, c := range []struct {
		name string
		f    *subjectFixture
		need Need
		want Subject
		err  error // nil: success; else errors.Is target, or errNotProvenSentinel
	}{
		{"nil peer", nil, copyProgramNeed, Subject{}, ErrNoPeer},
		{"windows sid", ptr(best(windowsUser, program)), copyProgramNeed, Subject{"windows", fixtureSID, program}, nil},
		{"windows sid, account only", ptr(best(windowsUser, program)), userOnly, Subject{"windows", fixtureSID, ""}, nil},
		{"windows without sid", ptr(best(windowsNoSIDUser, program)), copyProgramNeed, Subject{}, ErrNoAccount},
		{"posix uid", ptr(best(posixUser, program)), copyProgramNeed, Subject{"posix", "1000", program}, nil},
		{"posix uid 0", ptr(best(posixRootUser, program)), userOnly, Subject{"posix", "0", ""}, nil},
		{"negative uid", ptr(best(posixNegUser, program)), copyProgramNeed, Subject{}, ErrNoAccount},
		{"negative uid, account only", ptr(best(posixNegUser, program)), userOnly, Subject{}, ErrNoAccount},
		{"no kind", ptr(best(noKindUser, program)), userOnly, Subject{}, ErrNoAccount},
		{"missing program", ptr(subjectFixture{posixUser, ProofKernel, ProofKernel, ProofNone, ""}), copyProgramNeed, Subject{}, ErrNotProven},
		{"missing program, account only", ptr(subjectFixture{posixUser, ProofKernel, ProofKernel, ProofNone, ""}), userOnly, Subject{"posix", "1000", ""}, nil},
		{"relative program", ptr(best(posixUser, "app")), copyProgramNeed, Subject{}, ErrNoProgram},
		{"program cleaned", ptr(best(posixUser, fixtureMessyProgram())), copyProgramNeed, Subject{"posix", "1000", program}, nil},
		{"program below a negative uid", ptr(best(posixNegUser, "app")), copyProgramNeed, Subject{}, ErrNoProgram},
		{"no user", ptr(subjectFixture{nil, ProofNone, ProofKernel, ProofBound, program}), Need{Path: ProofBound}, Subject{}, ErrNotProven},
	} {
		t.Run(c.name, func(t *testing.T) {
			var p *Peer
			if c.f != nil {
				p = c.f.peer()
			}
			got, err := SubjectOf(p, c.need)
			if c.err == nil {
				if err != nil || got != c.want {
					t.Fatalf("SubjectOf = %+v, %v; want %+v", got, err, c.want)
				}
				return
			}
			if !errors.Is(err, c.err) || got != (Subject{}) {
				t.Fatalf("SubjectOf = %+v, %v; want refusal %v", got, err, c.err)
			}
		})
	}
	// Each proof level of each attribute the need names: below the need
	// refuses with ErrNotProven, at or above it names the caller.
	for p := ProofNone; p <= ProofSigned; p++ {
		for _, attr := range []string{"user", "process", "path"} {
			f := subjectFixture{posixUser, ProofKernel, ProofKernel, ProofBound, program}
			var need Proof
			switch attr {
			case "user":
				f.userProof, need = p, copyProgramNeed.User
			case "process":
				f.procProof, need = p, copyProgramNeed.Process
			case "path":
				f.pathPr, need = p, copyProgramNeed.Path
			}
			got, err := SubjectOf(f.peer(), copyProgramNeed)
			if p >= need {
				if err != nil || got != (Subject{"posix", "1000", program}) {
					t.Errorf("%s at %s: SubjectOf = %+v, %v", attr, p, got, err)
				}
			} else if !errors.Is(err, ErrNotProven) {
				t.Errorf("%s at %s below %s: SubjectOf = %+v, %v; want ErrNotProven", attr, p, need, got, err)
			}
		}
	}
}

// [ID-C7] User.Account is the account half of SubjectOf.
func TestUserAccount(t *testing.T) {
	for _, c := range []struct {
		u    User
		want string
	}{
		{*windowsUser, fixtureSID},
		{*windowsNoSIDUser, ""},
		{*posixUser, "1000"},
		{*posixRootUser, "0"},
		{*posixNegUser, ""},
		{User{Kind: "posix", UID: -2}, ""},
		{*noKindUser, ""},
		{User{Kind: "windows", SID: fixtureSID, UID: 1000}, fixtureSID},
		{User{Kind: "posix", SID: fixtureSID, UID: 7}, "7"},
	} {
		got, err := c.u.Account()
		if got != c.want || (c.want == "") != errors.Is(err, ErrNoAccount) {
			t.Errorf("%+v.Account() = %q, %v; want %q", c.u, got, err, c.want)
		}
	}
}

func TestAdmitOwnerThreeRefusalsAndExactSubject(t *testing.T) {
	program := fixtureProgram()
	ptr := func(f subjectFixture) *Peer { return f.peer() }
	for _, tc := range []struct {
		name    string
		peer    *Peer
		need    Need
		owner   string
		want    Subject
		verdict OwnerAdmission
	}{
		{"no peer", nil, copyProgramNeed, "1000", Subject{}, OwnerUnavailable},
		{"unproven", ptr(subjectFixture{posixUser, ProofNone, ProofKernel, ProofBound, program}), copyProgramNeed, "1000", Subject{}, OwnerIdentityRequired},
		{"unnameable program", ptr(best(posixUser, "relative")), copyProgramNeed, "1000", Subject{}, OwnerIdentityRequired},
		{"missing account", ptr(best(windowsNoSIDUser, program)), copyProgramNeed, "owner", Subject{}, OwnerOtherAccount},
		{"negative account", ptr(best(posixNegUser, program)), copyProgramNeed, "1000", Subject{}, OwnerOtherAccount},
		{"foreign account", ptr(best(posixUser, program)), copyProgramNeed, "1001", Subject{}, OwnerOtherAccount},
		{"empty owner", ptr(best(posixUser, program)), copyProgramNeed, "", Subject{}, OwnerOtherAccount},
		{"same posix", ptr(best(posixUser, program)), copyProgramNeed, "1000", Subject{"posix", "1000", program}, OwnerAdmitted},
		{"same windows", ptr(best(windowsUser, program)), copyProgramNeed, fixtureSID, Subject{"windows", fixtureSID, program}, OwnerAdmitted},
		{"account only", ptr(best(posixUser, "relative")), Need{User: ProofKernel}, "1000", Subject{"posix", "1000", ""}, OwnerAdmitted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, verdict := AdmitOwner(tc.peer, tc.need, tc.owner)
			if got != tc.want || verdict != tc.verdict {
				t.Fatal(got, verdict, tc.want, tc.verdict)
			}
		})
	}
}

// subjectReplacements are the sites of subjectCopies as they call SubjectOf
// after CQ-3(b), each written as its service's code is, keyed by the same
// site name.
var subjectReplacements = map[string]func(*Peer, string) string{
	"rights/go/client/authorization.go:30":             newFromPeer(copyProgramNeed),
	"credentials/go/service/host.go:155":               newFromPeer(copyProgramNeed),
	"inference/go/service/host.go:276":                 newFromPeer(copyProgramNeed),
	"resource/go/service/leases_host.go:47":            newFromPeer(copyProgramNeed),
	"inference/adapters/go/gateway/window.go:494":      newFromPeer(copyGatewayNeed),
	"asks/go/application/receiver.go:26":               newAsks,
	"config/go/service/service.go:171":                 newOwnerCheck("refused:identity_required", "refused:wrong_user"),
	"facade/go-core/resolution/caller.go:21":           newResolution,
	"facade/go/runtime/jobs.go:99":                     newJobsAuthorize,
	"facade/go/runtime/jobs.go:129":                    newJobsBinding,
	"facade/go/runtime/host.go:815":                    newResolverOwner,
	"logging/go/service/service.go:203":                newLoggingWrite,
	"logging/go/service/service.go:260":                newOwnerCheck("refused:identity_required", "refused:wrong_user"),
	"logging/go/service/application_history.go:74":     newLoggingApplication,
	"model/go/service/service.go:173":                  newModelAuthorized,
	"model/go/service/service.go:224":                  newModelSubject,
	"provider-modelbridge/go/service/host.go:162":      newModelbridge,
	"storage-over-local-stores/go/service/host.go:145": newOwnerCheck("refused:identity_required", "refused:forbidden"),
	"storage/go/service/service.go:343":                newStorageScope,
	"job/go/acceptanceprovider/link.go:69":             newJobLink,
	"conformance/clients/router/server.go:72":          newResolverOwner,
	"conformance/clients/facade/host.go:91":            newResolverOwner,
	"serve/opencode_session_windows.go:278":            newOpenCodeSession,
	"serve/runtime_logging.go:25":                      newSelfAccount,
	"examples/rights-playground/main.go:250":           newSelfAccount,
}

func newOpenCodeSession(peer *Peer, owner string) string {
	subject, err := SubjectOf(peer, subjectUserOnly)
	if err != nil {
		return "refused"
	}
	if _, err := peer.Process.AtLeast(ProofKernel); err != nil {
		return "refused"
	}
	if _, err := peer.Path.AtLeast(ProofBound); err != nil {
		return "refused"
	}
	if subject.AccountKind != "windows" || subject.Account != owner {
		return "refused"
	}
	return subjectOK(subject.AccountKind, subject.Account, "")
}

// newSelfAccount is User.Account on Self's answer, as serve's runtime log
// writer and the rights playground call it.
func newSelfAccount(peer *Peer, _ string) string {
	principal, err := peer.User.AtLeast(ProofNone)
	if err != nil {
		return "refused"
	}
	account, err := principal.Account()
	if err != nil {
		return "refused"
	}
	return subjectOK(principal.Kind, account, "")
}

var subjectUserOnly = Need{User: ProofKernel}

func newFromPeer(need Need) func(*Peer, string) string {
	return func(p *Peer, _ string) string {
		s, err := SubjectOf(p, need)
		if err != nil {
			return "refused"
		}
		return subjectOK(s.AccountKind, s.Account, s.Program)
	}
}

func newAsks(p *Peer, owner string) string {
	if p == nil {
		return "refused:caller_required"
	}
	s, e := SubjectOf(p, subjectUserOnly)
	if e != nil && !errors.Is(e, ErrNoAccount) {
		return "refused:proof"
	}
	if e != nil || s.Account != owner {
		return "refused:account acct=" + s.Account
	}
	path, e := p.Path.AtLeast(copyProgramNeed.Path)
	if e != nil || !filepath.IsAbs(path) {
		return "refused:program"
	}
	return subjectOK(s.AccountKind, s.Account, filepath.Clean(path))
}

// newOwnerCheck is config's authorize, logging's authorizeHistory and the
// local stores' admits: a proof failure answers proof, an account that
// cannot be named or is not the owner answers account.
func newOwnerCheck(proof, account string) func(*Peer, string) string {
	return func(p *Peer, owner string) string {
		s, err := SubjectOf(p, subjectUserOnly)
		if err != nil && !errors.Is(err, ErrNoAccount) {
			return proof
		}
		if err != nil || s.Account != owner {
			return account + " acct=" + s.Account
		}
		return subjectOK(s.AccountKind, s.Account, "")
	}
}

func newResolution(peer *Peer, _ string) string {
	if peer == nil {
		return "refused"
	}
	subject, err := SubjectOf(peer, subjectUserOnly)
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
	return subjectOK(subject.AccountKind, subject.Account, program)
}

func newJobsAuthorize(peer *Peer, owner string) string {
	if peer == nil {
		return "refused:caller_evidence"
	}
	subject, err := SubjectOf(peer, subjectUserOnly)
	if err != nil && !errors.Is(err, ErrNoAccount) {
		return "refused:proof"
	}
	if err != nil || subject.Account != owner {
		return "refused:another_owner acct=" + subject.Account
	}
	path, err := peer.Path.AtLeast(copyProgramNeed.Path)
	if err != nil || path == "" || !filepath.IsAbs(path) {
		return "refused:program"
	}
	return subjectOK(subject.AccountKind, subject.Account, path)
}

func newJobsBinding(peer *Peer, owner string) string {
	if a := newJobsAuthorize(peer, owner); strings.HasPrefix(a, "refused") {
		return a
	}
	subject, err := SubjectOf(peer, Need{User: copyProgramNeed.User, Path: copyProgramNeed.Path})
	if err != nil {
		return "refused:program"
	}
	path, err := peer.Path.AtLeast(copyProgramNeed.Path)
	if err != nil {
		return "refused:program"
	}
	return subjectOK(subject.AccountKind, subject.Account, filepath.Clean(path)+" "+subject.Program)
}

func newResolverOwner(peer *Peer, owner string) string {
	subject, err := SubjectOf(peer, subjectUserOnly)
	if err != nil && !errors.Is(err, ErrNoAccount) {
		return "refused"
	}
	if err == nil && subject.Account == owner {
		return subjectOK(subject.AccountKind, subject.Account, "")
	}
	return "refused acct=" + subject.Account
}

func newLoggingWrite(observed *Peer, _ string) string {
	if _, err := observed.Path.AtLeast(copyProgramNeed.Path); err != nil {
		return "refused"
	}
	if _, err := observed.User.AtLeast(copyProgramNeed.User); err != nil {
		return "refused"
	}
	if _, err := observed.Process.AtLeast(copyProgramNeed.Process); err != nil {
		return "refused"
	}
	subject, err := SubjectOf(observed, copyProgramNeed)
	if err != nil {
		return "refused"
	}
	return subjectOK(subject.AccountKind, subject.Account, subject.Program)
}

func newLoggingApplication(peer *Peer, owner string) string {
	if _, err := peer.User.AtLeast(copyProgramNeed.User); err != nil {
		return "refused:native_account"
	}
	subject, err := SubjectOf(peer, Need{User: copyProgramNeed.User, Path: copyProgramNeed.Path})
	switch {
	case err == nil:
	case errors.Is(err, ErrNoAccount):
		return "refused:wrong_user acct="
	default:
		return "refused:native_program"
	}
	if subject.Account != owner {
		return "refused:wrong_user acct=" + subject.Account
	}
	return subjectOK(subject.AccountKind, subject.Account, subject.Program)
}

func newModelAuthorized(p *Peer, owner string) string {
	s, e := SubjectOf(p, subjectUserOnly)
	if e != nil && !errors.Is(e, ErrNoAccount) {
		return "refused"
	}
	if e == nil && s.Account == owner {
		return subjectOK(s.AccountKind, s.Account, "")
	}
	return "refused acct=" + s.Account
}

func newModelSubject(p *Peer, owner string) string {
	s, e := SubjectOf(p, subjectUserOnly)
	if e != nil {
		return "refused"
	}
	program, e := p.Path.AtLeast(copyProgramNeed.Path)
	if e != nil || s.Account != owner || !filepath.IsAbs(program) {
		return "refused"
	}
	return subjectOK(s.AccountKind, s.Account, filepath.Clean(program))
}

func newModelbridge(peer *Peer, owner string) string {
	s, err := SubjectOf(peer, subjectUserOnly)
	if err != nil && !errors.Is(err, ErrNoAccount) {
		return "refused:identity_required"
	}
	if err != nil || s.Account != owner {
		return "refused:forbidden acct=" + s.Account
	}
	program, err := SubjectProgram(peer, copyProgramNeed.Path)
	if err != nil {
		return "refused:identity_required"
	}
	return subjectOK(s.AccountKind, s.Account, program)
}

func newStorageScope(peer *Peer, owner string) string {
	if peer == nil {
		return "refused"
	}
	s, e := SubjectOf(peer, subjectUserOnly)
	if e != nil && !errors.Is(e, ErrNoAccount) {
		return "refused"
	}
	if e != nil || s.Account != owner {
		return "refused acct=" + s.Account
	}
	path, e := peer.Path.AtLeast(copyProgramNeed.Path)
	if e != nil || !filepath.IsAbs(path) {
		return "refused"
	}
	return subjectOK(s.AccountKind, s.Account, filepath.Clean(path))
}

// newJobLink is SameAuthority's userPrincipal through User.Account.
func newJobLink(peer *Peer, owner string) string {
	if peer == nil {
		return "refused"
	}
	user, err := peer.User.AtLeast(ProofKernel)
	if err != nil {
		return "refused"
	}
	account, err := user.Account()
	if err != nil {
		return "refused"
	}
	if account != owner {
		return "refused acct=" + account
	}
	return subjectOK(user.Kind, account, "")
}

// intendedSubjectChange reports the one change CQ-3(b) makes on purpose:
// a user whose account cannot be named (a negative uid, a missing SID, no
// known kind) is refused everywhere, and a nil peer, which no site was
// handed, is refused rather than dereferenced.
func intendedSubjectChange(f *subjectFixture, old string) bool {
	if f == nil {
		return old == "panic"
	}
	if f.user == nil {
		return false
	}
	_, err := f.user.Account()
	return err != nil
}

// [ID-C7] Every replaced site answers as its recorded copy did, for the
// named rows against testdata/subject-of/copies.txt and for every grid
// combination against the transcription, except the intended refusal.
func TestSubjectOfMatchesEveryCopy(t *testing.T) {
	if len(subjectReplacements) != len(subjectCopies) {
		t.Fatalf("%d replacements for %d copies", len(subjectReplacements), len(subjectCopies))
	}
	recorded := recordedSubjectAnswers(t, copiesPath)
	for _, row := range namedSubjectRows() {
		for _, site := range subjectCopies {
			replacement := subjectReplacements[site.name]
			if replacement == nil {
				t.Fatalf("no replacement for %s", site.name)
			}
			old := recorded[row.name+"\t"+site.name]
			got := portable(answer(replacement, row.f))
			check(t, row.name, site.name, row.f, old, got)
		}
	}
	for _, f := range subjectGrid() {
		f := f
		for _, site := range subjectCopies {
			old := portable(answer(site.old, &f))
			got := portable(answer(subjectReplacements[site.name], &f))
			check(t, f.String(), site.name, &f, old, got)
		}
	}
}

func check(t *testing.T, row, site string, f *subjectFixture, old, got string) {
	t.Helper()
	if got != old && intendedSubjectChange(f, old) {
		if !strings.HasPrefix(got, "refused") {
			t.Errorf("%s at %s: answers %q, want a refusal (was %q)", row, site, got, old)
			return
		}
		// A site that refused before keeps its refusal class; only the
		// account it names may change (acct=-1 becomes acct=).
		if strings.HasPrefix(old, "refused") && refusalClass(got) != refusalClass(old) {
			t.Errorf("%s at %s: refuses as %q, recorded %q", row, site, refusalClass(got), refusalClass(old))
		}
		return
	}
	if got != old {
		t.Errorf("%s at %s: answers %q, recorded %q", row, site, got, old)
	}
}

// refusalClass is an answer's first field: "refused:wrong_user" of
// "refused:wrong_user acct=-1".
func refusalClass(answer string) string {
	if i := strings.IndexByte(answer, ' '); i >= 0 {
		return answer[:i]
	}
	return answer
}
