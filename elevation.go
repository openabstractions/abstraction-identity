package identity

// Token elevation types, TOKEN_ELEVATION_TYPE's values.
const (
	tokenElevationTypeDefault uint32 = 1 // no split token: UAC off, a standard user, the built-in Administrator, SYSTEM
	tokenElevationTypeFull    uint32 = 2 // the elevated half of a split admin token, after a UAC prompt
	tokenElevationTypeLimited uint32 = 3 // the filtered half: an admin's ordinary medium-integrity process
)

// elevatedToken classifies a Windows token from three of its fields [ID-H3]:
// its TOKEN_ELEVATION_TYPE, TokenElevation's TokenIsElevated and its
// mandatory label RID. A token is elevated when its label is high or above
// and it is either the full half of a split token or a token with no split
// that Windows itself reports elevated (an administrator with UAC off, the
// built-in Administrator). An admin's ordinary process holds the limited half:
// its Administrators SID is deny-only, so it is never elevated here. A token
// whose label could not be read has RID 0 and is never elevated. No group SID
// is consulted.
func elevatedToken(elevationType uint32, tokenIsElevated bool, rid uint32) bool {
	if !tokenIsElevated || rid < highIntegrityRID {
		return false
	}
	return elevationType == tokenElevationTypeFull || elevationType == tokenElevationTypeDefault
}

// Elevated is the bound peer attribute elevated [ID-H3]: the peer is a local
// native named-pipe peer on Windows whose token, read at kernel from the
// pipe at accept, and whose pinned process's primary token both classify as
// elevated, at high integrity or above and unrestricted, and whose process
// reads at kernel and was not recycled. Every other peer reads false: a
// loopback, AF_UNIX, XPC, remote or synthetic peer, any peer outside Windows
// and any peer whose evidence fell short. Nothing a peer sends can set it.
// It says nothing about the account; a caller compares User.SID itself.
func (p *Peer) Elevated() bool {
	if p == nil || p.Platform != "windows" || p.Transport != string(TransportNamedPipe) {
		return false
	}
	u, err := p.User.AtLeast(ProofKernel)
	if err != nil || u.Kind != "windows" || u.SID == "" || !u.Elevated || u.Restricted || u.IntegrityRID < highIntegrityRID {
		return false
	}
	proc, err := p.Process.AtLeast(ProofKernel)
	return err == nil && proc.PID > 0 && !proc.Recycled && !proc.StartTime.IsZero()
}
