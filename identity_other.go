//go:build !windows && !darwin && !linux

package identity

// Every other GOOS. The package compiles so that portable code depending on it
// still builds, and every call fails, so that nothing depending on it can
// accidentally ship a permission model that grants on an unanswered question.

func ceiling() Limits {
	return Limits{
		Platform:  "unsupported",
		Transport: "none",
		Bindable:  false,
		Binding:   unimplementedWhy,
		Best:      Need{},
		Why: map[string]string{
			"user":    unimplementedWhy,
			"process": unimplementedWhy,
			"path":    unimplementedWhy,
			"package": unimplementedWhy,
			"code":    unimplementedWhy,
		},
	}
}

const unimplementedWhy = "this operating system is not supported; no peer identity is available at any strength"

func ofHandle(h Handle, opts *Options) (*Peer, error) { return nil, ErrUnimplemented }

func bindHandle(h Handle, opts *Options) (binder, *Peer, error) { return nil, nil, ErrUnimplemented }
