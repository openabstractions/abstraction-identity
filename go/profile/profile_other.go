//go:build !windows

package profile

func probeView() (View, error) { return View{}, nil }
