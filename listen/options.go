package listen

import "time"

// WithDefaults fills unset limits and snapshots independently supplied server
// expectations. Explicit limits, dialers and per-call contexts are preserved.
func (c FrameClient) WithDefaults(timeout time.Duration, maxFrame uint32) FrameClient {
	if c.Timeout == 0 {
		c.Timeout = timeout
	}
	if c.MaxFrame == 0 {
		c.MaxFrame = maxFrame
	}
	if c.Server != nil {
		server := *c.Server
		if server.Process != nil {
			process := *server.Process
			server.Process = &process
		}
		c.Server = &server
	}
	return c
}
