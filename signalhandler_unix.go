// +build !windows

package endless

import (
	"os"
	"os/signal"
	"syscall"
)

// The default Handler for none Windows OSes is a SignalHandler
func init() {
	DefaultHandler = NewSignalHandler()
}

// SignalHook represents a signal processing hook.
// If false is returned no further processing of the signal is performed.
type SignalHook func(sig os.Signal, srv *Server) (cont bool)

// SignalHandler listens for signals and takes action on the Server.
//
// By default:
// SIGHUP: calls Restart()
// SIGUSR2: calls Terminate(0), Shutdown() must have been called first.
// SIGINT & SIGTERM: calls Shutdown()
//
// Pre and post signal handles can also be registered for custom actions.
type SignalHandler struct {
	preHooks  map[os.Signal][]SignalHook
	postHooks map[os.Signal][]SignalHook
}

// NewSignalHandler create a new SignalHandler for the s
func NewSignalHandler() *SignalHandler {
	return &SignalHandler{
		preHooks:  make(map[os.Signal][]SignalHook),
		postHooks: make(map[os.Signal][]SignalHook),
	}
}

// Handle listens for os.Signal's and calls any registered function hooks.
func (s *SignalHandler) Handle(srv *Server) {
	c := make(chan os.Signal, 1)
	signal.Notify(c)

	pid := syscall.Getpid()
	for {
		var sig os.Signal
		select {
		case sig = <-c:
		case <-srv.Done:
			return
		}

		if !s.handleSignal(s.preHooks[sig], sig, srv) {
			continue
		}

		switch sig {
		case syscall.SIGHUP:
			srv.Debugln("Received", sig, "restarting...")
			if err := srv.Restart(); err != nil {
				srv.Println("Fork err:", err)
			}
		case syscall.SIGUSR2:
			srv.Debugln("Received", sig, "terminating...")
			if err := srv.Terminate(0); err != nil {
				srv.Println(pid, err)
			}
		case syscall.SIGINT, syscall.SIGTERM:
			srv.Debugln("Received", sig, "shutting down...")
			if err := srv.Shutdown(); err != nil {
				srv.Println(pid, err)
			}
		}

		s.handleSignal(s.postHooks[sig], sig, srv)
	}
}

// handleSignal calls all hooks for a signal.
// Returns false early if a hook returns false.
func (s *SignalHandler) handleSignal(hooks []SignalHook, sig os.Signal, srv *Server) bool {
	for _, f := range hooks {
		if !f(sig, srv) {
			return false
		}
	}
	return true
}

// RegisterPreSignalHook registers a function to be run before any built in signal action.
func (s *SignalHandler) RegisterPreSignalHook(sig os.Signal, f SignalHook) {
	s.preHooks[sig] = append(s.preHooks[sig], f)
}

// RegisterPostSignalHook registers a function to be run after any built in signal action.
func (s *SignalHandler) RegisterPostSignalHook(sig os.Signal, f SignalHook) {
	s.preHooks[sig] = append(s.preHooks[sig], f)
}
