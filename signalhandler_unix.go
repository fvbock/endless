// +build !windows

package endless

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// The default Handler for none Windows OSes is a SignalHandler
func init() {
	SetHandler(NewSignalHandler())
}

// SignalHook represents a signal processing hook.
// If false is returned no further processing of the signal is performed.
type SignalHook func(sig os.Signal) (cont bool)

// SignalHandler listens for signals and takes action on the Manager.
//
// By default:
// SIGHUP: calls Restart()
// SIGUSR2: calls Terminate(0), Shutdown() must have been called first.
// SIGINT & SIGTERM: calls Shutdown()
//
// Pre and post signal handles can also be registered for custom actions.
type SignalHandler struct {
	mtx       sync.Mutex
	done      chan struct{}
	preHooks  map[os.Signal][]SignalHook
	postHooks map[os.Signal][]SignalHook
}

// NewSignalHandler create a new SignalHandler for the s
func NewSignalHandler() *SignalHandler {
	return &SignalHandler{
		done:      make(chan struct{}),
		preHooks:  make(map[os.Signal][]SignalHook),
		postHooks: make(map[os.Signal][]SignalHook),
	}
}

// Stop stops the handler from taking any more action
func (s *SignalHandler) Stop() {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	select {
	case <-s.done:
		return
	default:
		close(s.done)
	}
}

// Handle listens for os.Signal's and calls any registered function hooks.
func (s *SignalHandler) Handle(m *Manager) {
	c := make(chan os.Signal, 1)
	signal.Notify(c)
	defer func() {
		signal.Stop(c)
		s.Stop()
	}()

	pid := syscall.Getpid()
	for {
		var sig os.Signal
		select {
		case sig = <-c:
		case <-s.done:
			return
		}

		if !s.handleSignal(s.preHooks[sig], sig) {
			return
		}

		switch sig {
		case syscall.SIGHUP:
			m.Debugln("Received", sig, "restarting...")
			if _, err := m.Restart(); err != nil {
				m.Println("Fork err:", err)
			}
		case syscall.SIGUSR2:
			m.Debugln("Received", sig, "terminating...")
			if err := m.Terminate(0); err != nil {
				m.Println(pid, err)
			}
		case syscall.SIGINT, syscall.SIGTERM:
			m.Debugln("Received", sig, "shutting down...")
			if err := m.Shutdown(); err != nil {
				m.Println(pid, err)
			}
		}

		s.handleSignal(s.postHooks[sig], sig)
	}
}

// handleSignal calls all hooks for a signal.
// Returns false early if a hook returns false.
func (s *SignalHandler) handleSignal(hooks []SignalHook, sig os.Signal) bool {
	for _, f := range hooks {
		if !f(sig) {
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
