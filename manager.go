package endless

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ErrNoHandler is the error returned if no Handler was configured on the Server.
var ErrNoHandler = errors.New("no handler")

// ErrRestartInProgress is the error returned if Restart is called while one is already progress.
var ErrRestartInProgress = errors.New("already forked")

var mgr *Manager

func init() {
	mgr = &Manager{
		servers: make(map[string]*Server),
		offsets: make(map[string]int),
		Logger:  log.New(os.Stderr, "", log.LstdFlags),
	}
	socketOrder := os.Getenv("ENDLESS_SOCKET_ORDER")
	if socketOrder != "" {
		mgr.parentFile = os.NewFile(uintptr(3), "parent")
		for i, addr := range strings.Split(socketOrder, ",") {
			mgr.offsets[addr] = i
		}
	}
}

// Manager is the responsible for managing Servers.
type Manager struct {
	handler    Handler
	mtx        sync.Mutex
	servers    map[string]*Server
	offsets    map[string]int
	parentFile *os.File
	*log.Logger
	restarting bool
	Debug      bool
}

// Listen returns a listener created from the socket it was passed when restarted or
// a new listener created from the details given.
func (m *Manager) Listen(s *Server) (net.Listener, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.handler == nil {
		return nil, ErrNoHandler
	}

	key := s.AddressKey()
	if i, ok := m.offsets[key]; ok {
		return net.FileListener(os.NewFile(uintptr(4+i), "socket"))
	}

	l, err := net.Listen(s.Net, s.Addr)
	if err != nil {
		m.offsets[key] = len(m.offsets)
	}
	return l, err
}

// Register adds a server to the managers registered servers.
func (m *Manager) Register(srv *Server) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	m.servers[srv.AddressKey()] = srv
}

// Unregister removes a server to the managers registered servers.
func (m *Manager) Unregister(srv *Server) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	delete(m.servers, srv.AddressKey())
}

func (m *Manager) restartInit() ([]*os.File, []string, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.restarting {
		return nil, nil, ErrRestartInProgress
	}

	files := make([]*os.File, len(m.servers))
	addrs := make([]string, len(m.servers))

	// Get the accessor socket fds for _all_ server instances
	for _, srv := range m.servers {
		f, err := srv.endlessListener.File()
		if err != nil {
			return nil, nil, err
		}
		key := srv.AddressKey()
		i := m.offsets[key]
		files[i] = f
		addrs[i] = key
	}

	m.restarting = true

	// Build the environment eliminating duplicates
	env := os.Environ()
	orderedAddrs := strings.Join(addrs, ",")
	seen := false
	for i, kv := range env {
		k := strings.SplitAfterN(kv, "=", 2)[0]
		if k == "ENDLESS_SOCKET_ORDER" {
			if seen {
				// Remove duplicates
				continue
			}
			env[i] = orderedAddrs
			seen = true
		}
	}

	if !seen {
		env = append(env, "ENDLESS_SOCKET_ORDER="+orderedAddrs)
	}

	return files, env, nil
}

// serverListening signals the parent to close when all servers have called this method.
func (m *Manager) serverListening() error {
	if m.parentFile == nil || len(m.servers) != len(m.offsets) {
		return nil
	}

	// Last server to listen, signal the parent it can close
	return m.parentFile.Close()
}

// Restart restarts the process with the new binary.
func (m *Manager) Restart() (*os.Process, error) {
	files, env, err := m.restartInit()
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = env

	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("restart failed: %v", err)
	}
	cmd.ExtraFiles = append([]*os.File{pw}, files...)

	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return nil, fmt.Errorf("restart failed: %v", err)
	}

	// Close our copy of the write side straight away so we don't hold it open
	// after the child closes it.
	pw.Close()
	go m.childWait(pr)

	return cmd.Process, nil
}

// childWait waits for the child to signal its finished its startup process
// by closing the other end of the pipe and then calls Shutdown.
func (m *Manager) childWait(rc io.ReadCloser) error {
	for {
		if _, err := rc.Read(make([]byte, 10)); err != nil {
			break
		}
	}

	return m.Shutdown()
}

// Shutdown calls shutdown on all registered servers.
func (m *Manager) Shutdown() error {
	for _, srv := range m.servers {
		if err := srv.Shutdown(); err != nil {
			return err
		}
	}

	return nil
}

// Terminate calls terminate on all registered servers.
func (m *Manager) Terminate(d time.Duration) error {
	for _, srv := range m.servers {
		if err := srv.Terminate(d); err != nil {
			return err
		}
	}

	return nil
}

// Debugln calls Println on Logger with the current pid prepended if Debug is true
func (m *Manager) Debugln(v ...interface{}) {
	if m.Debug {
		m.Println(append([]interface{}{os.Getpid()}, v...))
	}
}

// SetHandler sets the active handler on the Manager.
// If the manager already had an active handler then its Stop method is called.
func (m *Manager) SetHandler(h Handler) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if mgr.handler != nil {
		mgr.handler.Stop()
	}
	mgr.handler = h
}

// Restart calls Restart on the default manager.
func Restart() (*os.Process, error) {
	return mgr.Restart()
}

// Shutdown calls Shutdown on the default manager.
func Shutdown() error {
	return mgr.Shutdown()
}

// Terminate calls Terminate on the default manager.
func Terminate(d time.Duration) error {
	return mgr.Terminate(d)
}

// SetHandler calls SetHandler on the default manager.
func SetHandler(h Handler) {
	mgr.SetHandler(h)
	go h.Handle(mgr)
}
