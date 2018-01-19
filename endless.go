package endless

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"
)

// State represents the current state of Server
type State uint8

const (
	// StateInit is the state of server when its created.
	StateInit State = iota

	// StateRunning is the state of server when its running.
	StateRunning

	// StateShuttingDown is the state of server when it is shutting down.
	StateShuttingDown

	// StateShutdown is the state of server when it has shutdown.
	StateShutdown

	// StateTerminated is the state of server if it was forcibly terminated.
	StateTerminated

	// StateFailed is the state of server if failed unexpectedly.
	StateFailed
)

func (s State) String() string {
	switch s {
	case StateInit:
		return "init"
	case StateRunning:
		return "running"
	case StateShuttingDown:
		return "shutting down"
	case StateShutdown:
		return "shutdown"
	case StateTerminated:
		return "terminated"
	default:
		return fmt.Sprintf("state(%d)", s)
	}
}

// InvalidStateError is the error type returned if an invalid state transition is attempted.
type InvalidStateError struct {
	CurrentState   State
	RequestedState State
}

func (err *InvalidStateError) Error() string {
	return fmt.Sprintf("invalid state transition from %v to %v", err.CurrentState, err.RequestedState)
}

// Default values used on server creation.
var (
	// DefaultReadTimeout is the default value assigned to ReadTimeout of Servers.
	DefaultReadTimeout time.Duration

	// DefaultWriteTimeout is the default value assigned to WriteTimeout of Servers.
	DefaultWriteTimeout time.Duration

	// DefaultMaxHeaderBytes is the default value assigned to MaxHeaderBytes of Servers.
	DefaultMaxHeaderBytes int

	// DefaultTerminateTimeout is the default value assigned to TerminateTimeout of Servers.
	DefaultTerminateTimeout = 60 * time.Second
)

// Handler is the interface that objects implement to perform operations on a endless Servers.
type Handler interface {
	Handle(*Manager)
	Stop()
}

// Server represents a endless server.
type Server struct {
	http.Server
	state            State
	listener         net.Listener
	endlessListener  *Listener
	wg               sync.WaitGroup
	BeforeBegin      func(add string)
	mtx              sync.RWMutex
	TerminateTimeout time.Duration
	Done             chan struct{}
	Debug            bool
	Net              string
}

// NewServer returns an initialized Server Object. Calling Serve on it will
// actually "start" the server.
func NewServer(net, addr string, handler http.Handler) (srv *Server) {
	srv = &Server{
		Done: make(chan struct{}),
		Net:  net,
	}

	srv.Server.Addr = addr
	srv.Server.ReadTimeout = DefaultReadTimeout
	srv.Server.WriteTimeout = DefaultWriteTimeout
	srv.Server.MaxHeaderBytes = DefaultMaxHeaderBytes
	srv.Server.Handler = handler
	srv.TerminateTimeout = DefaultTerminateTimeout

	srv.BeforeBegin = func(addr string) {
		srv.Debugln(syscall.Getpid(), addr)
	}

	mgr.Register(srv)

	return
}

// AddressKey returns the unique address key for the server.
func (srv *Server) AddressKey() string {
	return srv.Net + ":" + srv.Addr
}

// Printf calls Printf on ErrorLog if not nil otherwise it calls log.Printf.
func (srv *Server) Printf(format string, v ...interface{}) {
	if srv.ErrorLog != nil {
		srv.ErrorLog.Printf(format, v...)
	} else {
		log.Printf(format, v...)
	}
}

// Println calls Println on ErrorLog if not nil otherwise it calls log.Println.
func (srv *Server) Println(v ...interface{}) {
	if srv.ErrorLog != nil {
		srv.ErrorLog.Println(v...)
	} else {
		log.Println(v...)
	}
}

// Debugln calls Println with the current pid prepended if Debug is true
func (srv *Server) Debugln(v ...interface{}) {
	if srv.Debug {
		srv.Println(append([]interface{}{syscall.Getpid()}, v...))
	}
}

// ListenAndServe listens on the TCP network address addr and then calls Serve
// with handler to handle requests on incoming connections. Handler is typically
// nil, in which case the DefaultServeMux is used.
func ListenAndServe(addr string, handler http.Handler) error {
	server := NewServer("tcp", addr, handler)
	return server.ListenAndServe()
}

// ListenAndServeTLS acts identically to ListenAndServe, except that it expects
// HTTPS connections. Additionally, files containing a certificate and matching
// private key for the server must be provided. If the certificate is signed by a
// certificate authority, the certFile should be the concatenation of the server's
// certificate followed by the CA's certificate.
func ListenAndServeTLS(addr string, certFile string, keyFile string, handler http.Handler) error {
	server := NewServer("tcp", addr, handler)
	return server.ListenAndServeTLS(certFile, keyFile)
}

// GetState returns the current state of the server.
func (srv *Server) GetState() State {
	srv.mtx.RLock()
	defer srv.mtx.RUnlock()

	return srv.state
}

// invalidState returns an invalid state with the RequestedState set to req.
func (srv *Server) invalidState(req State) error {
	return &InvalidStateError{CurrentState: srv.state, RequestedState: req}
}

// setState updates the current state of the server to st.
// If its not valid to transition from the current state to st then and
// InvalidStateError is returned.
func (srv *Server) setState(st State) error {
	if st == srv.state {
		return nil
	}

	switch {
	case st == StateInit && srv.state != StateInit:
		return srv.invalidState(st)
	case st == StateRunning && srv.state != StateInit:
		return srv.invalidState(st)
	case st == StateShuttingDown && srv.state != StateRunning:
		return srv.invalidState(st)
	case st == StateShutdown:
		switch srv.state {
		case StateShuttingDown:
			// Nothing
		case StateFailed, StateTerminated:
			return nil
		default:
			return srv.invalidState(st)
		}
	case st == StateTerminated:
		if srv.state != StateShuttingDown {
			return srv.invalidState(st)
		}
	case st == StateFailed:
		switch srv.state {
		case StateTerminated, StateShutdown:
			return srv.invalidState(st)
		}
	}

	switch st {
	case StateTerminated, StateFailed, StateShutdown:
		// Final state
		mgr.Unregister(srv)
		if srv.listener != nil {
			srv.listener.Close()
		}
		close(srv.Done)
	}

	srv.state = st

	return nil
}

// Serve accepts incoming HTTP connections on the Listener l, creating a new
// service goroutine for each. The service goroutines read requests and then call
// handler to reply to them. Handler is typically nil, in which case the
// DefaultServeMux is used.
//
// In addition to the standard library Serve behaviour each connection is added to a
// sync.Waitgroup so that all outstanding connections can be served before shutting
// down the server.
func (srv *Server) Serve() error {
	srv.mtx.Lock()
	defer srv.mtx.Unlock()

	return srv.serveLocked()
}

func (srv *Server) serveLocked() error {
	if err := srv.setState(StateRunning); err != nil {
		return err
	}

	// Drop the lock while we're actually in serve or waiting for connections
	// to complete.
	srv.mtx.Unlock()

	defer srv.Debugln(syscall.Getpid(), "Serve() returning...")

	err := srv.Server.Serve(srv.listener)
	srv.Debugln(syscall.Getpid(), "Waiting for connections to finish...")
	srv.wg.Wait()

	srv.Debugln(syscall.Getpid(), "Connections finished")

	// Reobtain the lock while we manipulate state, ensuring that callers
	// unlock is successfull.
	srv.mtx.Lock()
	if err != nil && srv.state == StateRunning {
		// Unexpected error as we're still meant to be running
		srv.setState(StateFailed)
		return err
	}
	return srv.setState(StateShutdown)
}

// ListenAndServe listens on the TCP network address srv.Addr and then calls Serve
// to handle requests on incoming connections. If srv.Addr is blank, ":http" is
// used.
func (srv *Server) ListenAndServe() error {
	srv.mtx.Lock()
	defer srv.mtx.Unlock()

	if srv.Addr == "" {
		srv.Addr = ":http"
	}

	l, err := mgr.Listen(srv)
	if err != nil {
		srv.setState(StateFailed)
		return err
	}

	srv.endlessListener = NewListener(l, srv)
	srv.listener = srv.endlessListener

	if err = mgr.serverListening(); err != nil {
		srv.setState(StateFailed)
		return err
	}

	srv.BeforeBegin(srv.Addr)

	return srv.serveLocked()
}

// ListenAndServeTLS listens on the TCP network address srv.Addr and then calls
// Serve to handle requests on incoming TLS connections.
//
// Filenames containing a certificate and matching private key for the server must
// be provided. If the certificate is signed by a certificate authority, the
// certFile should be the concatenation of the server's certificate followed by the
// CA's certificate.
//
// If srv.Addr is blank, ":https" is used.
func (srv *Server) ListenAndServeTLS(certFile, keyFile string) (err error) {
	srv.mtx.Lock()
	defer srv.mtx.Unlock()

	if srv.Addr == "" {
		srv.Addr = ":https"
	}

	config := &tls.Config{}
	if srv.TLSConfig != nil {
		*config = *srv.TLSConfig
	}
	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}

	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		srv.setState(StateFailed)
		return
	}

	var l net.Listener
	l, err = mgr.Listen(srv)
	if err != nil {
		srv.setState(StateFailed)
		return
	}

	srv.endlessListener = NewListener(l, srv)
	srv.listener = tls.NewListener(srv.endlessListener, config)

	if err = mgr.serverListening(); err != nil {
		srv.setState(StateFailed)
		return err
	}

	srv.BeforeBegin(srv.Addr)

	return srv.serveLocked()
}

// Shutdown closes the Listener so that no new connections are accepted. it also
// starts a goroutine that will terminate (stop all running requests) the server
// after TerminateTimeout.
func (srv *Server) Shutdown() error {
	srv.mtx.Lock()
	defer srv.mtx.Unlock()

	switch srv.state {
	case StateShuttingDown, StateShutdown, StateTerminated, StateFailed:
		// No action needed
		return nil
	}

	if err := srv.setState(StateShuttingDown); err != nil {
		return err
	}

	err := srv.listener.Close()
	if srv.TerminateTimeout >= 0 {
		go srv.Terminate(srv.TerminateTimeout)
	}

	return err
}

// Terminate forces the server to shutdown in a given timeout - whether it
// finished outstanding requests or not. if Read/WriteTimeout are not set or the
// max header size is very big a connection could hang...
//
// srv.Serve() will not return until all connections are served. this will
// unblock the srv.wg.Wait() in Serve() thus causing ListenAndServe(TLS) to
// return.
func (srv *Server) Terminate(d time.Duration) error {
	srv.mtx.Lock()

	if srv.state != StateShuttingDown {
		srv.mtx.Unlock()
		return srv.invalidState(StateTerminated)
	}

	// Drop the lock while we wait
	srv.mtx.Unlock()

	select {
	case <-time.After(d):
	case <-srv.Done:
		// Shutdown succeeded in grace period
		return nil
	}

	// Check Shutdown really didn't succeed as select is random
	select {
	case <-srv.Done:
		// Shutdown succeeded in grace period
		return nil
	default:
	}
	srv.mtx.Lock()
	defer srv.mtx.Unlock()

	srv.endlessListener.Terminate()

	return srv.setState(StateTerminated)
}

// Listener represents an endless listener.
type Listener struct {
	net.Listener
	mtx    sync.Mutex
	server *Server
	conns  map[*conn]struct{}
}

// Terminate closes all active connections accepted by the listener.
func (el *Listener) Terminate() {
	el.mtx.Lock()
	defer el.mtx.Unlock()

	for c := range el.conns {
		el.closeConnLocked(c)
	}
}

// Accept implements the Accept method in the Listener interface; it waits
// for the next call and returns a generic Conn.
func (el *Listener) Accept() (net.Conn, error) {
	c, err := el.Listener.Accept()
	if err != nil {
		return nil, err
	}

	wc := &conn{
		Conn:     c,
		listener: el,
	}

	el.mtx.Lock()
	defer el.mtx.Unlock()

	el.conns[wc] = struct{}{}
	el.server.wg.Add(1)

	return wc, nil
}

// closeConn closes a connection removing it from the active connections list and notifies the server its done.
func (el *Listener) closeConn(c *conn) error {
	el.mtx.Lock()
	defer el.mtx.Unlock()

	return el.closeConnLocked(c)
}

func (el *Listener) closeConnLocked(c *conn) error {
	if c.closed {
		// Already closed
		return nil
	}

	delete(el.conns, c)
	el.server.wg.Done()
	c.closed = true

	return c.Conn.Close()
}

// ErrUnsupportedListener is the error returned when the Listener doesn't support a File method.
type ErrUnsupportedListener struct {
	net.Listener
}

func (e *ErrUnsupportedListener) Error() string {
	return fmt.Sprintf("%T", e.Listener)
}

// NewListener creates a new Listener.
func NewListener(l net.Listener, srv *Server) *Listener {
	return &Listener{
		Listener: l,
		server:   srv,
		conns:    make(map[*conn]struct{}),
	}
}

type listenerFile interface {
	File() (*os.File, error)
}

// File returns an os.File duplicated from the listener.
func (el *Listener) File() (*os.File, error) {
	// returns a dup(2) - FD_CLOEXEC flag *not* set
	if t, ok := el.Listener.(listenerFile); ok {
		return t.File()
	}
	return nil, &ErrUnsupportedListener{el.Listener}
}

type conn struct {
	net.Conn
	listener *Listener
	closed   bool
}

func (c *conn) Close() error {
	return c.listener.closeConn(c)
}
