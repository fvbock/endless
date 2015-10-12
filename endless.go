package endless

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ErrNoHandler is the error returned if no Handler was configured on the Server.
var ErrNoHandler = errors.New("no handler")

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

	// StateTerminate is the state of server if it was forcibly terminated.
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

// Internal globals
var (
	runningServerReg     sync.RWMutex
	runningServers       map[string]*Server
	runningServersOrder  []string
	socketPtrOffsetMap   map[string]uint
	runningServersForked bool
	isChild              bool
	socketOrder          string
)

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

func init() {
	flag.BoolVar(&isChild, "endless-continue", false, "listen on open fd (after forking)")
	flag.StringVar(&socketOrder, "endless-socketorder", "", "previous initialization order - used when more than one listener was started")

	runningServers = make(map[string]*Server)
	socketPtrOffsetMap = make(map[string]uint)
}

// Handler is the interface that objects implement to perform operations on a endless Server
type Handler interface {
	Handle(srv *Server)
}

// DefaultHandler is the default handler used when creating a new Server
var DefaultHandler Handler

// Server represents a endless server.
type Server struct {
	http.Server
	state State
	Handler
	Listener         net.Listener
	tlsInnerListener *Listener
	wg               sync.WaitGroup
	BeforeBegin      func(add string)
	lock             sync.RWMutex
	TerminateTimeout time.Duration
	Done             chan struct{}
	Debug            bool
}

// NewServer returns an initialized Server Object. Calling Serve on it will
// actually "start" the server.
func NewServer(addr string, handler http.Handler) (srv *Server) {
	runningServerReg.Lock()
	defer runningServerReg.Unlock()
	if !flag.Parsed() {
		flag.Parse()
	}
	if len(socketOrder) > 0 {
		for i, addr := range strings.Split(socketOrder, ",") {
			socketPtrOffsetMap[addr] = uint(i)
		}
	} else {
		socketPtrOffsetMap[addr] = uint(len(runningServersOrder))
	}

	srv = &Server{
		Done: make(chan struct{}),
	}

	srv.Server.Addr = addr
	srv.Server.ReadTimeout = DefaultReadTimeout
	srv.Server.WriteTimeout = DefaultWriteTimeout
	srv.Server.MaxHeaderBytes = DefaultMaxHeaderBytes
	srv.Server.Handler = handler
	srv.Handler = DefaultHandler
	srv.TerminateTimeout = DefaultTerminateTimeout

	srv.BeforeBegin = func(addr string) {
		srv.Debugln(syscall.Getpid(), addr)
	}

	runningServersOrder = append(runningServersOrder, addr)
	runningServers[addr] = srv

	return
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

// handle calls the Handlers Handle method if not nil, otherwise it returns
// ErrNoHandler.
func (srv *Server) handle() error {
	if srv.Handler == nil {
		return ErrNoHandler
	}

	go srv.Handle(srv)

	return nil
}

// ListenAndServe listens on the TCP network address addr and then calls Serve
// with handler to handle requests on incoming connections. Handler is typically
// nil, in which case the DefaultServeMux is used.
func ListenAndServe(addr string, handler http.Handler) error {
	server := NewServer(addr, handler)
	return server.ListenAndServe()
}

// ListenAndServeTLS acts identically to ListenAndServe, except that it expects
// HTTPS connections. Additionally, files containing a certificate and matching
// private key for the server must be provided. If the certificate is signed by a
// certificate authority, the certFile should be the concatenation of the server's
// certificate followed by the CA's certificate.
func ListenAndServeTLS(addr string, certFile string, keyFile string, handler http.Handler) error {
	server := NewServer(addr, handler)
	return server.ListenAndServeTLS(certFile, keyFile)
}

// GetState returns the current state of the server.
func (srv *Server) GetState() State {
	srv.lock.RLock()
	defer srv.lock.RUnlock()

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
	srv.lock.Lock()
	defer srv.lock.Unlock()

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
			close(srv.Done)
		case StateFailed, StateTerminated:
			return nil
		default:
			return srv.invalidState(st)
		}
	case st == StateTerminated:
		if srv.state != StateShuttingDown {
			return srv.invalidState(st)
		}
		close(srv.Done)
	case st == StateFailed:
		switch srv.state {
		case StateTerminated, StateShutdown:
			return srv.invalidState(st)
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
// In addition to the stl Serve behaviour each connection is added to a
// sync.Waitgroup so that all outstanding connections can be served before shutting
// down the server.
func (srv *Server) Serve() error {
	if err := srv.setState(StateRunning); err != nil {
		return err
	}

	defer srv.Debugln(syscall.Getpid(), "Serve() returning...")

	err := srv.Server.Serve(srv.Listener)
	srv.Debugln(syscall.Getpid(), "Waiting for connections to finish...")
	srv.wg.Wait()
	if err != nil && srv.GetState() == StateRunning {
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
	addr := srv.Addr
	if addr == "" {
		addr = ":http"
	}

	if err := srv.handle(); err != nil {
		return err
	}

	l, err := srv.getListener(addr)
	if err != nil {
		return err
	}

	srv.Listener = NewListener(l, srv)

	if isChild {
		if err = kill(syscall.Getppid()); err != nil {
			return err
		}
	}

	srv.BeforeBegin(srv.Addr)

	return srv.Serve()
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
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
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
		return
	}

	if err = srv.handle(); err != nil {
		return
	}

	var l net.Listener
	l, err = srv.getListener(addr)
	if err != nil {
		return
	}

	srv.tlsInnerListener = NewListener(l, srv)
	srv.Listener = tls.NewListener(srv.tlsInnerListener, config)

	if isChild {
		if err = kill(syscall.Getppid()); err != nil {
			return err
		}
	}

	srv.BeforeBegin(srv.Addr)

	return srv.Serve()
}

// getListener either opens a new socket to listen on, or takes the acceptor socket
// it got passed when restarted.
func (srv *Server) getListener(laddr string) (l net.Listener, err error) {
	if isChild {
		ptrOffset := uint(0)
		runningServerReg.RLock()
		defer runningServerReg.RUnlock()
		if len(socketPtrOffsetMap) > 0 {
			ptrOffset = socketPtrOffsetMap[laddr]
		}

		f := os.NewFile(uintptr(3+ptrOffset), "")
		l, err = net.FileListener(f)
		if err != nil {
			err = fmt.Errorf("net.FileListener error: %v", err)
			return
		}
	} else {
		l, err = net.Listen("tcp", laddr)
		if err != nil {
			err = fmt.Errorf("net.Listen error: %v", err)
			return
		}
	}
	return
}

// Shutdown closes the Listener so that no new connections are accepted. it also
// starts a goroutine that will terminate (stop all running requests) the server
// after TerminateTimeout.
func (srv *Server) Shutdown() error {
	switch srv.GetState() {
	case StateShuttingDown, StateShutdown, StateTerminated, StateFailed:
		// No action needed
		return nil
	}

	if err := srv.setState(StateShuttingDown); err != nil {
		return err
	}

	if srv.TerminateTimeout >= 0 {
		go srv.Terminate(srv.TerminateTimeout)
	}

	return srv.Listener.Close()
}

// Terminate forces the server to shutdown in a given timeout - whether it
// finished outstanding requests or not. if Read/WriteTimeout are not set or the
// max header size is very big a connection could hang...
//
// srv.Serve() will not return until all connections are served. this will
// unblock the srv.wg.Wait() in Serve() thus causing ListenAndServe(TLS) to
// return.
func (srv *Server) Terminate(d time.Duration) error {
	if srv.GetState() != StateShuttingDown {
		return srv.invalidState(StateTerminated)
	}

	select {
	case <-time.After(d):
	case <-srv.Done:
		// Shutdown succeeded in grace period
		return nil
	}

	srv.Debugln("Terminating parent")
	srv.listener().Terminate()

	return srv.setState(StateTerminated)
}

func (srv *Server) listener() *Listener {
	if l, ok := srv.Listener.(*Listener); ok {
		// normal listener
		return l
	}

	// tls listener
	return srv.tlsInnerListener
}

// Restart restarts the servers with the new binary
func (srv *Server) Restart() error {
	runningServerReg.Lock()
	defer runningServerReg.Unlock()

	// Only one server instance should fork!
	if runningServersForked {
		return errors.New("already forked")
	}

	runningServersForked = true

	var files = make([]*os.File, len(runningServers))
	var orderArgs = make([]string, len(runningServers))
	// get the accessor socket fds for _all_ server instances
	for _, srvPtr := range runningServers {
		// TODO(steve): process error from File()
		files[socketPtrOffsetMap[srvPtr.Server.Addr]], _ = srvPtr.listener().File()
		orderArgs[socketPtrOffsetMap[srvPtr.Server.Addr]] = srvPtr.Server.Addr
	}

	path := os.Args[0]
	var args []string
	if len(os.Args) > 1 {
		for _, arg := range os.Args[1:] {
			if arg == "-endless-continue" {
				break
			}
			args = append(args, arg)
		}
	}
	args = append(args, "-endless-continue")
	if len(runningServers) > 1 {
		args = append(args, fmt.Sprintf(`-endless-socketorder=%s`, strings.Join(orderArgs, ",")))
	}

	cmd := exec.Command(path, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.ExtraFiles = files

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("restart: failed: %v", err)
	}

	return nil
}

type Listener struct {
	net.Listener
	server *Server
	conns  map[net.Conn]struct{}
}

func (el *Listener) DeleteConn(c net.Conn) {
	delete(el.conns, c)
}

func (el *Listener) Terminate() {
	for c := range el.conns {
		c.Close()
	}
}

func (el *Listener) Accept() (net.Conn, error) {
	c, err := el.Listener.Accept()
	if err != nil {
		return nil, err
	}

	wc := &conn{
		Conn:     c,
		listener: el,
	}
	el.conns[wc] = struct{}{}
	el.server.wg.Add(1)

	return wc, nil
}

func NewListener(l net.Listener, srv *Server) *Listener {
	return &Listener{
		Listener: l,
		server:   srv,
		conns:    make(map[net.Conn]struct{}),
	}
}

func (el *Listener) File() (*os.File, error) {
	// returns a dup(2) - FD_CLOEXEC flag *not* set
	return el.Listener.(*net.TCPListener).File()
}

type conn struct {
	sync.Mutex
	net.Conn
	listener *Listener
}

func (c *conn) Close() error {
	c.Lock()
	defer c.Unlock()

	if c.listener == nil {
		// Already closed
		return nil
	}

	err := c.Conn.Close()

	c.listener.DeleteConn(c)
	c.listener.server.wg.Done()
	c.listener = nil

	return err
}
