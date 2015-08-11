package endless

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	// "github.com/fvbock/uds-go/introspect"
)

const (
	PRE_SIGNAL = iota
	POST_SIGNAL

	STATE_INIT
	STATE_RUNNING
	STATE_SHUTTING_DOWN
	STATE_TERMINATE
)

var (
	runningServerReg     sync.Mutex
	runningServers       map[string]*endlessServer
	runningServersOrder  []string
	socketPtrOffsetMap   map[string]uint
	runningServersForked bool

	DefaultReadTimeOut    time.Duration
	DefaultWriteTimeOut   time.Duration
	DefaultMaxHeaderBytes int
	DefaultHammerTime     time.Duration

	isChild     bool
	socketOrder string
)

func init() {
	flag.BoolVar(&isChild, "continue", false, "listen on open fd (after forking)")
	flag.StringVar(&socketOrder, "socketorder", "", "previous initialization order - used when more than one listener was started")

	runningServerReg = sync.Mutex{}
	runningServers = make(map[string]*endlessServer)
	runningServersOrder = []string{}
	socketPtrOffsetMap = make(map[string]uint)

	DefaultMaxHeaderBytes = 0 // use http.DefaultMaxHeaderBytes - which currently is 1 << 20 (1MB)

	// after a restart the parent will finish ongoing requests before
	// shutting down. set to a negative value to disable
	DefaultHammerTime = 60 * time.Second
}

type Server interface {
	Serve(l net.Listener) error
}

type CloseFunc func() error

func (fn CloseFunc) Close() error { return fn() }

type endlessServer struct {
	Server
	io.Closer
	Addr             string
	EndlessListener  net.Listener
	SignalHooks      map[int]map[os.Signal][]func()
	tlsInnerListener *endlessListener
	wg               sync.WaitGroup
	sigChan          chan os.Signal
	isChild          bool
	state            uint8
}

func newEndlessServer(addr string, server Server, closer io.Closer) (srv *endlessServer) {
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

	srv = &endlessServer{
		Server:  server,
		Closer:  closer,
		Addr:    addr,
		wg:      sync.WaitGroup{},
		sigChan: make(chan os.Signal),
		isChild: isChild,
		SignalHooks: map[int]map[os.Signal][]func(){
			PRE_SIGNAL: map[os.Signal][]func(){
				syscall.SIGHUP:  []func(){},
				syscall.SIGUSR1: []func(){},
				syscall.SIGUSR2: []func(){},
				syscall.SIGINT:  []func(){},
				syscall.SIGTERM: []func(){},
				syscall.SIGTSTP: []func(){},
			},
			POST_SIGNAL: map[os.Signal][]func(){
				syscall.SIGHUP:  []func(){},
				syscall.SIGUSR1: []func(){},
				syscall.SIGUSR2: []func(){},
				syscall.SIGINT:  []func(){},
				syscall.SIGTERM: []func(){},
				syscall.SIGTSTP: []func(){},
			},
		},
		state: STATE_INIT,
	}

	runningServersOrder = append(runningServersOrder, addr)
	runningServers[addr] = srv

	return
}

/*
NewServer returns an intialized endlessServer Object. Calling Serve on it will
actually "start" the server.
*/
func NewServer(addr string, handler http.Handler) *endlessServer {
	srv := &http.Server{
		Addr:           addr,
		ReadTimeout:    DefaultReadTimeOut,
		WriteTimeout:   DefaultWriteTimeOut,
		MaxHeaderBytes: DefaultMaxHeaderBytes,
		Handler:        handler,
	}

	return newEndlessServer(addr, srv, CloseFunc(func() error {
		// disable keep-alives on existing connections
		srv.SetKeepAlivesEnabled(false)

		return nil
	}))
}

/*
ListenAndServe listens on the TCP network address addr and then calls Serve
with handler to handle requests on incoming connections. Handler is typically
nil, in which case the DefaultServeMux is used.
*/
func ListenAndServe(addr string, handler http.Handler) error {
	server := NewServer(addr, handler)
	return server.ListenAndServe()
}

/*
ListenAndServeTLS acts identically to ListenAndServe, except that it expects
HTTPS connections. Additionally, files containing a certificate and matching
private key for the server must be provided. If the certificate is signed by a
certificate authority, the certFile should be the concatenation of the server's
certificate followed by the CA's certificate.
*/
func ListenAndServeTLS(addr string, certFile string, keyFile string, handler http.Handler) error {
	server := NewServer(addr, handler)
	return server.ListenAndServeTLS(certFile, keyFile)
}

type Handler interface {
	Serve(net.Conn)
}

type HandleFunc func(net.Conn)

func (fn HandleFunc) Serve(conn net.Conn) { fn(conn) }

func ListenAndServeTCP(addr string, handler Handler) error {
	server := NewTcpServer(addr, handler)
	return server.ListenAndServe()
}

type tcpServer struct {
	handler Handler
}

func NewTcpServer(addr string, handler Handler) *endlessServer {
	return newEndlessServer(addr, &tcpServer{handler}, CloseFunc(func() error { return nil }))
}

func (srv *tcpServer) Serve(l net.Listener) error {
	defer l.Close()
	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		rw, e := l.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("%d %s tcp: Accept error: %v; retrying in %v", os.Getpid(), l.(*endlessListener).Addr(), e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		tempDelay = 0

		go srv.handler.Serve(rw)
	}
}

type tlsServer struct {
	tcpServer

	TLSConfig *tls.Config
}

func NewTlsServer(addr string, handler Handler, config *tls.Config) *endlessServer {
	return newEndlessServer(addr, &tlsServer{tcpServer{handler}, config}, CloseFunc(func() error { return nil }))
}

func (srv *tlsServer) Serve(l net.Listener) error {
	return srv.tcpServer.Serve(tls.NewListener(l, srv.TLSConfig))
}

func (srv *endlessServer) TLSConfig() *tls.Config {
	switch t := srv.Server.(type) {
	case *http.Server:
		return t.TLSConfig
	case *tlsServer:
		return t.TLSConfig
	}

	return nil
}

/*
Serve accepts incoming HTTP connections on the listener l, creating a new
service goroutine for each. The service goroutines read requests and then call
handler to reply to them. Handler is typically nil, in which case the
DefaultServeMux is used.

In addition to the stl Serve behaviour each connection is added to a
sync.Waitgroup so that all outstanding connections can be served before shutting
down the server.
*/
func (srv *endlessServer) Serve() (err error) {
	defer log.Println(syscall.Getpid(), srv.EndlessListener.Addr(), "Serve() returning...")
	srv.state = STATE_RUNNING
	err = srv.Server.Serve(srv.EndlessListener)
	log.Println(syscall.Getpid(), srv.EndlessListener.Addr(), "Waiting for connections to finish...")
	srv.wg.Wait()
	srv.state = STATE_TERMINATE
	return
}

/*
ListenAndServe listens on the TCP network address srv.EndlessListener.Addr() and then calls Serve
to handle requests on incoming connections. If srv.EndlessListener.Addr() is blank, ":http" is
used.
*/
func (srv *endlessServer) ListenAndServe() (err error) {
	addr := srv.Addr
	if addr == "" {
		addr = ":http"
	}

	go srv.handleSignals()

	l, err := srv.getListener(addr)
	if err != nil {
		log.Println(err)
		return
	}

	srv.EndlessListener = newEndlessListener(l, srv)

	if srv.isChild {
		syscall.Kill(syscall.Getppid(), syscall.SIGTERM)
	}

	log.Println(syscall.Getpid(), srv.EndlessListener.Addr(), "ListenAndServe")
	return srv.Serve()
}

/*
ListenAndServeTLS listens on the TCP network address srv.EndlessListener.Addr() and then calls
Serve to handle requests on incoming TLS connections.

Filenames containing a certificate and matching private key for the server must
be provided. If the certificate is signed by a certificate authority, the
certFile should be the concatenation of the server's certificate followed by the
CA's certificate.

If srv.EndlessListener.Addr() is blank, ":https" is used.
*/
func (srv *endlessServer) ListenAndServeTLS(certFile, keyFile string) (err error) {
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
	}

	config := &tls.Config{}

	if srv.TLSConfig() != nil {
		*config = *srv.TLSConfig()
	}

	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}

	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return
	}

	go srv.handleSignals()

	l, err := srv.getListener(addr)
	if err != nil {
		log.Println(err)
		return
	}

	srv.tlsInnerListener = newEndlessListener(l, srv)
	srv.EndlessListener = tls.NewListener(srv.tlsInnerListener, config)

	if srv.isChild {
		syscall.Kill(syscall.Getppid(), syscall.SIGTERM)
	}

	log.Println(syscall.Getpid(), srv.EndlessListener.Addr(), "ListenAndServeTLS")
	return srv.Serve()
}

/*
getListener either opens a new socket to listen on, or takes the acceptor socket
it got passed when restarted.
*/
func (srv *endlessServer) getListener(laddr string) (l net.Listener, err error) {
	if srv.isChild {
		var ptrOffset uint = 0
		if len(socketPtrOffsetMap) > 0 {
			ptrOffset = socketPtrOffsetMap[laddr]
			// log.Println("laddr", laddr, "ptr offset", socketPtrOffsetMap[laddr])
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

/*
handleSignals listens for os Signals and calls any hooked in function that the
user had registered with the signal.
*/
func (srv *endlessServer) handleSignals() {
	var sig os.Signal

	signal.Notify(
		srv.sigChan,
		syscall.SIGHUP,
		syscall.SIGUSR1,
		syscall.SIGUSR2,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGTSTP,
	)

	pid := syscall.Getpid()
	for {
		sig = <-srv.sigChan
		srv.signalHooks(PRE_SIGNAL, sig)
		switch sig {
		case syscall.SIGHUP:
			log.Println(pid, srv.EndlessListener.Addr(), "Received SIGHUP. forking.")
			err := srv.fork()
			if err != nil {
				log.Println("Fork err:", err)
			}
		case syscall.SIGUSR1:
			log.Println(pid, srv.EndlessListener.Addr(), "Received SIGUSR1.")
		case syscall.SIGUSR2:
			log.Println(pid, srv.EndlessListener.Addr(), "Received SIGUSR2.")
			srv.hammerTime(0 * time.Second)
		case syscall.SIGINT:
			log.Println(pid, srv.EndlessListener.Addr(), "Received SIGINT.")
			srv.shutdown()
		case syscall.SIGTERM:
			log.Println(pid, srv.EndlessListener.Addr(), "Received SIGTERM.")
			srv.shutdown()
		case syscall.SIGTSTP:
			log.Println(pid, srv.EndlessListener.Addr(), "Received SIGTSTP.")
		default:
			log.Printf("%d %s Received %v: nothing i care about...\n", pid, srv.EndlessListener.Addr(), sig)
		}
		srv.signalHooks(POST_SIGNAL, sig)
	}
}

func (srv *endlessServer) signalHooks(ppFlag int, sig os.Signal) {
	if _, notSet := srv.SignalHooks[ppFlag][sig]; !notSet {
		return
	}
	for _, f := range srv.SignalHooks[ppFlag][sig] {
		f()
	}
	return
}

/*
shutdown closes the listener so that no new connections are accepted. it also
starts a goroutine that will hammer (stop all running requests) the server
after DefaultHammerTime.
*/
func (srv *endlessServer) shutdown() {
	if srv.state != STATE_RUNNING {
		return
	}

	srv.state = STATE_SHUTTING_DOWN
	if DefaultHammerTime >= 0 {
		go srv.hammerTime(DefaultHammerTime)
	}

	srv.Close()

	err := srv.EndlessListener.Close()
	if err != nil {
		log.Println(syscall.Getpid(), srv.EndlessListener.Addr(), "Listener.Close() error:", err)
	} else {
		log.Println(syscall.Getpid(), srv.EndlessListener.Addr(), "Listener closed.")
	}
}

/*
hammerTime forces the server to shutdown in a given timeout - whether it
finished outstanding requests or not. if Read/WriteTimeout are not set or the
max header size is very big a connection could hang...

srv.Serve() will not return until all connections are served. this will
unblock the srv.wg.Wait() in Serve() thus causing ListenAndServe(TLS) to
return.
*/
func (srv *endlessServer) hammerTime(d time.Duration) {
	defer func() {
		// we are calling srv.wg.Done() until it panics which means we called
		// Done() when the counter was already at 0 and we're done.
		// (and thus Serve() will return and the parent will exit)
		if r := recover(); r != nil {
			log.Println("WaitGroup at 0", r)
		}
	}()
	if srv.state != STATE_SHUTTING_DOWN {
		return
	}
	time.Sleep(d)
	log.Println("[STOP - Hammer Time] Forcefully shutting down parent")
	for {
		if srv.state == STATE_TERMINATE {
			break
		}
		srv.wg.Done()
	}
}

func (srv *endlessServer) fork() (err error) {
	// only one server isntance should fork!
	runningServerReg.Lock()
	defer runningServerReg.Unlock()
	if runningServersForked {
		return
	}
	runningServersForked = true

	var files = make([]*os.File, len(runningServers))
	var orderArgs = make([]string, len(runningServers))
	// get the accessor socket fds for _all_ server instances
	for _, srvPtr := range runningServers {
		// introspect.PrintTypeDump(srvPtr.EndlessListener)
		switch srvPtr.EndlessListener.(type) {
		case *endlessListener:
			// normal listener
			files[socketPtrOffsetMap[srvPtr.Addr]] = srvPtr.EndlessListener.(*endlessListener).File()
		default:
			// tls listener
			files[socketPtrOffsetMap[srvPtr.Addr]] = srvPtr.tlsInnerListener.File()
		}
		orderArgs[socketPtrOffsetMap[srvPtr.Addr]] = srvPtr.Addr
	}

	// log.Println(files)
	path := os.Args[0]
	var args []string
	if len(os.Args) > 1 {
		for _, arg := range os.Args[1:] {
			if arg == "-continue" {
				break
			}
			args = append(args, arg)
		}
	}
	args = append(args, "-continue")
	if len(runningServers) > 1 {
		args = append(args, fmt.Sprintf(`-socketorder=%s`, strings.Join(orderArgs, ",")))
		// log.Println(args)
	}

	cmd := exec.Command(path, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = files
	// cmd.SysProcAttr = &syscall.SysProcAttr{
	// 	Setsid:  true,
	// 	Setctty: true,
	// 	Ctty:    ,
	// }

	err = cmd.Start()
	if err != nil {
		log.Fatalf("Restart: Failed to launch, error: %v", err)
	}

	return
}

type endlessListener struct {
	net.Listener
	stopped bool
	server  *endlessServer
}

func (el *endlessListener) Accept() (c net.Conn, err error) {
	tc, err := el.Listener.(*net.TCPListener).AcceptTCP()
	if err != nil {
		return
	}

	tc.SetKeepAlive(true)                  // see http.tcpKeepAliveListener
	tc.SetKeepAlivePeriod(3 * time.Minute) // see http.tcpKeepAliveListener

	c = endlessConn{
		Conn:   tc,
		server: el.server,
	}

	el.server.wg.Add(1)
	return
}

func newEndlessListener(l net.Listener, srv *endlessServer) (el *endlessListener) {
	el = &endlessListener{
		Listener: l,
		server:   srv,
	}

	return
}

func (el *endlessListener) Close() error {
	if el.stopped {
		return syscall.EINVAL
	}

	el.stopped = true
	return el.Listener.Close()
}

func (el *endlessListener) File() *os.File {
	// returns a dup(2) - FD_CLOEXEC flag *not* set
	tl := el.Listener.(*net.TCPListener)
	fl, _ := tl.File()
	return fl
}

type endlessConn struct {
	net.Conn
	server *endlessServer
}

func (w endlessConn) Close() error {
    err := w.Conn.Close()
    if err == nil {
        w.server.wg.Done()
    }
    return err
}
