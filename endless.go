package endless

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	// "github.com/fvbock/uds-go/introspect"
	"github.com/rguliyev/smtpd"
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
	runningServerReg     sync.RWMutex
	runningServers       map[string]*endlessServer
	runningServersOrder  []string
	SMTPDrunningServers       map[string]*endlessSMTPDServer
	SMTPDrunningServersOrder  []string
	socketPtrOffsetMap   map[string]uint
	runningServersForked bool

	DefaultReadTimeOut    time.Duration
	DefaultWriteTimeOut   time.Duration
	DefaultMaxHeaderBytes int
	DefaultHammerTime     time.Duration

	isChild     bool
	socketOrder string

	hookableSignals []os.Signal
)

func init() {
	runningServerReg = sync.RWMutex{}
	runningServers = make(map[string]*endlessServer)
	runningServersOrder = []string{}
	SMTPDrunningServers = make(map[string]*endlessSMTPDServer)
	SMTPDrunningServersOrder = []string{}
	socketPtrOffsetMap = make(map[string]uint)

	DefaultMaxHeaderBytes = 0 // use http.DefaultMaxHeaderBytes - which currently is 1 << 20 (1MB)

	// after a restart the parent will finish ongoing requests before
	// shutting down. set to a negative value to disable
	DefaultHammerTime = 60 * time.Second

	hookableSignals = []os.Signal{
		syscall.SIGHUP,
		syscall.SIGUSR1,
		syscall.SIGUSR2,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGTSTP,
	}
}

type endlessServer struct {
	http.Server
	EndlessListener  net.Listener
	SignalHooks      map[int]map[os.Signal][]func()
	tlsInnerListener *endlessListener
	wg               sync.WaitGroup
	sigChan          chan os.Signal
	isChild          bool
	state            uint8
	lock             *sync.RWMutex
	BeforeBegin      func(add string)
}

type endlessSMTPDServer struct {
	smtpd.Server
	EndlessListener  net.Listener
	SignalHooks      map[int]map[os.Signal][]func()
	tlsInnerListener *SMTPDendlessListener
	wg               sync.WaitGroup
	sigChan          chan os.Signal
	isChild          bool
	state            uint8
	lock             *sync.RWMutex
	BeforeBegin      func(add string)
}

/*
NewServer returns an intialized endlessServer Object. Calling Serve on it will
actually "start" the server.
*/
func NewServer(addr string, handler http.Handler) (srv *endlessServer) {
	runningServerReg.Lock()
	defer runningServerReg.Unlock()

	socketOrder = os.Getenv("ENDLESS_SOCKET_ORDER")
	isChild = os.Getenv("ENDLESS_CONTINUE") != ""

	if len(socketOrder) > 0 {
		for i, addr := range strings.Split(socketOrder, ",") {
			socketPtrOffsetMap[addr] = uint(i)
		}
	} else {
		socketPtrOffsetMap[addr] = uint(len(runningServersOrder) + len(SMTPDrunningServersOrder))
	}

	srv = &endlessServer{
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
		lock:  &sync.RWMutex{},
	}

	srv.Server.Addr = addr
	srv.Server.ReadTimeout = DefaultReadTimeOut
	srv.Server.WriteTimeout = DefaultWriteTimeOut
	srv.Server.MaxHeaderBytes = DefaultMaxHeaderBytes
	srv.Server.Handler = handler

	srv.BeforeBegin = func(addr string) {
		log.Println(syscall.Getpid(), addr)
	}

	runningServersOrder = append(runningServersOrder, addr)
	runningServers[addr] = srv

	return
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

func (srv *endlessServer) getState() uint8 {
	srv.lock.RLock()
	defer srv.lock.RUnlock()

	return srv.state
}

func (srv *endlessServer) setState(st uint8) {
	srv.lock.Lock()
	defer srv.lock.Unlock()

	srv.state = st
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
	defer log.Println(syscall.Getpid(), "Serve() returning...")
	srv.setState(STATE_RUNNING)
	err = srv.Server.Serve(srv.EndlessListener)
	log.Println(syscall.Getpid(), "Waiting for connections to finish...")
	srv.wg.Wait()
	srv.setState(STATE_TERMINATE)
	return
}

/*
ListenAndServe listens on the TCP network address srv.Addr and then calls Serve
to handle requests on incoming connections. If srv.Addr is blank, ":http" is
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

	srv.BeforeBegin(srv.Addr)

	return srv.Serve()
}

/*
ListenAndServeTLS listens on the TCP network address srv.Addr and then calls
Serve to handle requests on incoming TLS connections.

Filenames containing a certificate and matching private key for the server must
be provided. If the certificate is signed by a certificate authority, the
certFile should be the concatenation of the server's certificate followed by the
CA's certificate.

If srv.Addr is blank, ":https" is used.
*/
func (srv *endlessServer) ListenAndServeTLS(certFile, keyFile string) (err error) {
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

	log.Println(syscall.Getpid(), srv.Addr)
	return srv.Serve()
}

/*
getListener either opens a new socket to listen on, or takes the acceptor socket
it got passed when restarted.
*/
func (srv *endlessServer) getListener(laddr string) (l net.Listener, err error) {
	if srv.isChild {
		var ptrOffset uint = 0
		runningServerReg.RLock()
		defer runningServerReg.RUnlock()
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
SMTPDNewServer returns an intialized endlessSMTPDServer Object. Calling Serve on it will
actually "start" the server.
*/
func SMTPDNewServer(addr string, handler smtpd.Handler, appname string, hostname string) (srv *endlessSMTPDServer) {
	runningServerReg.Lock()
	defer runningServerReg.Unlock()

	socketOrder = os.Getenv("ENDLESS_SOCKET_ORDER")
	isChild = os.Getenv("ENDLESS_CONTINUE") != ""

	if len(socketOrder) > 0 {
		for i, addr := range strings.Split(socketOrder, ",") {
			socketPtrOffsetMap[addr] = uint(i)
		}
	} else {
		socketPtrOffsetMap[addr] = uint(len(runningServersOrder) + len(SMTPDrunningServersOrder))
	}

	srv = &endlessSMTPDServer{
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
		lock:  &sync.RWMutex{},
	}

	srv.Server.Addr = addr
	srv.Server.Handler = handler
	srv.Server.Appname = appname
	srv.Server.Hostname = hostname

	srv.BeforeBegin = func(addr string) {
		log.Println(syscall.Getpid(), addr)
	}

	if SMTPDrunningServers == nil {
		SMTPDrunningServers = make(map[string]*endlessSMTPDServer)
		SMTPDrunningServersOrder = []string{}
	}
	SMTPDrunningServersOrder = append(SMTPDrunningServersOrder, addr)
	SMTPDrunningServers[addr] = srv

	return
}

/*
ListenAndServe listens on the TCP network address addr and then calls Serve
with handler to handle requests on incoming connections. Handler is typically
nil, in which case the DefaultServeMux is used.
*/
func SMTPDListenAndServe(addr string, handler smtpd.Handler, appname string, hostname string) error {
	server := SMTPDNewServer(addr, handler, appname, hostname)
	return server.SMTPDListenAndServe()
}

/*
ListenAndServeTLS acts identically to ListenAndServe, except that it expects
HTTPS connections. Additionally, files containing a certificate and matching
private key for the server must be provided. If the certificate is signed by a
certificate authority, the certFile should be the concatenation of the server's
certificate followed by the CA's certificate.
*/
func SMTPDListenAndServeTLS(addr string, certFile string, keyFile string, handler smtpd.Handler, appname string, hostname string) error {
	server := SMTPDNewServer(addr, handler, appname, hostname)
	return server.SMTPDListenAndServeTLS(addr, certFile, keyFile, handler, appname, hostname)
}

func (srv *endlessSMTPDServer) SMTPDgetState() uint8 {
	srv.lock.RLock()
	defer srv.lock.RUnlock()

	return srv.state
}

func (srv *endlessSMTPDServer) SMTPDsetState(st uint8) {
	srv.lock.Lock()
	defer srv.lock.Unlock()

	srv.state = st
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
func (srv *endlessSMTPDServer) SMTPDServe() (err error) {
	defer log.Println(syscall.Getpid(), "Serve() returning...")
	srv.SMTPDsetState(STATE_RUNNING)
	err = srv.Server.Serve(srv.EndlessListener)
	log.Println(syscall.Getpid(), "Waiting for connections to finish...")
	srv.wg.Wait()
	srv.SMTPDsetState(STATE_TERMINATE)
	return
}

/*
ListenAndServe listens on the TCP network address srv.Addr and then calls Serve
to handle requests on incoming connections. If srv.Addr is blank, ":http" is
used.
*/
func (srv *endlessSMTPDServer) SMTPDListenAndServe() (err error) {
	addr := srv.Addr
	if srv.Addr == "" {
		srv.Addr = ":25"
	}
	if srv.Appname == "" {
		srv.Appname = "smtpd"
	}
	if srv.Hostname == "" {
		srv.Hostname, _ = os.Hostname()
	}
	if srv.Timeout == 0 {
		srv.Timeout = 5 * time.Minute
	}

	// go srv.handleSignals()

	l, err := srv.SMTPDgetListener(addr)
	if err != nil {
		log.Println(err)
		return
	}

	srv.EndlessListener = SMTPDnewEndlessListener(l, srv)

	if srv.isChild {
		syscall.Kill(syscall.Getppid(), syscall.SIGTERM)
	}

	srv.BeforeBegin(srv.Addr)

	return srv.Serve(l)

}

/*
ListenAndServeTLS listens on the TCP network address srv.Addr and then calls
Serve to handle requests on incoming TLS connections.

Filenames containing a certificate and matching private key for the server must
be provided. If the certificate is signed by a certificate authority, the
certFile should be the concatenation of the server's certificate followed by the
CA's certificate.

If srv.Addr is blank, ":https" is used.
*/
func (srv *endlessSMTPDServer) SMTPDListenAndServeTLS(addr, certFile, keyFile string, handler smtpd.Handler, appname string, hostname string) (err error) {
	if srv.Addr == "" {
		srv.Addr = ":25"
	}
	if srv.Appname == "" {
		srv.Appname = "smtpd"
	}
	if srv.Hostname == "" {
		srv.Hostname, _ = os.Hostname()
	}
	if srv.Timeout == 0 {
		srv.Timeout = 5 * time.Minute
	}

	err = srv.ConfigureTLS(certFile, keyFile)
	if err != nil {
		return err
	}
	config := srv.TLSConfig

	l, err := srv.SMTPDgetListener(addr)
	if err != nil {
		log.Println(err)
		return
	}

	srv.tlsInnerListener = SMTPDnewEndlessListener(l, srv)
	srv.EndlessListener = tls.NewListener(srv.tlsInnerListener, config)

	if srv.isChild {
		syscall.Kill(syscall.Getppid(), syscall.SIGTERM)
	}

	log.Println(syscall.Getpid(), srv.Addr)
	return srv.Serve(l)
}

/*
getListener either opens a new socket to listen on, or takes the acceptor socket
it got passed when restarted.
*/
func (srv *endlessSMTPDServer) SMTPDgetListener(laddr string) (l net.Listener, err error) {
	if srv.isChild {
		var ptrOffset uint = 0
		runningServerReg.RLock()
		defer runningServerReg.RUnlock()
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
		hookableSignals...,
	)

	pid := syscall.Getpid()
	for {
		sig = <-srv.sigChan
		srv.signalHooks(PRE_SIGNAL, sig)
		switch sig {
		case syscall.SIGHUP:
			log.Println(pid, "Received SIGHUP. forking.")
			err := srv.fork()
			if err != nil {
				log.Println("Fork err:", err)
			}
		case syscall.SIGUSR1:
			log.Println(pid, "Received SIGUSR1.")
		case syscall.SIGUSR2:
			log.Println(pid, "Received SIGUSR2.")
			srv.hammerTime(0 * time.Second)
		case syscall.SIGINT:
			log.Println(pid, "Received SIGINT.")
			srv.shutdown()
		case syscall.SIGTERM:
			log.Println(pid, "Received SIGTERM.")
			srv.shutdown()
		case syscall.SIGTSTP:
			log.Println(pid, "Received SIGTSTP.")
		default:
			log.Printf("Received %v: nothing i care about...\n", sig)
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
	if srv.getState() != STATE_RUNNING {
		return
	}

	srv.setState(STATE_SHUTTING_DOWN)
	if DefaultHammerTime >= 0 {
		go srv.hammerTime(DefaultHammerTime)
	}
	// disable keep-alives on existing connections
	// srv.SetKeepAlivesEnabled(false)
	err := srv.EndlessListener.Close()
	if err != nil {
		log.Println(syscall.Getpid(), "Listener.Close() error:", err)
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
	if srv.getState() != STATE_SHUTTING_DOWN {
		return
	}
	time.Sleep(d)
	log.Println("[STOP - Hammer Time] Forcefully shutting down parent")
	for {
		if srv.getState() == STATE_TERMINATE {
			break
		}
		srv.wg.Done()
		runtime.Gosched()
	}
}

func (srv *endlessServer) fork() (err error) {
	runningServerReg.Lock()
	defer runningServerReg.Unlock()

	// only one server instance should fork!
	if runningServersForked {
		return errors.New("Another process already forked. Ignoring this one.")
	}

	runningServersForked = true

	var files = make([]*os.File, len(runningServers) + len(SMTPDrunningServers))
	var orderArgs = make([]string, len(runningServers) + len(SMTPDrunningServers))
	// get the accessor socket fds for _all_ server instances
	for _, srvPtr := range runningServers {
		// introspect.PrintTypeDump(srvPtr.EndlessListener)
		switch srvPtr.EndlessListener.(type) {
		case *endlessListener:
			// normal listener
			files[socketPtrOffsetMap[srvPtr.Server.Addr]], err = srvPtr.EndlessListener.(*endlessListener).File()
		default:
			// tls listener
			files[socketPtrOffsetMap[srvPtr.Server.Addr]], err = srvPtr.tlsInnerListener.File()
		}
		orderArgs[socketPtrOffsetMap[srvPtr.Server.Addr]] = srvPtr.Server.Addr
	}

	for _, srvPtr := range SMTPDrunningServers {
		// introspect.PrintTypeDump(srvPtr.EndlessListener)
		switch srvPtr.EndlessListener.(type) {
		case *SMTPDendlessListener:
			// normal listener
			files[socketPtrOffsetMap[srvPtr.Server.Addr]], err = srvPtr.EndlessListener.(*SMTPDendlessListener).File()
		default:
			// tls listener
			files[socketPtrOffsetMap[srvPtr.Server.Addr]], err = srvPtr.tlsInnerListener.File()
		}
		orderArgs[socketPtrOffsetMap[srvPtr.Server.Addr]] = srvPtr.Server.Addr
	}

	env := append(
		os.Environ(),
		"ENDLESS_CONTINUE=1",
	)
	if len(runningServers) + len(SMTPDrunningServers) > 1 {
		env = append(env, fmt.Sprintf(`ENDLESS_SOCKET_ORDER=%s`, strings.Join(orderArgs, ",")))
	}

	// log.Println(files)
	path := os.Args[0]
	var args []string
	if len(os.Args) > 1 {
		args = os.Args[1:]
	}

	cmd := exec.Command(path, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = files
	cmd.Env = env

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

func (el *endlessListener) File() (*os.File, error) {
	// returns a dup(2) - FD_CLOEXEC flag *not* set
	tl := el.Listener.(*net.TCPListener)
	fl, err := tl.File()
	return fl, err
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

type SMTPDendlessListener struct {
	net.Listener
	stopped bool
	server  *endlessSMTPDServer
}

func (el *SMTPDendlessListener) Accept() (c net.Conn, err error) {
	tc, err := el.Listener.(*net.TCPListener).AcceptTCP()
	if err != nil {
		return
	}

	tc.SetKeepAlive(true)                  // see http.tcpKeepAliveListener
	tc.SetKeepAlivePeriod(3 * time.Minute) // see http.tcpKeepAliveListener

	c = SMTPDendlessConn{
		Conn:   tc,
		server: el.server,
	}

	el.server.wg.Add(1)
	return
}

func SMTPDnewEndlessListener(l net.Listener, srv *endlessSMTPDServer) (el *SMTPDendlessListener) {
	el = &SMTPDendlessListener{
		Listener: l,
		server:   srv,
	}

	return
}

func (el *SMTPDendlessListener) Close() error {
	if el.stopped {
		return syscall.EINVAL
	}

	el.stopped = true
	return el.Listener.Close()
}

func (el *SMTPDendlessListener) File() (*os.File, error) {
	// returns a dup(2) - FD_CLOEXEC flag *not* set
	tl := el.Listener.(*net.TCPListener)
	fl, err := tl.File()
	return fl, err
}

type SMTPDendlessConn struct {
	net.Conn
	server *endlessSMTPDServer
}

func (w SMTPDendlessConn) Close() error {
	err := w.Conn.Close()
	if err == nil {
		w.server.wg.Done()
	}
	return err
}

/*
RegisterSignalHook registers a function to be run PRE_SIGNAL or POST_SIGNAL for
a given signal. PRE or POST in this case means before or after the signal
related code endless itself runs
*/
func (srv *endlessServer) RegisterSignalHook(prePost int, sig os.Signal, f func()) (err error) {
	if prePost != PRE_SIGNAL && prePost != POST_SIGNAL {
		err = fmt.Errorf("Cannot use %v for prePost arg. Must be endless.PRE_SIGNAL or endless.POST_SIGNAL.", sig)
		return
	}
	for _, s := range hookableSignals {
		if s == sig {
			srv.SignalHooks[prePost][sig] = append(srv.SignalHooks[prePost][sig], f)
			return
		}
	}
	err = fmt.Errorf("Signal %v is not supported.", sig)
	return
}
