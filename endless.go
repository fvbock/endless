package endless

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	PRE_SIGNAL  = 0
	POST_SIGNAL = 1
)

var (
	runningServerReg sync.Mutex
	runningServers   map[int]*endlessServer

	isChild bool
)

func init() {
	flag.BoolVar(&isChild, "continue", false, "listen on open fd (after forking)")
	flag.Parse()

	runningServerReg = sync.Mutex{}
	runningServers = make(map[int]*endlessServer)
}

type endlessServer struct {
	http.Server
	Listener    *endlessListener
	wg          sync.WaitGroup
	sigChan     chan os.Signal
	isChild     bool
	SignalHooks map[int]map[os.Signal][]func()
}

func NewServer(addr string, handler http.Handler) (srv *endlessServer) {
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
	}

	srv.Server.Addr = addr
	srv.Server.ReadTimeout = 10 * time.Second
	srv.Server.WriteTimeout = 10 * time.Second
	// srv.Server.MaxHeaderBytes = 1 << 16
	srv.Server.Handler = handler

	runningServerReg.Lock()
	runningServers[len(runningServers)] = srv
	runningServerReg.Unlock()

	return
}

func ListenAndServe(addr string, handler http.Handler) error {
	server := NewServer(addr, handler)
	return server.ListenAndServe()
}

func (srv *endlessServer) ListenAndServe() (err error) {
	addr := srv.Addr
	if addr == "" {
		addr = ":http"
	}

	go srv.handleSignals()

	var l net.Listener
	if srv.isChild {
		// log.Println("IsChild.")
		var ptrOffset uint = 0
		// wonder whether starting servers in goroutines could create a
		// race which ends up assigning the wrong fd... maybe add Addr
		// to the registry of runningServers
		for i, srvPtr := range runningServers {
			if srv == srvPtr {
				ptrOffset = uint(i)
				break
			}
		}
		f := os.NewFile(uintptr(3+ptrOffset), "")
		l, err = net.FileListener(f)
		if err != nil {
			log.Println("net.FileListener error:", err)
			return
		}
	} else {
		// log.Println("NewServer.")
		l, err = net.Listen("tcp", srv.Server.Addr)
		if err != nil {
			log.Println("net.Listen error:", err)
			return
		}
	}
	srv.Listener = newEndlessListener(l, srv)

	if srv.isChild {
		syscall.Kill(syscall.Getppid(), syscall.SIGTERM)
	}

	log.Println("PID:", syscall.Getpid(), srv.Addr)
	return srv.Serve()
}

func (srv *endlessServer) Serve() (err error) {
	err = srv.Server.Serve(srv.Listener)
	log.Println(syscall.Getpid(), "Waiting for connections to finish...")
	srv.wg.Wait()
	return
}

// TODO: TLS...

// func ListenAndServeTLS(addr string, certFile string, keyFile string, handler http.Handler, isChild bool) error {
// 	server := NewServer(addr, handler, isChild)
// 	return server.ListenAndServeTLS(certFile, keyFile)
// }

// func (srv *Server) ListenAndServeTLS(certFile, keyFile string) error {
// 	addr := srv.Addr
// 	if addr == "" {
// 		addr = ":https"
// 	}
// 	config := &tls.Config{}
// 	if srv.TLSConfig != nil {
// 		*config = *srv.TLSConfig
// 	}
// 	if config.NextProtos == nil {
// 		config.NextProtos = []string{"http/1.1"}
// 	}

// 	var err error
// 	config.Certificates = make([]tls.Certificate, 1)
// 	config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
// 	if err != nil {
// 		return err
// 	}

// 	ln, err := net.Listen("tcp", addr)
// 	if err != nil {
// 		return err
// 	}

// 	tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config)
// 	return srv.Serve(tlsListener)
// }

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
			log.Println(pid, "Received SIGHUP. forking.")
			err := srv.fork()
			if err != nil {
				log.Println("Fork err:", err)
			}
		case syscall.SIGUSR1:
			log.Println(pid, "Received SIGUSR1.")
		case syscall.SIGUSR2:
			log.Println(pid, "Received SIGUSR2.")
		case syscall.SIGINT:
			log.Println(pid, "Received SIGINT.")
			srv.shutdown()
		case syscall.SIGTERM:
			log.Println(pid, "Received SIGTERM.")
			srv.shutdown()
		case syscall.SIGTSTP:
			log.Println(pid, "Received SIGTSTP.")
			srv.shutdown()
		default:
			log.Printf("Received %v: nothing i care about....\n", sig)
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

func (srv *endlessServer) shutdown() {
	err := srv.Listener.Close()
	if err != nil {
		log.Println(syscall.Getpid(), "srv.Listener.Close() error:", err)
	} else {
		log.Println(syscall.Getpid(), "srv.Listener closed.")
	}
}

func (srv *endlessServer) fork() (err error) {
	// only one server isntance should fork!
	if runningServers[0] != srv {
		return
	}

	var files []*os.File
	// get the accessor socket fds for _all_ server instances
	for _, srvPtr := range runningServers {
		files = append(files, srvPtr.Listener.File()) // returns a dup(2) - FD_CLOEXEC flag *not* set
	}

	path := os.Args[0]
	args := []string{"-continue"}

	cmd := exec.Command(path, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = files

	err = cmd.Start()
	if err != nil {
		log.Fatalf("Restart: Failed to launch, error: %v", err)
	}

	return
}

type endlessListener struct {
	net.Listener
	stop    chan error
	stopped bool
	server  *endlessServer
}

func (el *endlessListener) Accept() (c net.Conn, err error) {
	// c, err = el.Listener.Accept()
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
		stop:     make(chan error),
		server:   srv,
	}

	go func() {
		_ = <-el.stop
		el.stopped = true
		el.stop <- el.Listener.Close()
	}()
	return
}

func (el *endlessListener) Close() error {
	if el.stopped {
		return syscall.EINVAL
	}
	el.stop <- nil
	return <-el.stop
}

func (el *endlessListener) File() *os.File {
	tl := el.Listener.(*net.TCPListener)
	fl, _ := tl.File()
	return fl
}

type endlessConn struct {
	net.Conn
	server *endlessServer
}

func (w endlessConn) Close() error {
	w.server.wg.Done()
	return w.Conn.Close()
}
