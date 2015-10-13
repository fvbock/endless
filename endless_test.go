package endless

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockHandler struct {
	mock.Mock
	req *TestReq
}

func NewMockHandler() *MockHandler {
	return &MockHandler{}
}

func (h *MockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var tr *TestReq
	if h.req != nil {
		tr = h.req
	} else {
		args := h.Called(r.URL.Path)
		tr = args.Get(0).(*TestReq)
	}

	v := tr.URL.Query()
	sleep := v.Get("sleep")
	if sleep != "" {
		d, err := time.ParseDuration(sleep)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, err)
			return
		}
		time.Sleep(d)
	}
	w.WriteHeader(tr.StatusCode)
	fmt.Fprint(w, tr.Body)
}

type TestServer struct {
	*Server
	errs     []error
	servErr  error
	certFile string
	keyFile  string
}

const TestAddr = ":4242"
const TestNet = "tcp"

func NewTestServer(h http.Handler) *TestServer {
	return &TestServer{
		Server: NewServer(TestNet, TestAddr, h),
		errs:   make([]error, 0, 10),
	}
}

func (s TestServer) ListenAndServe() error {
	s.servErr = s.Server.ListenAndServe()
	select {
	case <-s.Done:
	default:
		close(s.Done)
	}
	return s.servErr
}

func (s TestServer) ListenAndServeTLS() error {
	s.servErr = s.Server.ListenAndServeTLS(s.certFile, s.keyFile)
	os.Remove(s.certFile)
	os.Remove(s.keyFile)
	select {
	case <-s.Done:
	default:
		close(s.Done)
	}
	return s.servErr
}

func (s *TestServer) AddError(err error) {
	if err != nil {
		s.errs = append(s.errs, err)
	}
}

func (s *TestServer) FuncAfter(d time.Duration, f func() error) {
	go func() {
		select {
		case <-time.After(d):
			s.AddError(f())
		case <-s.Done:
		}
	}()
}

// CreateCert creates a self signed cert and keys, returning the names of the files they are stored in.
func (s *TestServer) CreateCert() error {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %s", err)
	}
	template := &x509.Certificate{
		IsCA:         true,
		SubjectKeyId: []byte{1, 2, 3},
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(5, 5, 5),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to generate cert: %s", err)
	}

	certOut, err := ioutil.TempFile("", "test")
	if err != nil {
		return err
	}
	defer certOut.Close()

	if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		os.Remove(certOut.Name())
		return err
	}

	keyOut, err := ioutil.TempFile("", "test")
	if err != nil {
		os.Remove(certOut.Name())
		return err
	}
	defer keyOut.Close()

	if err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		os.Remove(certOut.Name())
		os.Remove(keyOut.Name())
		return err
	}

	s.certFile = certOut.Name()
	s.keyFile = keyOut.Name()

	return nil
}

func (s *TestServer) Run(tls bool) error {
	if tls {
		if err := s.CreateCert(); err != nil {
			return err
		}
	}
	go func() {
		var err error
		if tls {
			err = s.ListenAndServeTLS()
		} else {
			err = s.ListenAndServe()
		}

		if err != nil {
			log.Println("error:", err)
		}
	}()

	for s.GetState() == StateInit {
		select {
		case <-time.After(10 * time.Millisecond):
			// Retest to see if its running yet
		case <-s.Done:
			if s.servErr != nil {
				return s.servErr
			}

			return fmt.Errorf("unexpected exit")
		}
	}

	return s.servErr
}

type TestReq struct {
	URL        *url.URL
	StatusCode int
	Body       string
	RequestErr error
	Method     string
	t          *testing.T
}

func NewTestReq(t *testing.T, h *MockHandler, urlStr string) *TestReq {
	u, err := url.Parse("http://localhost" + TestAddr + urlStr)
	if err != nil {
		t.Fatal(err)
	}

	r := &TestReq{
		URL:        u,
		StatusCode: http.StatusOK,
		Body:       "body",
		t:          t,
	}

	if h != nil {
		h.On("ServeHTTP", r.URL.Path).Return(r)
	}

	return r
}

func (r *TestReq) SetError(err error) {
	r.RequestErr = &url.Error{URL: r.URL.String(), Err: err}
}

func (r *TestReq) Validate(resp *http.Response, err error, closeBody bool) {
	assert.Equal(r.t, r.RequestErr, err)
	if r.RequestErr == nil && assert.NotNil(r.t, resp) {
		assert.Equal(r.t, r.StatusCode, resp.StatusCode)
		b, err := ioutil.ReadAll(resp.Body)
		if closeBody {
			resp.Body.Close()
		}
		assert.NoError(r.t, err)
		assert.Equal(r.t, r.Body, string(b))
	}
}

func (r *TestReq) Get(closeBody bool) {
	r.Method = "GET"
	if err, ok := r.RequestErr.(*url.Error); ok {
		err.Op = "Get"
	}
	resp, err := TestClient.Get(r.URL.String())
	r.Validate(resp, err, closeBody)
}

var TestTransport = &http.Transport{
	Dial: (&net.Dialer{
		Timeout:   time.Second,
		KeepAlive: 0,
	}).Dial,
	DisableKeepAlives:   true,
	TLSHandshakeTimeout: time.Second,
}
var TestClient = &http.Client{Transport: TestTransport}

func serverHelper() *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}

	return cmd
}

// TestHelperProcess isn't a real test. It's used as a helper process.
func TestHelperProcess(t *testing.T) {
	log.SetPrefix(fmt.Sprintf("child: %v - ", os.Getpid()))
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "" {
		t.Skip("test helper")
	}

	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}

	h := NewMockHandler()
	h.req = NewTestReq(t, h, "/test")
	s := NewTestServer(h)
	err := s.Run(false)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("ready")

	if err := processCmds(os.Stdin); err != nil {
		log.Fatal(err)
	}

	s.TerminateTimeout = 0
	if err := s.Shutdown(); err != nil {
		log.Fatal(err)
	}

	<-s.Done
}

func processCmds(f io.ReadCloser) error {
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		txt := scanner.Text()
		switch txt {
		case "restart":
			if _, err := Restart(); err != nil {
				return err
			}
			fmt.Println("restart")
		case "shutdown":
			if err := Shutdown(); err != nil {
				return err
			}
			fmt.Println("shutdown")
		case "terminate":
			if err := Terminate(0); err != nil {
				return err
			}
			fmt.Println("terminate")
		case "done":
			fmt.Println("done")
			break
		default:
			return fmt.Errorf("unrecognised cmd: %v", txt)
		}
	}

	return scanner.Err()
}

func TestShutdown(t *testing.T) {
	s := NewTestServer(NewMockHandler())

	assert.NoError(t, s.Run(false))
	assert.NoError(t, s.Shutdown())

	<-s.Done
	assert.NoError(t, s.servErr)
	assert.Equal(t, StateShutdown, s.GetState())
}

func TestShutdownTLS(t *testing.T) {
	s := NewTestServer(NewMockHandler())

	assert.NoError(t, s.Run(true))
	assert.NoError(t, s.Shutdown())

	<-s.Done
	assert.NoError(t, s.servErr)
	assert.Equal(t, StateShutdown, s.GetState())
}

func TestDoubleShutdown(t *testing.T) {
	s := NewTestServer(NewMockHandler())

	assert.NoError(t, s.Run(false))
	assert.NoError(t, s.Shutdown())
	assert.NoError(t, s.Shutdown())

	<-s.Done
	assert.NoError(t, s.servErr)
	assert.Equal(t, StateShutdown, s.GetState())
}

func TestShutdownRequest(t *testing.T) {
	h := NewMockHandler()
	s := NewTestServer(h)

	assert.NoError(t, s.Run(false))

	r := NewTestReq(t, h, "/test")
	r.Get(true)
	assert.NoError(t, s.Shutdown())

	h.AssertExpectations(t)

	<-s.Done
	assert.NoError(t, s.servErr)
	assert.Equal(t, StateShutdown, s.GetState())
}

func TestTerminateKeepAlive(t *testing.T) {
	h := NewMockHandler()
	s := NewTestServer(h)
	s.TerminateTimeout = time.Second

	assert.NoError(t, s.Run(false))

	r := NewTestReq(t, h, "/test")
	TestTransport.DisableKeepAlives = false
	r.Get(true)
	TestTransport.DisableKeepAlives = true
	assert.NoError(t, s.Shutdown())

	h.AssertExpectations(t)

	<-s.Done
	assert.NoError(t, s.servErr)
	assert.Equal(t, StateTerminated, s.GetState())
}

func TestTerminateHandler(t *testing.T) {
	h := NewMockHandler()
	s := NewTestServer(h)
	s.TerminateTimeout = 100 * time.Millisecond

	assert.NoError(t, s.Run(false))

	r := NewTestReq(t, h, "/test?sleep=1s")
	r.SetError(io.EOF)
	s.FuncAfter(100*time.Millisecond, s.Shutdown)

	r.Get(true)

	h.AssertExpectations(t)

	<-s.Done
	assert.NoError(t, s.servErr)
	assert.Equal(t, StateTerminated, s.GetState())
}

func readText(t *testing.T, s *bufio.Scanner) string {
	if s.Scan() {
		return s.Text()
	}

	t.Fatal(s.Err())

	// Not reached
	return ""
}

func TestRestart(t *testing.T) {
	cmd := serverHelper()
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}

	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}

	scanner := bufio.NewScanner(stdout)

	txt := readText(t, scanner)
	assert.Equal(t, "ready", txt)

	r := NewTestReq(t, nil, "/test")
	r.Get(true)

	fmt.Fprintln(stdin, "restart")

	txt = readText(t, scanner)
	assert.Equal(t, "restart", txt)

	txt = readText(t, scanner)
	assert.Equal(t, "ready", txt)

	r.Get(true)
	stdin.Close()
	//h.On("ServeHTTP", r.URL.Path).Return(r)

	//h.AssertExpectations(t)
}
