package endless

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockHandler struct {
	mock.Mock
}

func NewMockHandler() *MockHandler {
	return &MockHandler{}
}

func (h *MockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	args := h.Called(r.URL.Path)
	tr := args.Get(0).(*TestReq)
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

func NewTestServer(h http.Handler) *TestServer {
	return &TestServer{
		Server: NewServer(TestAddr, h),
		errs:   make([]error, 0, 10),
	}
}

func (s TestServer) ListenAndServe() error {
	s.servErr = s.Server.ListenAndServe()
	return s.servErr
}

func (s TestServer) ListenAndServeTLS() error {
	s.servErr = s.Server.ListenAndServeTLS(s.certFile, s.keyFile)
	os.Remove(s.certFile)
	os.Remove(s.keyFile)
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
	s.certFile = certOut.Name()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := ioutil.TempFile("", "test")
	if err != nil {
		os.Remove(s.certFile)
		s.certFile = ""
		return err
	}
	s.keyFile = keyOut.Name()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	return nil
}

func (s *TestServer) Run(tls bool) error {
	if tls {
		if err := s.CreateCert(); err != nil {
			return err
		}
	}
	go func() {
		if tls {
			s.ListenAndServeTLS()
		} else {
			s.ListenAndServe()
		}
	}()

	for s.GetState() == StateInit {
		select {
		case <-time.After(10 * time.Millisecond):
			// ListenAndServe should be running now
		case <-s.Done:
			// Unexpected exit
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
	h.On("ServeHTTP", r.URL.Path).Return(r)

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
