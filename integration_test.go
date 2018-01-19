package endless

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

const (
	intSrvFeatureToggle = "GO_INTEGRATION_TEST_SERVER"
	intSrvPath          = "/test"
	intSrvAlivePath     = "/alive"
	intSrvReqRecv       = "request received"
)

var (
	serverpids = make(map[int]struct{})
	intSrvHost = *flag.String("host", "localhost", "useable host for test server")
	intSrvPort = *flag.String("port", "4242", "useable port for test server")
)

// TestIntegrationServer isn't a real test - instead it is used as a
// test server binary so that we can test signal handling and the subsequent
// shutdown/restarts from a separate binary from the test itself.
// This test is only run when an environment variable feature toggle
// (named by intSrvFeatureToggle) is set by the calling test
func TestIntegrationServer(t *testing.T) {
	if os.Getenv(intSrvFeatureToggle) != "1" {
		t.Skip("Skipping as have not been asked to stand up integration server")
	}
	mux1 := mux.NewRouter()

	mux1.HandleFunc(intSrvPath, integrationTestServerHandler).Methods(http.MethodGet)
	alive := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	mux1.HandleFunc(intSrvAlivePath, alive).Methods(http.MethodGet)

	base := fmt.Sprintf("%s:%s", intSrvHost, intSrvPort)
	srv := NewServer("tcp", base, mux1)
	srv.ErrorLog = log.New(os.Stdout, "", log.LstdFlags)
	srv.Debug = true
	srv.TerminateTimeout = 2 * time.Second

	// This is used to signal back to the calling test that the server has started up
	fmt.Println("PID:", os.Getpid())
	if err := srv.ListenAndServe(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("Shutting down")
}

// integrationTestServerHandler is the handler used by the integration test server
func integrationTestServerHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println(intSrvReqRecv)
	duration, err := time.ParseDuration(r.FormValue("duration"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	time.Sleep(duration)
	fmt.Fprintf(
		w, "Slept for %v seconds. Response from pid %v.\n",
		duration.Seconds(),
		os.Getpid(),
	)
}

// createIntegrationServer will re-run the test binary that is currently running,
// but only execute the "TestIntegrationServer" test, which will stand up an
// 'endless' server which can be used to test signal handling
func createIntegrationServerTest() *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=TestIntegrationServer")

	// Set the feature toggle for the integration test server
	cmd.Env = []string{intSrvFeatureToggle + "=1"}

	return cmd
}

func TestIntegrationRestart(t *testing.T) {
	flag.Parse()
	intServer := createIntegrationServerTest()
	msgs := make(chan string, 3) // we read off the channel three times so ensure we don't deadlock
	// Start test integration server
	require.NoError(t, startIntegrationServer(intServer, msgs), "starting integration test server")
	ppid := intServer.Process.Pid
	defer teardownServer(t, ppid)
	go intServer.Wait()

	// The pid is printed out from the integation test server once it has fully started up
	// Check for this message so we can start sending requests/signals to the server
	msg, err := waitForMessage(msgs, 3*time.Second)
	require.NoError(t, err, "wait for server startup")
	msgPid, _ := strconv.Atoi(msg) // don't care about error here as we're just going to compare msgPid to the parentpid anyway
	require.Equal(t, ppid, msgPid, "unexpected message down messages channel")

	// Wait for the server to actually come up and respond to requests before we send any important ones
	require.NoError(t, waitForServer(fmt.Sprintf("http://%s:%s%s", intSrvHost, intSrvPort, intSrvAlivePath)), "wait for server to accept requests")

	// Send a long running request to the test server
	lReqWait := &sync.WaitGroup{}
	lReqWait.Add(1)
	var (
		lResp   *http.Response
		lReqErr error
	)
	go func() {
		lResp, lReqErr = sendIntegrationTestRequest(2 * time.Second)
		lReqWait.Done()
	}()

	msg, err = waitForMessage(msgs, 1*time.Second)
	require.NoError(t, err, "wait for long request to arrive")
	require.Equal(t, intSrvReqRecv, msg, "unexpected message while waiting for long request to arrive")

	// Send a signal to the test server to restart
	require.NoError(t, intServer.Process.Signal(syscall.SIGHUP), "send signal to restart")

	// The child server should also print it's pid out once it's started up, so look for this
	msg, err = waitForMessage(msgs, 3*time.Second)
	require.NoError(t, err, "wait for child server startup")
	cpid, _ := strconv.Atoi(msg) // don't care about error here as we're just going to check msgPid isn't zero
	require.NotZero(t, msgPid, "unexpected message down messages channel")
	defer teardownServer(t, cpid) // set up the child server to be torn down on test exit

	// Send a quick request to the server. The child server should now be up and running, accepting requests,
	// so check that it is the child PID that appears in the response and not the parent
	qResp, qReqErr := sendIntegrationTestRequest(0)
	require.NoError(t, qReqErr, "sending quick request to child server")
	require.Equal(t, http.StatusOK, qResp.StatusCode, "response code from long request")

	qBody, err := ioutil.ReadAll(qResp.Body)
	qResp.Body.Close()
	require.NoError(t, err, "read from quick request body")
	require.NotContains(t, string(qBody), strconv.Itoa(ppid), "quick response contained wrong PID")
	require.Contains(t, string(qBody), strconv.Itoa(cpid), "quick response did not contain correct PID")

	// Wait for long request to finish, which should be responded to from
	// the parent integration test server
	lReqWait.Wait()
	require.NoError(t, lReqErr, "sending long request to parent server")
	require.Equal(t, http.StatusOK, lResp.StatusCode, "http response code from long running request")
	lBody, err := ioutil.ReadAll(lResp.Body)
	require.NoError(t, err, "read from long request body")
	require.Contains(t, string(lBody), strconv.Itoa(ppid), "long response did not contain correct PID")
	time.Sleep(2 * time.Second)
	require.Error(t, intServer.Process.Signal(syscall.Signal(0)), "expected error when signalling stopped parent process, process has not exited")

}

func sendIntegrationTestRequest(sleepDuration time.Duration) (*http.Response, error) {
	reqURL := fmt.Sprintf("http://%s:%s%s?duration=%s", intSrvHost, intSrvPort, intSrvPath, sleepDuration)
	timeout := int(sleepDuration.Seconds() + 2) // add two seconds to the duration of the call to get the http timeout

	client := http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}
	return client.Get(reqURL)
}

func startIntegrationServer(intServer *exec.Cmd, messages chan string) error {
	outPipe, err := intServer.StdoutPipe()
	if err != nil {
		close(messages)
		return err // note process not started yet so we shouldn't have to kill intserver
	}
	if err := intServer.Start(); err != nil {
		close(messages)
		return err
	}
	// Forward relevant messages from stdout back to the test
	go watchStdout(outPipe, messages)
	return nil
}

func teardownServer(t *testing.T, pid int) {
	proc, err := os.FindProcess(pid)
	if err != nil {
		t.Fatalf("Could not find process with PID %v to clean up\n", pid)
	}
	if err := proc.Kill(); err != nil {
		if !strings.Contains(err.Error(), "process already finished") {
			t.Fatalf("Could not find process with PID %v to clean up\n", pid)
		}
	}
}

func waitForMessage(msgs chan string, timeout time.Duration) (string, error) {
	to := time.NewTimer(timeout)
	select {
	case <-to.C:
		return "", fmt.Errorf("timeout of %v exceeded", timeout)
	case msg, open := <-msgs:
		if !open {
			return "", errors.New("unexpected close of messages channel")
		}
		return msg, nil
	}
}

func waitForServer(uri string) error {
	reqURL, err := url.ParseRequestURI(uri)
	if err != nil {
		return err
	}
	req := &http.Request{
		URL: reqURL,
	}
	client := http.DefaultClient
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	for {
		cctx, ccancel := context.WithTimeout(ctx, 10*time.Millisecond)
		defer ccancel()
		resp, err := client.Do(req.WithContext(cctx))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-cctx.Done():
			// request took too long, go round again
		default:
			if err == nil {
				if resp.StatusCode == http.StatusOK {
					return nil
				}
				return fmt.Errorf("unexpected HTTP response from server: %v", resp.StatusCode)
			}
		}
	}
}

// watchStdout watches stdout from the test integration server for specific messages
// * the PID on start up
// * request received notification from the HTTP handler
func watchStdout(outPipe io.ReadCloser, messages chan string) {
	defer close(messages)
	scanner := bufio.NewScanner(outPipe)
	for scanner.Scan() {
		line := scanner.Text()
		if pid, ok := getpid(line); ok {
			messages <- pid
			continue
		}
		if line == intSrvReqRecv {
			messages <- line
			continue
		}
	}
	if err := scanner.Err(); err != nil {
		messages <- err.Error()
		close(messages)
		return
	}
}

func getpid(line string) (string, bool) {
	if !strings.Contains(line, "PID: ") {
		return "", false
	}
	pid := strings.TrimPrefix(strings.TrimSpace(line), "PID: ")
	if _, err := strconv.Atoi(pid); err != nil {
		return "", false
	}
	return pid, true
}
