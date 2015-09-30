package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"sync"
	"time"
)

var (
	keepRestarting bool
)

func compileAndStartTestServer(compileDone chan struct{}) {
	cmd := exec.Command("go", []string{"build", "-a", "-v", "-o", "test_server", "examples/testserver.go"}...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if err != nil {
		log.Println("test server compile error:", err)
	}
	err = cmd.Wait()
	if err != nil {
		log.Println("test server compile error:", err)
	}

	cmd = exec.Command("./test_server", []string{}...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		log.Println("test server error:", err)
	}
	compileDone <- struct{}{}
	err = cmd.Wait()
	if err != nil {
		log.Println("test server error:", err)
	}
	return
}

func runAB() (err error) {
	time.Sleep(time.Second * 1)
	cmd := exec.Command("ab", []string{"-c 1000", "-n 100000", "http://localhost:4242/foo"}...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		log.Println("AB error:", err)
	}
	err = cmd.Wait()
	if err != nil {
		log.Println("AB error:", err)
	}
	return
}

func stopTestServer() (err error) {
	log.Println("* Wait 5 seconds and then send kill -15 to server")
	time.Sleep(time.Second * 5)
	log.Println("* kill -15")
	cmd := exec.Command("./test/stop_server.sh", []string{}...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		log.Println("kill error:", err)
		return
	}

	err = cmd.Wait()
	if err != nil {
		log.Println("kill error:", err)
	}
	return
}

func keepRestartingServer() {
	time.Sleep(time.Second * 1)
	for keepRestarting {
		time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
		// time.Sleep(time.Second * 60)
		log.Println("sending kill -1")
		cmd := exec.Command("./test/restart_server.sh", []string{}...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err := cmd.Start()
		if err != nil {
			log.Println("restart error:", err)
		}
		err = cmd.Wait()
		if err != nil {
			log.Println("restart error:", err)
		}
	}
}

func main() {
	// check for ab - pretty hacky...
	out, _ := exec.Command("which", []string{"ab"}...).Output()
	log.Println("WHICH ab:", string(out))
	if len(out) == 0 {
		log.Println("cant find ab (apache bench). not running test.")
		return
	}

	wg := sync.WaitGroup{}
	var compileDone = make(chan struct{}, 1)
	wg.Add(2)
	go func() {
		log.Println("compile and start test server")
		compileAndStartTestServer(compileDone)
		log.Println("test server stopped")
		wg.Done()
	}()

	time.Sleep(time.Second * 1)

	go func() {
		<-compileDone
		log.Println("Starting ab")
		keepRestarting = true
		go keepRestartingServer()
		err := runAB()
		if err != nil {
			panic(fmt.Sprintf("Failed to start ab: %v", err))
		}
		log.Println("ab done. stop server.")
		keepRestarting = false
		stopTestServer()
		wg.Done()
	}()

	wg.Wait()
	log.Println("All done.")
}
