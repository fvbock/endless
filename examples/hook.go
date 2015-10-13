package main

import (
	"log"
	"net/http"
	"os"
	"syscall"

	"github.com/fvbock/endless"
	"github.com/gorilla/mux"
)

func handler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("WORLD!"))
}

func preSigUsr1(sig os.Signal, m *endless.Manager) bool {
	log.Println("pre SIGUSR1")
	return true
}

func postSigUsr1(sig os.Signal, m *endless.Manager) bool {
	log.Println("post SIGUSR1")
	return true
}

func main() {
	mux1 := mux.NewRouter()
	mux1.HandleFunc("/hello", handler).
		Methods("GET")

	srv := endless.NewServer("localhost:4244", mux1)
	h := srv.Handler.(*endless.SignalHandler)
	h.RegisterPreSignalHook(syscall.SIGUSR1, preSigUsr1)
	h.RegisterPostSignalHook(syscall.SIGUSR1, postSigUsr1)
	err := srv.ListenAndServe()
	if err != nil {
		log.Println(err)
	}
	log.Println("Server on 4244 stopped")

	os.Exit(0)
}
