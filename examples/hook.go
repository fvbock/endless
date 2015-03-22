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

func preSigUsr1() {
	log.Println("pre SIGUSR1")
}

func postSigUsr1() {
	log.Println("post SIGUSR1")
}

func main() {
	mux1 := mux.NewRouter()
	mux1.HandleFunc("/hello", handler).
		Methods("GET")

	srv := endless.NewServer("localhost:4244", mux1)
	srv.SignalHooks[endless.PRE_SIGNAL][syscall.SIGUSR1] = append(
		srv.SignalHooks[endless.PRE_SIGNAL][syscall.SIGUSR1],
		preSigUsr1)
	srv.SignalHooks[endless.POST_SIGNAL][syscall.SIGUSR1] = append(
		srv.SignalHooks[endless.POST_SIGNAL][syscall.SIGUSR1],
		postSigUsr1)

	err := srv.ListenAndServe()
	if err != nil {
		log.Println(err)
	}
	log.Println("Server on 4244 stopped")

	os.Exit(0)
}
