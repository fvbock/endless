package main

import (
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/fvbock/endless"
	"github.com/gorilla/mux"
)

func handlerTest(w http.ResponseWriter, r *http.Request) {
	time.Sleep(time.Duration(rand.Intn(2000)) * time.Millisecond)
	w.Write([]byte("bar\n"))
}

func main() {
	// endless.DefaultHammerTime = 10*time.Second
	mux := mux.NewRouter()
	mux.HandleFunc("/foo", handlerTest).
		Methods("GET")

	err := endless.ListenAndServe("localhost:4242", mux)
	if err != nil {
		log.Println(err)
	}
	log.Println("Server on 4242 stopped")

	os.Exit(0)
}
