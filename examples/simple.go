package main

import (
	"log"
	"net/http"
	"os"

	"github.com/fvbock/endless"
	"github.com/gorilla/mux"
)

func handler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("WORLD!"))
}

func main() {
	mux1 := mux.NewRouter()
	mux1.HandleFunc("/hello", handler).
		Methods("GET")

	err := endless.ListenAndServe("localhost:4242", mux1)
	if err != nil {
		log.Println(err)
	}
	log.Println("Server on 4242 stopped")

	os.Exit(0)
}
