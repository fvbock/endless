package main

import (
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/fvbock/endless"
	"github.com/gorilla/mux"
)

func handler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("WORLD!"))
}

func handlerFoo(w http.ResponseWriter, r *http.Request) {
	time.Sleep(time.Second)
	w.Write([]byte("BAR"))
}

func handlerBar(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("FOO"))
}

func main() {
	mux1 := mux.NewRouter()
	mux1.HandleFunc("/hello", handler).
		Methods("GET")
	mux1.HandleFunc("/foo", handlerFoo).
		Methods("GET")

	mux2 := mux.NewRouter()
	mux2.HandleFunc("/bar", handlerBar).
		Methods("GET")

	log.Println("Starting servers...")

	w := sync.WaitGroup{}
	w.Add(2)
	go func() {
		time.Sleep(time.Second)
		err := endless.ListenAndServe("localhost:4242", mux1)
		if err != nil {
			log.Println(err)
		}
		log.Println("Server on 4242 stopped")
		w.Done()
	}()
	go func() {
		err := endless.ListenAndServe("localhost:4243", mux2)
		if err != nil {
			log.Println(err)
		}
		log.Println("Server on 4243 stopped")
		w.Done()
	}()
	w.Wait()
	log.Println("All servers stopped. Exiting.")

	os.Exit(0)
}
