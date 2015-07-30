package main

import (
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/flier/endless"
	"github.com/gorilla/mux"
)

func handler(w http.ResponseWriter, r *http.Request) {
	buf, _ := ioutil.ReadAll(r.Body)

	w.Write(buf)
}

func main() {
	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		endless.ListenAndServeTCP("localhost:8007", endless.HandleFunc(func(conn net.Conn) {
			defer conn.Close()

			var buf [4096]byte

			for {
				if n, err := conn.Read(buf[:]); err != nil {
					if err != io.EOF {
						log.Printf("error, %s", err)
					}

					break
				} else if _, err := conn.Write(buf[:n]); err != nil {
					log.Printf("error, %s", err)

					break
				}
			}
		}))
	}()

	go func() {
		defer wg.Done()

		mux1 := mux.NewRouter()
		mux1.HandleFunc("/", handler).Methods("POST")

		if err := endless.ListenAndServe("localhost:8008", mux1); err != nil {
			log.Println(err)
		} else {
			log.Println("Server on 8007 stopped")
		}
	}()

	wg.Wait()

	os.Exit(0)
}
