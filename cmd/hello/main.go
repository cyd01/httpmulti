package main

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/cyd01/httpmulti"
)

var (
	addr     = "127.0.0.1:8080"
	certFile = "cert.pem"
	keyFile  = "key.pem"
)

func hello(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.URL.Path)
	fmt.Fprintln(w, "Hello world!")
}

func main2() {
	var err error

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", hello)

	server := &httpmulti.Server{Addr: addr}
	log.Fatal(server.Serve(ln, mux, certFile, keyFile))
}

func main3() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", hello)

	server := httpmulti.New(addr)
	log.Fatal(server.ListenAndServe(mux, certFile, keyFile))
}

func main4() {
	var err error

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", hello)

	log.Fatal(httpmulti.Serve(ln, mux, certFile, keyFile))
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", hello)

	log.Println("Starting hello server at", addr)
	log.Fatal(httpmulti.ListenAndServe(addr, mux, certFile, keyFile))
}
