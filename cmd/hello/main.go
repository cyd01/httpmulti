package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/cyd01/httpmulti"
)

var (
	addr     = flag.String("addr", "127.0.0.1:8080", "listening address")
	certFile = flag.String("cert", "cert.pem", "certificate file")
	keyFile  = flag.String("key", "key.pem", "private key file")
)

func hello(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.URL.Path)
	w.Header().Set("Content-Type", "text/plain")
	n := strings.TrimPrefix(r.URL.Path, "/")
	if n == "" {
		fmt.Fprintln(w, "Hello world!")
	} else {
		fmt.Fprintln(w, "Hello "+n+"!")
	}
}

func main() {
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/", hello)

	log.Println("Starting hello server at", *addr)
	server := httpmulti.New(*addr)
	log.Fatal(server.ListenAndServe(mux, *certFile, *keyFile))
}
