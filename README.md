# httpmulti

How to start both HTTP ans HTTPS servers on same port ?

## Description

The solution to this exercice is to read and analyse the first byte of the communication only.

Simple `HTTP` protocol starts directly with the HTTP verb:

- **G**ET
- **P**OST
- **H**EAD
- **D**ELETE
- ...

So that the first byte is either **G**, **P**, **H**, **D**, ...

`HTTPS` communication starts with the SSL handshake. And in this case the first byte always is the character with the code **22**.

In this simple [httpmulti](main.go) library once we got the first byte we send it to the the right server (`HTTP` or `HTTPS` depending on its value) with the rest of the communication.

The only thing you have to do is to decribe a [serveMux](https://pkg.go.dev/net/http#ServeMux) with its route handlers list. Then run the `multihttp` server with this serveMux. As for simple `net/http` library the server starts with either function

```go
func ListenAndServe(addr string, handler http.Handler, certFile, keyFile string) error
```

or

```go
func Serve(ln net.Listener, handler http.Handler, certFile, keyFile string) error
```

Of course, to be able to serve SSL communications a private key (`key.pem`) and a valid certificate (`cert.pem`) must be provided.

`httpmulti` accept a custom `log.Logger`

```go
server.SetLogger(log.Default())
```

It is also possible to define a list of CIDR to block with

```go
server.AddCIDRBlockList("127.0.0.0/8")
```

By default `httpmulti` listens protocol `tcp`. It is possible to force `tcp4`, `tcp6`, `unix` or `unixpacket`:

```go
server.SetProtocol("tcp4")
```

Force TLS connections

```go
server.ForceSecure()
```

Remove `HTTP/2` support

```go
server.SetHTTP2(false)
```

Add CA certificate file to validate client certificates against ...

```go
server.SetCACertFile("ca.crt")
```

... and and CRL file to check revoked certificates

```go
server.SetCRL("ca.crl")
```

## Examples

### Hello world

Here is a simple [Hello World!](cmd/hello/main.go):

```go
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
```

Build it with command `go build ./cmd/hello` and start it with `./hello`.

The server is reachable at `http://localhost:8080` and `https://localhost:8080`.

### File server

A simple [file server example](cmd/fileserver/main.go) is available.

Build it with command `go build ./cmd/fileserver`.

### Proxy

Another simple example to [proxify towards another HTTP server](cmd/proxy/main.go) is available.

Build it with command `go build ./cmd/proxy`.

## Complement

### How to easily build a server certificate

#### Make a light certificate authority

```bash
openssl genrsa -out cakey.pem 4096 \
&& openssl req -x509 -sha512 -days 3650 \
  -new -noenc \
  -key cakey.pem \
  -outform PEM -out cacert.pem \
  -addext "basicConstraints = critical, CA:TRUE" \
  -addext "subjectKeyIdentifier = hash" \
  -addext "authorityKeyIdentifier = keyid:always, issuer" \
  -addext "keyUsage = critical, keyCertSign, cRLSign, digitalSignature" \
  -subj "/C=FR/ST=France/L=Paris/O=Orga/OU=Unit/CN=EasyCA" \
&& sudo cp cacert.pem /usr/local/share/ca-certificates/easyca.crt \
&& sudo update-ca-certificates
```

#### Make server certificate

```bash
openssl req -new \
  -newkey rsa:4096 -nodes -keyform PEM -keyout key.pem \
  -outform PEM -out csr.pem \
  -subj "/C=FR/ST=France/L=Paris/O=Orga/OU=Unit/CN=localhost" \
  -addext "subjectAltName = IP:127.0.0.1,DNS:localhost" \
&& openssl x509 -req -days 3650 -sha512 \
  -CA cacert.pem -CAkey cakey.pem -CAcreateserial \
  -in csr.pem \
  -copy_extensions copy \
  -outform PEM -out cert.pem
```

#### Remove certificate authority

```bash
sudo rm -f /usr/local/share/ca-certificates/easyca.crt \
&& sudo update-ca-certificates -f
```

---

> Ref:  
[https://groups.google.com/g/golang-nuts/c/4oZp1csAm2o/m/nTTKDvvFJQ0J](https://groups.google.com/g/golang-nuts/c/4oZp1csAm2o/m/nTTKDvvFJQ0J)  
[https://stackoverflow.com/questions/26090301/run-both-http-and-https-in-same-program](https://stackoverflow.com/questions/26090301/run-both-http-and-https-in-same-program)
