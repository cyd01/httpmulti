package httpmulti

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

type Conn struct {
	net.Conn
	b byte
	e error
	f bool
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.f {
		c.f = false
		b[0] = c.b
		if len(b) > 1 && c.e == nil {
			n, e := c.Conn.Read(b[1:])
			if e != nil {
				c.Conn.Close()
			}
			return n + 1, e
		} else {
			return 1, c.e
		}
	}
	return c.Conn.Read(b)
}

type SplitListener struct {
	net.Listener
	config *tls.Config
}

func (l *SplitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			// Interrompre seulement pour les erreurs fatales
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			// Si le listener a été fermé, on relaie l'erreur
			if strings.Contains(err.Error(), "use of closed network connection") {
				return nil, err
			}
			log.Printf("accept error (not fatal): %v\n", err)
			continue // ignorer les erreurs passagères
		}

		b := make([]byte, 1)
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, err = c.Read(b)
		c.SetReadDeadline(time.Time{})
		if err != nil {
			// Certaines erreurs peuvent être ignorées
			if errors.Is(err, io.EOF) ||
				strings.Contains(err.Error(), "i/o timeout") ||
				strings.Contains(err.Error(), "reset by peer") ||
				strings.Contains(err.Error(), "connection aborted") {
				log.Printf("read error (not fatal): %v\n", err)
				c.Close()
				continue // ignorer et attendre une nouvelle connexion
			}
			c.Close()
			return nil, fmt.Errorf("read error: %w", err)
		}

		con := &Conn{
			Conn: c,
			b:    b[0],
			e:    err,
			f:    true,
		}

		if b[0] == 22 {
			if l.config != nil {
				return tls.Server(con, l.config), nil
			}
			return con, nil
		}

		return con, nil
	}
}

type Server struct {
	http.Server
	Addr string
	l    *SplitListener
}

func New(addr string) *Server {
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}
	srv := &Server{Addr: addr}
	return srv
}

func (s *Server) SetHTTP1(b bool) {
	if s.Server.Protocols == nil {
		s.Server.Protocols = new(http.Protocols)
	}
	s.Server.Protocols.SetHTTP1(b)
}

func (s *Server) SetHTTP2(b bool) {
	if s.Server.Protocols == nil {
		s.Server.Protocols = new(http.Protocols)
	}
	s.Server.Protocols.SetHTTP2(b)
}

func (s *Server) SetUnencryptedHTTP2(b bool) {
	if s.Server.Protocols == nil {
		s.Server.Protocols = new(http.Protocols)
	}
	s.Server.Protocols.SetUnencryptedHTTP2(b)
}

func (s *Server) WithHTTP1() *Server {
	s.SetHTTP1(true)
	return s
}

func (s *Server) WithHTTP2() *Server {
	s.SetHTTP2(true)
	return s
}

func (s *Server) This() *http.Server {
	return &s.Server
}

func (s *Server) Close() error {
	return s.Server.Close()
}

func (s *Server) RegisterOnShutdown(f func()) {
	s.Server.RegisterOnShutdown(f)
}

func (s *Server) SetKeepAlivesEnabled(v bool) {
	s.Server.SetKeepAlivesEnabled(v)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.Server.Shutdown(ctx)
}

func isValidAddr(addr string) bool {
	regex := regexp.MustCompile(`^([a-zA-Z0-9.-]+)?:([0-9]+)$`)
	return regex.MatchString(addr)
}

func (s *Server) ListenAndServe(handler http.Handler, certFile, keyFile string) error {
	if len(s.Addr) > 0 {
		s.Server.Addr = s.Addr
	}
	if !isValidAddr(s.Server.Addr) {
		return errors.New("invalid server address: " + s.Server.Addr)
	}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return errors.New("Can not start listener on " + s.Addr)
	}
	return s.Serve(ln, handler, certFile, keyFile)
}

func (s *Server) Serve(ln net.Listener, handler http.Handler, certFile, keyFile string) error {
	s.Addr = ln.Addr().String()
	http2.ConfigureServer(&s.Server, &http2.Server{})
	s.l = &SplitListener{Listener: ln}
	s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			handler.ServeHTTP(w, r)
		} else {
			handler.ServeHTTP(w, r)
		}
	})
	if (len(certFile) > 0) && (len(keyFile) > 0) && existfile(certFile) && existfile(keyFile) {
		var err error
		config := &tls.Config{
			MinVersion:             tls.VersionTLS12,
			NextProtos:             []string{"h2", "h3", "http/1.1"},
			SessionTicketsDisabled: true,
		}
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return errors.New("Can not load X509 key pair")
		}
		s.l.config = config
	} else {
		s.l.config = nil
	}
	return s.Server.Serve(s.l)
}

func ListenAndServe(addr string, handler http.Handler, certFile, keyFile string) error {
	server := New(addr)
	return server.ListenAndServe(handler, certFile, keyFile)
}

func Serve(ln net.Listener, handler http.Handler, certFile, keyFile string) error {
	server := &Server{}
	return server.Serve(ln, handler, certFile, keyFile)
}

func existfile(filename string) bool {
	if _, err := os.Stat(filename); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}
