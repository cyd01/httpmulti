package httpmulti

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Conn struct {
	net.Conn
	b byte
	e error
	f bool
}

/*
	Read implements the net.Conn Read method for the Conn struct.

The Conn struct is a wrapper around net.Conn that allows us to peek at the first byte of the connection to determine if it's a TLS connection (which starts with byte 22 for TLS handshakes). The Read method checks if this is the first read (indicated by the boolean f). If it is, it returns the first byte that was read during the Accept phase. If there are more bytes to read and no error occurred, it reads the remaining bytes into the provided buffer. For subsequent reads, it simply delegates to the underlying net.Conn Read method.
*/
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
	ReadTimeout time.Duration
	tlsConfig   *tls.Config
	CIDRMatcher *CIDRMatcher
	server      *Server
	mu          sync.Mutex
}

/*
	Accept implements the net.Listener Accept method for the SplitListener struct.

The SplitListener is a custom listener that wraps a standard net.Listener to provide additional functionality. In the Accept method, it continuously accepts incoming connections. For each accepted connection, it checks if the remote address matches any CIDR blocks in the block list (if configured) and rejects the connection if it does. It then peeks at the first byte of the connection to determine if it's a TLS handshake (byte 22). If it is, it wraps the connection in a tls.Server with the provided TLS configuration. If not, it returns the connection as is. The method also includes error handling to ignore temporary errors and log important events if a logger is configured.
*/
var ErrClosedListener = errors.New("closed listener")

func (l *SplitListener) Accept() (net.Conn, error) {
	if l.server.Logger != nil {
		log.Printf("[httpmulti] start accepting connections at '%s'\n", l.server.Addr)
	}
	for {
		c, err := l.Listener.Accept()

		if err != nil {
			// Interrompre seulement pour les erreurs fatales
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			// Si le listener a été fermé, on relaie l'erreur
			if strings.Contains(err.Error(), "use of closed network connection") {
				return nil, ErrClosedListener
			}
			if l.server.Logger != nil {
				log.Printf("[httpmulti] accept error (not fatal): %v\n", err)
			}
			continue // ignorer les erreurs passagères
		}

		if l.CIDRMatcher != nil && l.CIDRMatcher.MatchConn(c) {
			if l.server.Logger != nil {
				log.Printf("[httpmulti] connection from '%s' rejected\n", c.RemoteAddr())
			}
			c.Close()
			continue
		}

		if l.server.Logger != nil {
			log.Printf("[httpmulti] new connection from '%s' accepted\n", c.RemoteAddr())
		}

		b := make([]byte, 1)
		if l.ReadTimeout > 0 {
			c.SetReadDeadline(time.Now().Add(l.ReadTimeout))
		}
		_, err = c.Read(b)
		c.SetReadDeadline(time.Time{})
		if err != nil {
			// Certaines erreurs peuvent être ignorées
			if errors.Is(err, io.EOF) ||
				strings.Contains(err.Error(), "i/o timeout") ||
				strings.Contains(err.Error(), "reset by peer") ||
				strings.Contains(err.Error(), "connection aborted") {
				if l.server.Logger != nil {
					log.Printf("[httpmulti] read error (not fatal): %v\n", err)
				}
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
			if l.tlsConfig != nil {
				return tls.Server(con, l.tlsConfig), nil
			}
		}
		if l.server.ForceSecureFlag {
			if l.server.Logger != nil {
				log.Printf("[httpmulti] TLS is required for connection from '%s'\n", c.RemoteAddr())
			}
			c.Close()
			continue
		}
		return con, nil
	}
}

func (l *SplitListener) Close() error {
	var err error
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.server != nil {
		err = l.Listener.Close()
	}
	l.tlsConfig = nil
	l.server = nil
	return err
}

/*
	Server is a custom HTTP server that supports both HTTP/1.1 and HTTP/2 protocols, with optional TLS encryption and CIDR-based connection blocking.

The Server struct embeds the standard http.Server and adds additional fields for configuration, such as the listening address, network protocol, CIDR block list for connection blocking, read timeout, and a logger for important events. The Server provides methods to configure supported protocols (HTTP/1.1, HTTP/2, unencrypted HTTP/2), set the network protocol (TCP over IPv4 or IPv6), add CIDR blocks to the block list, and manage server lifecycle (starting, shutting down). The server can be started with TLS encryption if certificate and key files are provided, and it uses a custom SplitListener to handle incoming connections based on the configured settings.
*/
type Server struct {
	http.Server
	Addr            string
	Proto           string
	CIDRBlockList   []string
	ReadTimeout     time.Duration
	l               *SplitListener
	Logger          *log.Logger
	ServerKeyFile   string
	ServerCertFile  string
	CACertFile      string
	CRL             *x509.RevocationList
	ForceSecureFlag bool
}

/*
	New creates a new Server with the specified address.

The address should be in the form "host:port", ":port" or "port".
If the host is omitted, it defaults to all interfaces. If the port is omitted, it defaults to ":80".
By default the returned Server is configured to support both HTTP/1.1 and HTTP/2, but you can customize this using the methods
  - SetHTTP1
  - SetHTTP2
  - SetUnencryptedHTTP2

or using the helper methods
  - WithHTTP1
  - WithHTTP2
  - WithUnencryptedHTTP2

You can also specify the protocol ("tcp", "tcp4", "tcp6") using the SetProtocol method or the WithTCP4 and WithTCP6 helper methods.
*/
func New(addr string) *Server {
	if len(addr) == 0 {
		addr = ":80"
	}
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}
	srv := &Server{Addr: addr, Proto: "tcp", ReadTimeout: time.Duration(500) * time.Millisecond}
	return srv
}

/*
	GetAddr returns the server's listening address.

This is useful when the server is started with an empty address or ":0" to get the actual port assigned by the system.
*/
func (s *Server) GetAddr() string {
	return s.Addr
}

// SetLogger sets the logger for the server. If set, the server will log important events such as starting, accepting connections, and errors.
func (s *Server) SetLogger(logger *log.Logger) {
	s.Logger = logger
}
func (s *Server) WithLogger(logger *log.Logger) *Server {
	s.SetLogger(logger)
	return s
}

/*
	AddCIDRBlockList adds a CIDR block to the server's block list.

Connections from IP addresses that match any of the CIDR blocks in the list will be rejected by the server.

The CIDR block should be in the format "IP/mask", for example "
*/
func (s *Server) AddCIDRBlockList(cidr string) {
	s.CIDRBlockList = append(s.CIDRBlockList, cidr)
}

func (s *Server) SetReadTimeout(d time.Duration) {
	s.ReadTimeout = d
}

// ForceSecure force the server to require TLS for all connections.
func (s *Server) ForceSecure() {
	s.ForceSecureFlag = true
}

func (s *Server) WithForceSecure() *Server {
	s.ForceSecure()
	return s
}

// Set TLS with the given certificate and key files.
func (s *Server) SetTLS(certFile, keyFile string) {
	s.ServerCertFile = certFile
	s.ServerKeyFile = keyFile
}

func (s *Server) WithTLS(certFile, keyFile string) *Server {
	s.SetTLS(certFile, keyFile)
	return s
}

/*
	SetProtocol sets the network protocol for the server (e.g., "tcp", "tcp4", "tcp6").

By default, the protocol is set to "tcp", which allows both IPv4 and IPv6 connections.
You can use this method to restrict the server to only accept connections over a specific protocol.
For example, calling SetProtocol("tcp4") will configure the server to only accept IPv4 connections, while SetProtocol("tcp6") will restrict it to IPv6 connections.
*/
func (s *Server) SetProtocol(proto string) {
	s.Proto = proto
}

/*
	WithProtocol sets the network protocol for the server (e.g., "tcp", "tcp4", "tcp6").

By default, the protocol is set to "tcp", which allows both IPv4 and IPv6 connections.
You can use this method to restrict the server to only accept connections over a specific protocol.
For example, calling WithProtocol("tcp4") will configure the server to only accept IPv4 connections, while WithProtocol("tcp6") will restrict it to IPv6 connections.
*/
func (s *Server) WithProtocol(proto string) *Server {
	s.SetProtocol(proto)
	return s
}

// WithTCP4 is a helper method that sets the server to use TCP over IPv4.
func (s *Server) WithTCP4() *Server {
	s.SetProtocol("tcp4")
	return s
}

// WithTCP6 is a helper method that sets the server to use TCP over IPv6.
func (s *Server) WithTCP6() *Server {
	s.SetProtocol("tcp6")
	return s
}

// SetHTTP1 enables or disables support for HTTP/1.1 on the server.
func (s *Server) SetHTTP1(b bool) {
	if s.Server.Protocols == nil {
		s.Server.Protocols = new(http.Protocols)
	}
	s.Server.Protocols.SetHTTP1(b)
}

// SetHTTP2 enables or disables support for HTTP/2 on the server.
func (s *Server) SetHTTP2(b bool) {
	if s.Server.Protocols == nil {
		s.Server.Protocols = new(http.Protocols)
	}
	s.Server.Protocols.SetHTTP2(b)
}

// SetUnencryptedHTTP2 enables or disables support for unencrypted HTTP/2 on the server.
func (s *Server) SetUnencryptedHTTP2(b bool) {
	if s.Server.Protocols == nil {
		s.Server.Protocols = new(http.Protocols)
	}
	s.Server.Protocols.SetUnencryptedHTTP2(b)
}

// SetCACertFile sets the path to the CA certificate file for TLS connections.
func (s *Server) SetCACertFile(caCertFile string) {
	s.CACertFile = caCertFile
}

// SetCRL sets a CRL file for TLS connections.
func (s *Server) SetCRL(crlFile string) error {
	data, err := os.ReadFile(crlFile)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "X509 CRL" {
		return fmt.Errorf("CRL PEM invalide")
	}
	c, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return err
	}
	s.CRL = c
	return nil
}

// WithHTTP1 is a helper method that sets the server to support HTTP/1.1.
func (s *Server) WithHTTP1() *Server {
	s.SetHTTP1(true)
	return s
}

// WithHTTP2 is a helper method that sets the server to support HTTP/2.
func (s *Server) WithHTTP2() *Server {
	s.SetHTTP2(true)
	return s
}

// WithUnencryptedHTTP2 is a helper method that sets the server to use unencrypted HTTP/2.
func (s *Server) WithUnencryptedHTTP2() *Server {
	s.SetUnencryptedHTTP2(true)
	return s
}

// WithoutHTTP1 is a helper method that disables the server from support HTTP/1.1.
func (s *Server) WithoutHTTP1() *Server {
	s.SetHTTP1(false)
	return s
}

// WithoutHTTP2 is a helper method that disables the server from support HTTP/2.
func (s *Server) WithoutHTTP2() *Server {
	s.SetHTTP2(false)
	return s
}

// WithoutUnencryptedHTTP2 is a helper method that disables the server from using unencrypted HTTP/2.
func (s *Server) WithoutUnencryptedHTTP2() *Server {
	s.SetUnencryptedHTTP2(false)
	return s
}

// WithCACertFile is a helper method that sets the path to the CA certificate file for TLS connections and returns the server instance for chaining.
func (s *Server) WithCACertFile(caCertFile string) *Server {
	s.SetCACertFile(caCertFile)
	return s
}

// WithCRL is a helper method that sets a CRL file for TLS connections.
func (s *Server) WithCRL(crlFile string) error {
	return s.SetCRL(crlFile)
}

// This returns the underlying http.Server instance, allowing you to access its fields and methods directly if needed.
func (s *Server) This() *http.Server {
	return &s.Server
}

// Close gracefully shuts down the server without interrupting any active connections.
//
// It returns an error if the server fails to shut down properly.
func (s *Server) Close() error {
	return s.Server.Close()
}

// RegisterOnShutdown registers a function to be called when the server is shutting down.
func (s *Server) RegisterOnShutdown(f func()) {
	s.Server.RegisterOnShutdown(f)
}

// SetKeepAlivesEnabled enables or disables HTTP keep-alives on the server.
func (s *Server) SetKeepAlivesEnabled(v bool) {
	s.Server.SetKeepAlivesEnabled(v)
}

// Shutdown gracefully shuts down the server without interrupting any active connections.
//
// It takes a context that can be used to set a timeout for the shutdown process. If the context times out before the shutdown is complete, the server will forcefully close all connections.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.l != nil && s.l.server != nil {
		s.l.Close()
	}
	return s.Server.Shutdown(ctx)
}

/*
	ListenAndServe starts the server and listens for incoming connections.

It takes an http.Handler to handle incoming HTTP requests, and optional certificate and key files for TLS encryption.
If the certificate and key files are provided and valid, the server will use TLS. Otherwise, it will start without encryption.

The method returns an error if the server fails to start or encounters a fatal error while running.
*/
func (s *Server) ListenAndServe(handler http.Handler, certFile, keyFile string) error {
	if len(s.Addr) > 0 {
		s.Server.Addr = s.Addr
	}
	if !isValidAddr(s.Server.Addr) {
		return errors.New("invalid server address: " + s.Server.Addr)
	}
	if s.Logger != nil {
		log.Printf("[httpmulti] start listening at '%s'\n", s.Addr)
	}
	if s.Proto == "" {
		s.Proto = "tcp"
	}
	ln, err := net.Listen(s.Proto, s.Addr)
	if err != nil {
		if s.Logger != nil {
			log.Printf("[httpmulti] can not start listener on '%s'\n", s.Addr)
		}
		return errors.New("Can not start listener on " + s.Addr)
	}
	return s.Serve(ln, handler, certFile, keyFile)
}

/*
	Serve starts the server using the provided net.Listener.

It takes an http.Handler to handle incoming HTTP requests, and optional certificate and key files for TLS encryption.
If the certificate and key files are provided and valid, the server will use TLS. Otherwise, it will start without encryption.

The method returns an error if the server fails to start or encounters a fatal error while running.
*/
func (s *Server) Serve(ln net.Listener, handler http.Handler, certFile, keyFile string) error {
	s.Addr = ln.Addr().String()
	if s.ReadTimeout == 0 {
		s.ReadTimeout = time.Duration(500) * time.Millisecond
	}
	cm, err := NewCIDRMatcher(s.CIDRBlockList)
	if err != nil {
		s.l = &SplitListener{Listener: ln, ReadTimeout: s.ReadTimeout, server: s}
	} else {
		s.l = &SplitListener{Listener: ln, ReadTimeout: s.ReadTimeout, server: s, CIDRMatcher: cm}
	}
	s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			handler.ServeHTTP(w, r)
		} else {
			handler.ServeHTTP(w, r)
		}
	})
	if certFile != "" && keyFile != "" {
		var err error
		tlsConfig := s.Server.TLSConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		}
		tlsConfig.MinVersion = tls.VersionTLS12
		tlsConfig.NextProtos = []string{"h2", "h3", "http/1.1"}
		tlsConfig.SessionTicketsDisabled = true
		tlsConfig.Certificates = make([]tls.Certificate, 1)
		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return errors.New("Can not load X509 key pair")
		}
		if s.CACertFile != "" {
			caCerts, err := os.ReadFile(s.CACertFile)
			if err != nil {
				return fmt.Errorf("failed to read CA certificate file: %w", err)
			}
			caCertPool, err := x509.SystemCertPool()
			if err != nil {
				return fmt.Errorf("failed to create system certificate pool: %w", err)
			}
			if !caCertPool.AppendCertsFromPEM(caCerts) {
				return errors.New("failed to append CA certificate")
			}
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			if s.CRL != nil {
				tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return fmt.Errorf("no client certificat")
					}
					cert := cs.PeerCertificates[0]
					for _, revoked := range s.CRL.RevokedCertificateEntries {
						if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
							return fmt.Errorf(
								"revoked certificat (serial number %s)",
								cert.SerialNumber,
							)
						}
					}
					return nil
				}
			}
		}
		s.Server.TLSConfig = tlsConfig
	}
	s.l.tlsConfig = s.Server.TLSConfig
	return s.Server.Serve(s.l)
}

func (s *Server) ListenAndServeMulti(handler http.Handler) error {
	return s.ListenAndServe(handler, "", "")
}

func (s *Server) ServeMulti(ln net.Listener, handler http.Handler) error {
	return s.Serve(ln, handler, "", "")
}

/*
ListenAndServe is a convenience function that creates a new Server with the specified address, configures it to support both HTTP/1.1 and HTTP/2 (including unencrypted HTTP/2), and starts listening for incoming connections using the provided http.Handler.

It takes an http.Handler to handle incoming HTTP requests, and optional certificate and key files for TLS encryption.
If the certificate and key files are provided and valid, the server will use TLS. Otherwise, it will start without encryption.
*/
func ListenAndServe(addr string, handler http.Handler, certFile, keyFile string) error {
	server := New(addr).WithHTTP1().WithHTTP2()
	server.SetUnencryptedHTTP2(true)
	return server.ListenAndServe(handler, certFile, keyFile)
}

/*
Serve starts the server using the provided net.Listener.

It takes an http.Handler to handle incoming HTTP requests, and optional certificate and key files for TLS encryption.
If the certificate and key files are provided and valid, the server will use TLS. Otherwise, it will start without encryption.

The method returns an error if the server fails to start or encounters a fatal error while running.
*/
func Serve(ln net.Listener, handler http.Handler, certFile, keyFile string) error {
	server := New(ln.Addr().String())
	server.SetHTTP1(true)
	server.SetHTTP2(true)
	server.SetUnencryptedHTTP2(true)
	return server.Serve(ln, handler, certFile, keyFile)
}

/*
	Run starts the server and listens for incoming connections.

It takes an http.Handler to handle incoming HTTP requests, and optional certificate and key files for TLS encryption.
If the certificate and key files are provided and valid, the server will use TLS. Otherwise, it will start without encryption.

The method returns an error if the server fails to start or encounters a fatal error while running.
*/
func (s *Server) Listen(handler http.Handler) error {
	return s.Run(handler, s.ServerCertFile, s.ServerKeyFile)
}

func (s *Server) Run(handler http.Handler, certFile, keyFile string) error {
	var err error = nil
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if s.Logger != nil {
			s.Logger.Printf("[httpmulti] Starting test Web server on <%s>\n", s.Addr)
			if (len(keyFile) > 0) && (len(certFile) > 0) {
				s.Logger.Printf("[httpmulti] with key <%s> and certificate <%s>\n", keyFile, certFile)
			}
		}
		err = s.ListenAndServe(handler, certFile, keyFile)
		if err != nil {
			if s.Logger != nil {
				s.Logger.Printf("[httpmulti] Server error: %v", err)
			}
			quit <- syscall.SIGQUIT
		}
	}()

	switch <-quit {
	case syscall.SIGQUIT:
	default:
		if s.Logger != nil {
			s.Logger.Printf("[httpmulti] Shutting down server...\n")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); (err != nil) && (err != ErrClosedListener) {
			if s.Logger != nil {
				s.Logger.Printf("[httpmulti] Server forced to shutdown: %v\n", err)
			}
			return fmt.Errorf("server forced to shutdown: %v", err)
		}
		if s.Logger != nil {
			s.Logger.Printf("[httpmulti] Server exiting\n")
		}

		if err == http.ErrServerClosed {
			return nil
		}
	}
	return err
}
