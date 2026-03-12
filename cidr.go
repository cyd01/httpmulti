package httpmulti

import (
	"fmt"
	"net"
	"net/netip"
)

// CIDRMatcher stocke les préfixes autorisés
type CIDRMatcher struct {
	prefixes []netip.Prefix
}

// NewCIDRMatcher parse une liste de CIDR une seule fois
func NewCIDRMatcher(cidrs []string) (*CIDRMatcher, error) {
	m := &CIDRMatcher{
		prefixes: make([]netip.Prefix, 0, len(cidrs)),
	}

	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("CIDR invalide %q: %w", c, err)
		}
		m.prefixes = append(m.prefixes, p)
	}

	return m, nil
}

// MatchAddr teste si une IP appartient à un des CIDR
func (m *CIDRMatcher) MatchAddr(addr netip.Addr) bool {
	for _, p := range m.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// MatchConn teste directement une connexion net.Conn
func (m *CIDRMatcher) MatchConn(conn net.Conn) bool {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return false
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}

	return m.MatchAddr(addr)
}
