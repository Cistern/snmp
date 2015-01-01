package snmp

import (
	"net"
)

// A SessionManager listens on a UDP port and manages SNMP sessions.
type SessionManager struct {
	sessions map[string]*Session
	conn     *net.UDPConn
}

// NewSessionManager creates a new SessionManager and starts
// listening on a UDP port.
func NewSessionManager() (*SessionManager, error) {

	// Listen on a socket
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}

	s := &SessionManager{
		sessions: map[string]*Session{},
		conn:     conn,
	}

	go s.handleDatagrams()

	return s, nil
}

// handleDatagrams sends incoming datagrams to the
// corresponding sessions.
func (s *SessionManager) handleDatagrams() error {
	for {
		b := make([]byte, 1500)

		n, addr, err := s.conn.ReadFromUDP(b)
		if err != nil {
			return err
		}

		key := addr.String()

		sess, present := s.sessions[key]
		if !present {
			continue
		}

		sess.inbound <- b[:n]
	}
}

// NewSession creates a new SNMP v3 session using "authPriv" mode with
// SHA authentication and AES encryption.
func (s *SessionManager) NewSession(address, user, authPassphrase, privPassphrase string) (*Session, error) {
	sess, err := newSession(address, user, authPassphrase, privPassphrase)
	if err != nil {
		return nil, err
	}

	sess.conn = s.conn

	s.sessions[sess.addr.String()] = sess

	return sess, nil
}
