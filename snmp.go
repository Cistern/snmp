package snmp

import (
	"bytes"
	"errors"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

// Session represents an SNMP v3 session to a single device.
type Session struct {
	addr           *net.UDPAddr
	conn           *net.UDPConn
	user           []byte
	authPassphrase []byte
	privPassphrase []byte

	engineID    []byte
	engineBoots int32
	engineTime  int32

	authKey []byte
	privKey []byte
	aesIV   int64

	inflight map[int]chan DataType
	lock     sync.Mutex
}

// NewSession creates a new SNMP v3 session using "authPriv" mode with
// SHA authentication and AES encryption.
func NewSession(address, user, authPassphrase, privPassphrase string) (*Session, error) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}

	sess := &Session{
		addr:           addr,
		conn:           conn,
		user:           []byte(user),
		authPassphrase: []byte(authPassphrase),
		privPassphrase: []byte(privPassphrase),
		aesIV:          rand.Int63(),
		inflight:       make(map[int]chan DataType),
	}

	go sess.handleListen()

	return sess, nil
}

func (s *Session) doRequest(data []byte, reqId int, c chan DataType) error {
	_, err := s.conn.WriteTo(data, s.addr)
	if err != nil {
		return err
	}

	s.inflight[reqId] = c
	go func() {
		<-time.After(500 * time.Millisecond) // TODO: make this into a package-level variable
		s.lock.Lock()
		defer s.lock.Unlock()

		// TODO: explain what this is doing
		if c, ok := s.inflight[reqId]; ok {
			// haven't received a response yet
			close(c)
			delete(s.inflight, reqId)
		}
	}()

	return nil
}

// TODO: add comment
func (s *Session) handleListen() {
	b := make([]byte, 65500)

	for {
		n, err := s.conn.Read(b)
		if err != nil {
			continue // TODO: Check if we might get into an infinite loop...
			// What if the socket gets closed?
		}

		decoded, _, err := decode(bytes.NewReader(b[:n]))
		if err != nil {
			continue
		}

		s.lock.Lock()

		// TODO: make this safe
		reqId := int(decoded.(Sequence)[1].(Sequence)[0].(Int))

		// TODO: make this safe
		switch decoded.(Sequence)[3].(type) {
		case String:
			encrypted := []byte(decoded.(Sequence)[3].(String)) // TODO: make this safe

			engineStuff, _, err := decode(bytes.NewReader([]byte(decoded.(Sequence)[2].(String))))
			if err != nil {
				continue
			}

			s.engineBoots = int32(engineStuff.(Sequence)[1].(Int))
			s.engineTime = int32(engineStuff.(Sequence)[2].(Int))

			priv := []byte(engineStuff.(Sequence)[5].(String))

			result, _, err := decode(bytes.NewReader(s.decrypt(encrypted, priv)))

			if err != nil {
				continue
			}

			responseData := result.(Sequence)[2]

			log.Printf("%T", responseData)

			switch responseData.(type) {
			case GetResponse:
				reqId = responseData.(GetResponse).requestID

			case Report:
				reqId = int(responseData.(Report)[0].(Int)) // TODO: ^
			}
		}

		if c, ok := s.inflight[reqId]; ok {
			c <- decoded // TODO: consider a non-blocking send? Think about deadlocks...
			delete(s.inflight, reqId)
		}

		s.lock.Unlock() // TODO: Non-blocking send might be better.
	}

}

// TODO: add comment
func (s *Session) Discover() error {
	reqId := int(rand.Intn(100000))

	encodedEngineData, err := Sequence{
		String(""),
		Int(0),
		Int(0),
		String(""),
		String(""),
		String(""),
	}.Encode()

	if err != nil {
		return err
	}

	discoverySequence, err := Sequence{
		Int(3),
		Sequence{
			Int(reqId),
			Int(65507),
			String("\x04"), // TODO: \x04?
			Int(3),
		},
		String(encodedEngineData),
		Sequence{
			String(""),
			String(""),
			newGetRequest(reqId, []Varbind{}),
		},
	}.Encode()

	if err != nil {
		return err
	}

	var decoded DataType
	var ok bool

	// TODO: make num of retries a package-level variable
	// TODO: turn this into a function?
	for i := 0; i < 3; i++ {
		c := make(chan DataType)
		s.doRequest(discoverySequence, int(reqId), c)

		decoded, ok = <-c
		if ok {
			break
		} else {
			if i == 2 {
				return errors.New("discovery failed")
			}
		}
	}

	engineStuff, _, err := decode(bytes.NewReader([]byte(decoded.(Sequence)[2].(String))))
	if err != nil {
		return err
	}

	s.engineID = []byte(engineStuff.(Sequence)[0].(String))
	s.engineBoots = int32(engineStuff.(Sequence)[1].(Int))
	s.engineTime = int32(engineStuff.(Sequence)[2].(Int))

	s.privKey = passphraseToKey(s.privPassphrase, s.engineID)[:16]
	s.authKey = passphraseToKey(s.authPassphrase, s.engineID)

	return nil
}

func (s *Session) Get(oid ObjectIdentifier) (*GetResponse, error) {
	reqId := int(rand.Int31())

	getReq, err := Sequence{
		String(s.engineID),
		String(""),
		newGetRequest(reqId, []Varbind{NewVarbind(oid, Null)}),
	}.Encode()

	if err != nil {
		return nil, err
	}

	// TODO: turn this all into a function
	encrypted, priv := s.encrypt(getReq)

	packet, err := s.constructPacket(encrypted, priv)
	if err != nil {
		return nil, err
	}

	var decoded DataType
	var ok bool

	for i := 0; i < 3; i++ {
		c := make(chan DataType)
		s.doRequest(packet, int(reqId), c)

		decoded, ok = <-c
		if ok {
			break
		} else {
			if i == 2 {
				return nil, errors.New("timeout")
			}
		}
	}

	encrypted = []byte(decoded.(Sequence)[3].(String))
	engineStuff, _, err := decode(bytes.NewReader([]byte(decoded.(Sequence)[2].(String))))

	if err != nil {
		return nil, err
	}

	s.engineBoots = int32(engineStuff.(Sequence)[1].(Int))
	s.engineTime = int32(engineStuff.(Sequence)[2].(Int))

	priv = []byte(engineStuff.(Sequence)[5].(String))

	result, _, err := decode(bytes.NewReader(s.decrypt(encrypted, priv)))

	getRes, ok := result.(Sequence)[2].(GetResponse)
	if !ok {
		return nil, ErrDecodingType
	}

	return &getRes, nil
}

func (s *Session) GetNext(oid ObjectIdentifier) (*GetResponse, error) {
	reqId := int(rand.Int31())

	getNextReq, err := Sequence{
		String(s.engineID),
		String(""),
		newGetNextRequest(reqId, []Varbind{NewVarbind(oid, Null)}),
	}.Encode()

	if err != nil {
		return nil, err
	}

	// TODO: function this up
	encrypted, priv := s.encrypt(getNextReq)

	packet, err := s.constructPacket(encrypted, priv)
	if err != nil {
		return nil, err
	}

	var decoded DataType
	var ok bool

	for i := 0; i < 3; i++ {
		c := make(chan DataType)
		s.doRequest(packet, int(reqId), c)

		decoded, ok = <-c
		if ok {
			break
		} else {
			if i == 2 {
				return nil, errors.New("timeout")
			}
		}
	}

	encrypted = []byte(decoded.(Sequence)[3].(String))
	engineStuff, _, err := decode(bytes.NewReader([]byte(decoded.(Sequence)[2].(String))))
	if err != nil {
		return nil, err
	}

	s.engineBoots = int32(engineStuff.(Sequence)[1].(Int))
	s.engineTime = int32(engineStuff.(Sequence)[2].(Int))

	priv = []byte(engineStuff.(Sequence)[5].(String))

	result, _, err := decode(bytes.NewReader(s.decrypt(encrypted, priv)))
	getRes, ok := result.(Sequence)[2].(GetResponse)
	if !ok {
		return nil, ErrDecodingType
	}

	return &getRes, nil
}

func (s *Session) constructPacket(encrypted, priv []byte) ([]byte, error) {
	msgId := Int(rand.Int31())

	v3Header, err := Sequence{
		String(s.engineID),
		Int(s.engineBoots),
		Int(s.engineTime),
		String(s.user),
		String(strings.Repeat("\x00", 12)),
		String(priv),
	}.Encode()

	if err != nil {
		return nil, err
	}

	packet, err := Sequence{
		Int(3),
		Sequence{
			msgId,
			Int(65507),
			String("\x07"),
			Int(3),
		},
		String(v3Header),
		String(encrypted),
	}.Encode()

	if err != nil {
		return nil, err
	}

	authParam := s.auth(packet)

	return bytes.Replace(packet, bytes.Repeat([]byte{0}, 12), authParam, 1), nil
}

func (s *Session) Close() error {
	return s.conn.Close()
}
