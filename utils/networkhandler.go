package utils

import (
	"bytes"
	"encoding/gob"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

type NetworkHandler struct {
	ips        map[int]string // Index -1 is the ip of the coin
	conns      map[int]*connection
	Funcs      *HandlerFuncs
	Chans      *HandlerChans
	sync.Mutex // Use this lock when interacting with conns
	bytesSent  int
	bytesLock  sync.Mutex
}

type connection struct {
	conn net.Conn
	enc  *gob.Encoder
}

func NewNetworkHandler(ips map[int]string, id, n, kappa int, rcfgs RoundConfigs) *NetworkHandler {
	// Create local channels. The handler will forward incoming messages to the correct local
	// channels.
	rbcChans := make(map[int][]chan *Message)          // UROUND -> instance
	abaChans := make(map[int]map[int][]chan *Message)  // UROUND -> round -> instance
	acsChans := make(map[int]chan *Message)            // UROUND
	blaChans := make(map[int]map[int]chan *Message)    // UROUND -> round
	abcChans := make(map[int]chan *Message)            // UROUND
	coinChans := make(map[int]map[int][]chan *Message) // UROUND -> round -> instance
	handlerChans := &HandlerChans{
		rbcChans:  rbcChans,
		abaChans:  abaChans,
		acsChans:  acsChans,
		blaChans:  blaChans,
		abcChans:  abcChans,
		coinChans: coinChans,
		round:     make(map[int]bool),
		rbcLock:   sync.RWMutex{},
		abaLock:   sync.RWMutex{},
		acsLock:   sync.RWMutex{},
		blaLock:   sync.RWMutex{},
		abcLock:   sync.RWMutex{},
		rLock:     sync.RWMutex{},
	}
	handlerChans.updateRound(0, n, kappa)

	conns := make(map[int]*connection)
	handler := &NetworkHandler{
		ips:       ips,
		conns:     conns,
		Chans:     handlerChans,
		bytesSent: 0,
		bytesLock: sync.Mutex{},
	}

	// Create multicast and receive functions for communication with other nodes.
	// Paramater order: UROUND, round, instance, receiver id
	multicast := func(msg *Message, origin Origin, params ...int) {
		//log.Printf("Node %d multicast with %T", id, msg.Payload)
		var p [4]int
		for i, param := range params {
			p[i] = param
		}
		m := &HandlerMessage{
			UROUND:   p[0],
			Round:    p[1],
			Instance: p[2],
			Origin:   origin,
			Payload:  msg,
		}
		//log.Printf("Node %d UROUND %d %d -> %T\n", msg.Sender, m.UROUND, m.Origin, msg.Payload)
		if p[3] != -1 {
			// Send only to one node
			go handler.send(m, p[3], rcfgs[m.UROUND].Async, rcfgs[m.UROUND].Crashed[p[3]])
		} else {
			for i := 0; i < n; i++ {
				go handler.send(m, i, rcfgs[m.UROUND].Async, rcfgs[m.UROUND].Crashed[i])
			}
		}
	}
	// Parameter order: UROUND, round, instance
	receive := func(origin Origin, params ...int) *Message {
		var p [3]int
		for i, param := range params {
			p[i] = param
		}

		// Check if channels for received UROUND exist
		handlerChans.rLock.RLock()
		if !handlerChans.round[p[0]] {
			handlerChans.rLock.RUnlock()
			handlerChans.updateRound(p[0], n, kappa)
		} else {
			handlerChans.rLock.RUnlock()
		}

		switch origin {
		case ABA:
			// Check if there are channels for the current round.
			handlerChans.abaLock.Lock()
			if abaChans[p[0]][p[1]] == nil {
				abaChans[p[0]][p[1]] = make([]chan *Message, n)
				for i := range abaChans[p[0]][p[1]] {
					abaChans[p[0]][p[1]][i] = make(chan *Message, 999)
				}
			}
			handlerChans.abaLock.Unlock()
			handlerChans.abaLock.RLock()
			ch := abaChans[p[0]][p[1]][p[2]]
			if ch == nil {
				log.Printf("%d %d RECEIVING FROM NIL ABA", id, p[0])
			}
			handlerChans.abaLock.RUnlock()
			return <-ch
		case ABC:
			handlerChans.abcLock.RLock()
			ch := abcChans[p[0]]
			if ch == nil {
				log.Printf("%d %d RECEIVING FROM NIL ABC", id, p[0])
			}
			handlerChans.abcLock.RUnlock()
			//log.Printf("Receiving in round %d -- %d", p[0], len(ch))
			return <-ch
		case ACS:
			handlerChans.acsLock.RLock()
			ch := acsChans[p[0]]
			if ch == nil {
				log.Printf("%d %d RECEIVING FROM NIL ACS", id, p[0])
			}
			handlerChans.acsLock.RUnlock()
			return <-ch
		case BLA:
			handlerChans.blaLock.RLock()
			ch := blaChans[p[0]][p[1]]
			if ch == nil {
				log.Printf("%d %d RECEIVING FROM NIL BLA", id, p[0])
			}
			handlerChans.blaLock.RUnlock()
			return <-ch
		case RBC:
			handlerChans.rbcLock.RLock()
			ch := rbcChans[p[0]][p[2]]
			if ch == nil {
				log.Printf("%d %d RECEIVING FROM NIL RBC", id, p[0])
			}
			handlerChans.rbcLock.RUnlock()
			return <-ch
		case COIN:
			handlerChans.coinLock.Lock()
			if coinChans[p[0]][p[1]] == nil {
				coinChans[p[0]][p[1]] = make([]chan *Message, n)
				for i := range coinChans[p[0]][p[1]] {
					coinChans[p[0]][p[1]][i] = make(chan *Message, 999)
				}
			}
			handlerChans.coinLock.Unlock()
			handlerChans.coinLock.RLock()
			ch := coinChans[p[0]][p[1]][p[2]]
			if ch == nil {
				log.Printf("%d %d RECEIVING FROM NIL COIN", id, p[0])
			}
			handlerChans.coinLock.RUnlock()
			return <-ch
		}
		return nil
	}

	// Create multicast and receive functions for the created channels.
	rbcMulticast := func(msg *Message, UROUND, instance int) {
		go multicast(msg, RBC, UROUND, 0, instance, -1)
	}
	rbcReceive := func(UROUND, instance int) *Message {
		return receive(RBC, UROUND, UROUND, instance)
	}

	abaMulticast := func(msg *Message, UROUND, round, instance int) {
		go multicast(msg, ABA, UROUND, round, instance, -1)
	}
	abaReceive := func(UROUND, round, instance int) *Message {
		return receive(ABA, UROUND, round, instance)
	}

	blaMulticast := func(msg *Message, UROUND, round, receiver int) {
		go multicast(msg, BLA, UROUND, round, 0, receiver)
	}
	blaReceive := func(UROUND, round int) *Message {
		return receive(BLA, UROUND, round)
	}

	acsMulticast := func(msg *Message, UROUND int) {
		go multicast(msg, ACS, UROUND, 0, 0, -1)
	}
	acsReceive := func(UROUND int) *Message {
		return receive(ACS, UROUND)
	}

	abcMulticast := func(msg *Message, UROUND int, receiver int) {
		go multicast(msg, ABC, UROUND, 0, 0, receiver)
	}
	abcReceive := func(UROUND int) *Message {
		return receive(ABC, UROUND)
	}

	var coinConn *gob.Encoder
	var coinConnLock sync.Mutex
	coinCall := func(msg *CoinRequest) byte {
		coinConnLock.Lock()

		if coinConn == nil {
			// Create a new connection and encoder
			c, err := net.Dial("tcp", ips[-1])
			for err != nil {
				time.Sleep(200 * time.Millisecond)
				c, err = net.Dial("tcp", ips[-1])
			}
			enc := gob.NewEncoder(c)
			coinConn = enc
		}
		coinConnLock.Unlock()
		err := coinConn.Encode(msg)
		if err != nil {
			log.Printf("Node %d failed to send message to coin", id)
		}
		answer := receive(COIN, msg.UROUND, msg.Round, msg.Instance)
		return byte(answer.Sender)
	}

	// Receiver that assigns incoming messages to the correct channels
	receiver := func() {
		port := strings.Split(ips[id], ":")[1]
		addr := "0.0.0.0:" + port
		l, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("Node %d was unable to start listener. %s", id, err)
		}
		// log.Printf("Starting receiver for node %d", id)
		defer l.Close()

		for {
			c, err := l.Accept()
			if err != nil {
				//log.Printf("Node %d got err while establishing connection. %s", id, err)
				continue
			}
			go handlerChans.listener(id, n, kappa, c)
		}
	}

	handlerFuncs := &HandlerFuncs{
		RBCmulticast: rbcMulticast,
		RBCreceive:   rbcReceive,
		ABAmulticast: abaMulticast,
		ABAreceive:   abaReceive,
		BLAmulticast: blaMulticast,
		BLAreceive:   blaReceive,
		ACSmulticast: acsMulticast,
		ACSreceive:   acsReceive,
		ABCmulticast: abcMulticast,
		ABCreceive:   abcReceive,
		CoinCall:     coinCall,
		Receiver:     receiver,
	}

	handler.Funcs = handlerFuncs

	return handler
}

func (h *NetworkHandler) BytesSent() int {
	h.bytesLock.Lock()
	defer h.bytesLock.Unlock()
	return h.bytesSent
}

func (h *NetworkHandler) incrementBytes(n int) {
	h.bytesLock.Lock()
	defer h.bytesLock.Unlock()
	h.bytesSent += n
}

func (h *NetworkHandler) send(msg *HandlerMessage, i int, delay bool, crashed bool) {
	if delay {
		r := rand.Intn(300) + 50
		time.Sleep(time.Duration(r) * time.Millisecond)
	}
	if crashed {
		return
	}

	h.Lock()
	defer h.Unlock()

	if h.conns[i] == nil {
		// Create a new connection and encoder
		c, err := net.Dial("tcp", h.ips[i])
		for err != nil {
			time.Sleep(10 * time.Millisecond)
			c, err = net.Dial("tcp", h.ips[i])
		}
		connection := &connection{
			conn: c,
			enc:  gob.NewEncoder(c),
		}
		h.conns[i] = connection
	}
	go func() {
		buf := new(bytes.Buffer)
		e := gob.NewEncoder(buf)
		e.Encode(msg)
		h.incrementBytes(buf.Len())
	}()
	err := h.conns[i].enc.Encode(msg)
	if err != nil {
		log.Printf("Node %d failed to send message to %d", msg.Payload.Sender, i)
	}
}
