package utils

import (
	"bytes"
	"encoding/gob"
	"log"
	"net"
	"sync"
	"time"
)

// TODO: set deadline for connection?

type NetworkHandler struct {
	ips    map[int]string // Index -1 is the ip of the coin
	Funcs    *HandlerFuncs
	Chans    *HandlerChans
}

func NewNetworkHandler(ips map[int]string, id, n, kappa int) *NetworkHandler {
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
		//log.Printf("Node %d UROUND %d %d -> %T", msg.Sender, m.UROUND, m.Origin, msg.Payload)
		if p[3] != -1 {
			// Send only to one node
			send(m, ips[p[3]])
		} else {
			for i := 0; i < n; i++ {
				send(m, ips[i])
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

	coinCall := func(msg *CoinRequest) (byte, error) {
		coinIP := ips[-1]
		// Send coinrequest
		buf := new(bytes.Buffer)
		enc := gob.NewEncoder(buf)
		err := enc.Encode(msg)
		if err != nil {
			log.Printf("Encoding of coin request failed for node %d", msg.Sender)
			// TODO: return error instead of value
			return 1, err
		}
		c, err := net.Dial("tcp", coinIP)
		for err != nil {
			time.Sleep(200 * time.Millisecond)
			c, err = net.Dial("tcp", coinIP)
		}
		c.Write(buf.Bytes())
		defer c.Close()

		// Wait for answer
		answer := receive(COIN, msg.UROUND, msg.Round, msg.Instance)

		return byte(answer.Sender), nil
	}

	// Receiver that assigns incoming messages to the correct channels
	receiver := func() {
		log.Printf("Starting receiver for node %d", id)
		l, err := net.Listen("tcp", ips[id])
		if err != nil {
			log.Fatalf("Node %d was unable to start listener. %s", id, err)
		}
		defer l.Close()

		for {
			conn, err := l.Accept()
			if err != nil {
				log.Printf("Node %d got err while establishing connection. %s", id, err)
				continue
			}
			go func(c net.Conn) {
				// TODO: size
				data := make([]byte, 100000)
				//start := time.Now()
				conn.Read(data)
				conn.Close()
				//end := time.Since(start)
				msg, _, err := decode(data)
				//log.Printf("Node %d %s to read from tcp - %d - %T", id, end, b, msg.Payload.Payload)
				if err != nil {
					log.Printf("Node %d was unable to decode received data", id)
					return
				}
				// log.Printf("Node %d got %T from %d", id, msg.Payload.Payload, msg.Payload.Sender)

				// Check if channels for received UROUND exist
				handlerChans.rLock.RLock()
				if !handlerChans.round[msg.UROUND] {
					handlerChans.rLock.RUnlock()
					handlerChans.updateRound(msg.UROUND, n, kappa)
				} else {

					handlerChans.rLock.RUnlock()
				}

				switch msg.Origin {
				case ABA:
					// Check if there are channels for the current round.
					handlerChans.abaLock.Lock()
					if abaChans[msg.UROUND][msg.Round] == nil {
						abaChans[msg.UROUND][msg.Round] = make([]chan *Message, n)
						for i := range abaChans[msg.UROUND][msg.Round] {
							abaChans[msg.UROUND][msg.Round][i] = make(chan *Message, 999)
						}
					}
					handlerChans.abaLock.Unlock()
					handlerChans.abaLock.RLock()
					if abaChans[msg.UROUND][msg.Round][msg.Instance] == nil {
						log.Printf("%d %d SENDING TO NIL CHAN ABA", id, msg.UROUND)
					}
					abaChans[msg.UROUND][msg.Round][msg.Instance] <- msg.Payload
					handlerChans.abaLock.RUnlock()
				case ABC:
					handlerChans.abcLock.RLock()
					if abcChans[msg.UROUND] == nil {
						log.Printf("%d %d SENDING TO NIL CHAN ABC", id, msg.UROUND)
					}
					abcChans[msg.UROUND] <- msg.Payload
					// log.Printf("RECEIVER: Receiving in round %d from %d. SIZE: %d", msg.UROUND, msg.Payload.Sender, len(abcChans[msg.UROUND]))
					handlerChans.abcLock.RUnlock()
				case ACS:
					handlerChans.acsLock.RLock()
					if acsChans[msg.UROUND] == nil {
						log.Printf("%d %d SENDING TO NIL CHAN ACS", id, msg.UROUND)
					}
					acsChans[msg.UROUND] <- msg.Payload
					handlerChans.acsLock.RUnlock()
				case BLA:
					handlerChans.blaLock.RLock()
					if blaChans[msg.UROUND][msg.Round] == nil {
						log.Printf("%d %d SENDING TO NIL CHAN BLA", id, msg.UROUND)
					}
					//log.Printf("UROUND %d r %d    <- %d", msg.UROUND, msg.Round, msg.Payload.Sender)
					blaChans[msg.UROUND][msg.Round] <- msg.Payload
					handlerChans.blaLock.RUnlock()
				case RBC:
					handlerChans.rbcLock.RLock()
					if rbcChans[msg.UROUND][msg.Instance] == nil {
						log.Printf("%d %d SENDING TO NIL CHAN RBC", id, msg.UROUND)
					}
					rbcChans[msg.UROUND][msg.Instance] <- msg.Payload
					handlerChans.rbcLock.RUnlock()
				case COIN:
					// Check if there are channels for the current round.
					handlerChans.coinLock.Lock()
					if coinChans[msg.UROUND][msg.Round] == nil {
						coinChans[msg.UROUND][msg.Round] = make([]chan *Message, n)
						for i := range coinChans[msg.UROUND][msg.Round] {
							coinChans[msg.UROUND][msg.Round][i] = make(chan *Message, 999)
						}
					}
					handlerChans.coinLock.Unlock()
					handlerChans.coinLock.RLock()
					if coinChans[msg.UROUND][msg.Round][msg.Instance] == nil {
						log.Printf("%d %d SENDING TO NIL CHAN COIN", id, msg.UROUND)
					}
					coinChans[msg.UROUND][msg.Round][msg.Instance] <- msg.Payload
					handlerChans.coinLock.RUnlock()
				}
			}(conn)

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

	handler := &NetworkHandler{
		ips: ips,
		Funcs: handlerFuncs,
		Chans: handlerChans,
	}

	return handler
}

func send(msg *HandlerMessage, ip string) error {
	buf, err := encode(msg)
	if err != nil {
		log.Printf("Node %d failed to encode message for %s", msg.Payload.Sender, ip)
		return err
	}
	c, err := net.Dial("tcp", ip)
	for err != nil {
		//log.Printf("Node %d waiting for turn...", msg.Payload.Sender)
		time.Sleep(200 * time.Millisecond)
		c, err = net.Dial("tcp", ip)
	}
	_, err = c.Write(buf.Bytes())
	if err != nil {
		log.Printf("Node %d failed to send message to %s", msg.Payload.Sender, ip)
		c.Close()
		return err
	}
	//log.Printf("%d ---%T---> %s", msg.Payload.Sender, msg.Payload.Payload, ip)
	c.Close()
	return nil
}

func encode(msg *HandlerMessage) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(msg)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func decode(data []byte) (*HandlerMessage, int, error) {
	buf := bytes.NewBuffer(data)
	msg := new(HandlerMessage)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(msg)
	if err != nil {
		return nil, 0, err
	}
	return msg, buf.Len(), nil
}
