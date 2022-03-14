package utils

import (
	// "log"
	"log"
	"sync"
)

// TODO: ACS hängt ständig bug?

type Handler struct {
	nodes map[int]chan *HandlerMessage
	Funcs *HandlerFuncs
	Chans *HandlerChans
}

type HandlerFuncs struct {
	RBCmulticast func(msg *Message, UROUND, instance int)
	RBCreceive   func(UROUND, instance int) *Message
	ABAmulticast func(msg *Message, UROUND, round, instance int)
	ABAreceive   func(UROUND, round, instance int) *Message
	BLAmulticast func(msg *Message, UROUND, round, receiver int)
	BLAreceive   func(UROUND, round int) *Message
	ACSmulticast func(msg *Message, UROUND int)
	ACSreceive   func(UROUND int) *Message
	ABCmulticast func(msg *Message, UROUND int, receiver int)
	ABCreceive   func(UROUND int) *Message
}

type HandlerMessage struct {
	UROUND   int
	Round    int
	Instance int
	origin   Origin
	Payload  *Message
}

type HandlerChans struct {
	rbcChans map[int][]chan *Message         // UROUND -> instance - > channel
	abaChans map[int]map[int][]chan *Message // UROUND -> round -> instance -> channel
	acsChans map[int]chan *Message           // UROUND -> channel
	blaChans map[int]map[int]chan *Message   // UROUND -> round -> channel
	abcChans map[int]chan *Message           // UROUND -> channel
	round    map[int]bool                    // Maximum round for which the channels are set
	rbcLock  sync.RWMutex
	abaLock  sync.RWMutex
	acsLock  sync.RWMutex
	blaLock  sync.RWMutex
	abcLock  sync.RWMutex
	rLock    sync.RWMutex
}

func NewHandler(nodes map[int]chan *HandlerMessage, id, n, kappa int) *Handler {
	// Create local channels. The handler will forward incoming messages to the correct local
	// channels.
	rbcChans := make(map[int][]chan *Message)         // UROUND -> instance
	abaChans := make(map[int]map[int][]chan *Message) // UROUND -> round -> instance
	acsChans := make(map[int]chan *Message)           // UROUND
	blaChans := make(map[int]map[int]chan *Message)   // UROUND -> round
	abcChans := make(map[int]chan *Message)           // UROUND
	handlerChans := &HandlerChans{
		rbcChans: rbcChans,
		abaChans: abaChans,
		acsChans: acsChans,
		blaChans: blaChans,
		abcChans: abcChans,
		round:    make(map[int]bool),
		rbcLock:  sync.RWMutex{},
		abaLock:  sync.RWMutex{},
		acsLock:  sync.RWMutex{},
		blaLock:  sync.RWMutex{},
		abcLock:  sync.RWMutex{},
		rLock:    sync.RWMutex{},
	}
	handlerChans.updateRound(0, n, kappa)

	// Create multicast and receive functions for communication with other nodes.
	// Paramater order: UROUND, round, instance, receiver id
	multicast := func(msg *Message, origin Origin, params ...int) {
		var p [4]int
		for i, param := range params {
			p[i] = param
		}
		m := &HandlerMessage{
			UROUND:   p[0],
			Round:    p[1],
			Instance: p[2],
			origin:   origin,
			Payload:  msg,
		}
		// log.Printf("Node %d UROUND %d %d -> %T", msg.Sender, m.UROUND, m.origin, msg.Payload)
		if p[3] != -1 {
			// Send only to one node
			nodes[p[3]] <- m
		} else {
			for i := 0; i < n; i++ {
				nodes[i] <- m
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
			log.Printf("Receive updating rounds for UROUND %d", p[0])
			handlerChans.updateRound(p[0], n, kappa)
		} else {
			handlerChans.rLock.RUnlock()
		}

		switch origin {
		case ABA:
			// Check if there are channels for the current round.
			handlerChans.abaLock.RLock()
			if abaChans[p[0]][p[1]] == nil {
				handlerChans.abaLock.RUnlock()
				handlerChans.abaLock.Lock()
				abaChans[p[0]][p[1]] = make([]chan *Message, n)
				for i := range abaChans[p[0]][p[1]] {
					abaChans[p[0]][p[1]][i] = make(chan *Message, 99999)
				}
				handlerChans.abaLock.Unlock()
			} else {
				handlerChans.abaLock.RUnlock()
			}
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
		}
		return nil
	}

	// Create multicast and receive functions for the created channels.
	// TODO: make multicast non-blocking
	rbcMulticast := func(msg *Message, UROUND, instance int) {
		multicast(msg, RBC, UROUND, 0, instance, -1)
	}
	rbcReceive := func(UROUND, instance int) *Message {
		return receive(RBC, UROUND, UROUND, instance)
	}

	abaMulticast := func(msg *Message, UROUND, round, instance int) {
		multicast(msg, ABA, UROUND, round, instance, -1)
	}
	abaReceive := func(UROUND, round, instance int) *Message {
		return receive(ABA, UROUND, round, instance)
	}

	blaMulticast := func(msg *Message, UROUND, round, receiver int) {
		multicast(msg, BLA, UROUND, round, 0, receiver)
	}
	blaReceive := func(UROUND, round int) *Message {
		return receive(BLA, UROUND, round)
	}

	acsMulticast := func(msg *Message, UROUND int) {
		multicast(msg, ACS, UROUND, 0, 0, -1)
	}
	acsReceive := func(UROUND int) *Message {
		return receive(ACS, UROUND)
	}

	abcMulticast := func(msg *Message, UROUND int, receiver int) {
		multicast(msg, ABC, UROUND, 0, 0, receiver)
	}
	abcReceive := func(UROUND int) *Message {
		return receive(ABC, UROUND)
	}

	// Receiver that assigns incoming messages to the correct channels
	receiver := func() {
		for {
			msg := <-nodes[id]

			// Check if channels for received UROUND exist
			handlerChans.rLock.RLock()
			if !handlerChans.round[msg.UROUND] {
				handlerChans.rLock.RUnlock()
				log.Printf("Receiver updating rounds for UROUND %d", msg.UROUND)
				handlerChans.updateRound(msg.UROUND, n, kappa)
			} else {

				handlerChans.rLock.RUnlock()
			}

			switch msg.origin {
			case ABA:
				// TODO: Test this (set expected round duration to 1)
				// Check if there are channels for the current round.
				handlerChans.abaLock.RLock()
				if abaChans[msg.UROUND][msg.Round] == nil {
					handlerChans.abaLock.RUnlock()
					handlerChans.abaLock.Lock()
					abaChans[msg.UROUND][msg.Round] = make([]chan *Message, n)
					for i := range abaChans[msg.UROUND][msg.Round] {
						abaChans[msg.UROUND][msg.Round][i] = make(chan *Message, 99999)
					}
					handlerChans.abaLock.Unlock()
				} else {
					handlerChans.abaLock.RUnlock()
				}
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
			}
		}
	}
	go receiver()

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
	}

	handler := &Handler{
		nodes: nodes,
		Funcs: handlerFuncs,
		Chans: handlerChans,
	}

	return handler
}

// TODO: description
func (h *HandlerChans) updateRound(UROUND, n, kappa int) {
	updatedRound := 1
	h.rLock.Lock()
	defer h.rLock.Unlock()
	if h.round[UROUND] {
		log.Printf("Aborting UROUND %d", UROUND)
		return
	}
	h.round[UROUND] = true

	// Update rbc
	h.rbcLock.Lock()
	for i := UROUND; i < UROUND+updatedRound; i++ {
		h.rbcChans[i] = make([]chan *Message, n)
		for j := 0; j < n; j++ {
			h.rbcChans[i][j] = make(chan *Message, 999)
		}
	}
	h.rbcLock.Unlock()

	// Update aba. aba runs in expected constant round times. 10 rounds should be enough, but it is
	// possible that it runs forever. Hence we need to check in the receiver functions if the
	// current round exists.
	h.abaLock.Lock()
	for i := UROUND; i < UROUND+updatedRound; i++ {
		if h.abaChans[i] != nil {
			log.Printf("h.abaChans[i] != nil")
		}
		h.abaChans[i] = make(map[int][]chan *Message)
		for j := 0; j < 10; j++ {
			if h.abaChans[i][j] != nil {
				log.Printf("h.abaChans[i][j] != nil")
			}
			h.abaChans[i][j] = make([]chan *Message, n)
			for k := range h.abaChans[i][j] {
				if h.abaChans[i][j][k] != nil {
					log.Printf("h.abaChans[i][j][k] != nil")
				}
				h.abaChans[i][j][k] = make(chan *Message, 999)
			}
		}
	}
	h.abaLock.Unlock()

	// Update acs
	h.acsLock.Lock()
	for i := UROUND; i < UROUND+updatedRound; i++ {
		h.acsChans[i] = make(chan *Message, 999)
	}
	h.acsLock.Unlock()

	// Update bla. bla will run for kappa rounds.
	h.blaLock.Lock()
	for i := UROUND; i < UROUND+updatedRound; i++ {
		h.blaChans[i] = make(map[int]chan *Message)
		for j := 0; j < kappa; j++ {
			h.blaChans[i][j] = make(chan *Message, 999)
		}
	}
	h.blaLock.Unlock()

	// Update abc
	h.abcLock.Lock()
	for i := UROUND; i < UROUND+updatedRound; i++ {
		h.abcChans[i] = make(chan *Message, 999)
	}
	h.abcLock.Unlock()
}
