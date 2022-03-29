package utils

import (
	"encoding/gob"
	"log"
	"net"
	"sync"
)

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
	CoinCall     func(msg *CoinRequest) byte
	Receiver     func()
}

type HandlerChans struct {
	rbcChans  map[int][]chan *Message         // UROUND -> instance - > channel
	abaChans  map[int]map[int][]chan *Message // UROUND -> round -> instance -> channel
	acsChans  map[int]chan *Message           // UROUND -> channel
	blaChans  map[int]map[int]chan *Message   // UROUND -> round -> channel
	abcChans  map[int]chan *Message           // UROUND -> channel
	coinChans map[int]map[int][]chan *Message // UROUND -> round -> instance -> channel
	round     map[int]bool                    // Maximum round for which the channels are set
	rbcLock   sync.RWMutex
	abaLock   sync.RWMutex
	acsLock   sync.RWMutex
	blaLock   sync.RWMutex
	abcLock   sync.RWMutex
	coinLock  sync.RWMutex
	rLock     sync.RWMutex
}

// Creates channels for UROUND if there aren't any already.
func (h *HandlerChans) updateRound(UROUND, n, kappa int) {
	updatedRound := 1
	h.rLock.Lock()
	defer h.rLock.Unlock()
	if h.round[UROUND] {
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
		h.abaChans[i] = make(map[int][]chan *Message)
		for j := 0; j < 10; j++ {
			h.abaChans[i][j] = make([]chan *Message, n)
			for k := range h.abaChans[i][j] {
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

	// Update coin
	h.coinLock.Lock()
	if h.coinChans == nil {
		h.coinLock.Unlock()
		return
	}
	for i := UROUND; i < UROUND+updatedRound; i++ {
		h.coinChans[i] = make(map[int][]chan *Message)
		for j := 0; j < 10; j++ {
			h.coinChans[i][j] = make([]chan *Message, n)
			for k := range h.coinChans[i][j] {
				h.coinChans[i][j][k] = make(chan *Message, 999)
			}
		}
	}
	h.coinLock.Unlock()
}

func (h *HandlerChans) listener(id, n, kappa int, c net.Conn) {
	dec := gob.NewDecoder(c)

	for {
		msg := new(HandlerMessage)
		err := dec.Decode(msg)

		if err != nil {
			log.Printf("Node %d got err while establishing connection. %s", id, err)
			continue
		}

		h.rLock.RLock()
		if !h.round[msg.UROUND] {
			h.rLock.RUnlock()
			h.updateRound(msg.UROUND, n, kappa)
		} else {
			h.rLock.RUnlock()
		}

		switch msg.Origin {
		case ABA:
			// Check if there are channels for the current round.
			h.abaLock.Lock()
			if h.abaChans[msg.UROUND][msg.Round] == nil {
				h.abaChans[msg.UROUND][msg.Round] = make([]chan *Message, n)
				for i := range h.abaChans[msg.UROUND][msg.Round] {
					h.abaChans[msg.UROUND][msg.Round][i] = make(chan *Message, 999)
				}
			}
			h.abaLock.Unlock()
			h.abaLock.RLock()
			h.abaChans[msg.UROUND][msg.Round][msg.Instance] <- msg.Payload
			h.abaLock.RUnlock()
		case ABC:
			h.abcLock.RLock()
			h.abcChans[msg.UROUND] <- msg.Payload
			h.abcLock.RUnlock()
		case ACS:
			h.acsLock.RLock()
			h.acsChans[msg.UROUND] <- msg.Payload
			h.acsLock.RUnlock()
		case BLA:
			h.blaLock.RLock()
			h.blaChans[msg.UROUND][msg.Round] <- msg.Payload
			h.blaLock.RUnlock()
		case RBC:
			h.rbcLock.RLock()
			h.rbcChans[msg.UROUND][msg.Instance] <- msg.Payload
			h.rbcLock.RUnlock()
		case COIN:
			// Check if there are channels for the current round.
			h.coinLock.Lock()
			if h.coinChans[msg.UROUND][msg.Round] == nil {
				h.coinChans[msg.UROUND][msg.Round] = make([]chan *Message, n)
				for i := range h.coinChans[msg.UROUND][msg.Round] {
					h.coinChans[msg.UROUND][msg.Round][i] = make(chan *Message, 999)
				}
			}
			h.coinLock.Unlock()
			h.coinLock.RLock()
			h.coinChans[msg.UROUND][msg.Round][msg.Instance] <- msg.Payload
			h.coinLock.RUnlock()
		}
	}
}
