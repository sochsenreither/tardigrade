package utils

import "github.com/niclabs/tcrsa"

type Message struct {
	Sender  int
	Payload interface{}
}

type HandlerMessage struct {
	UROUND   int
	Round    int
	Instance int
	Origin   Origin
	Payload  *Message
}

type CoinRequest struct {
	Sender      int
	UROUND      int
	Round       int
	Sig         *tcrsa.SigShare
	AnswerLocal chan byte
	Instance    int
}

type CoinAnswer struct {
}

type Origin int

const (
	ABA Origin = iota
	BLA
	RBC
	ACS
	ABC
	COIN
)
