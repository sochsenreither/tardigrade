package utils

import "github.com/niclabs/tcrsa"

type Message struct {
	Sender  int
	Payload interface{}
}

type CoinRequest struct {
	Sender   int
	UROUND   int
	Round    int
	Sig      *tcrsa.SigShare
	Answer   chan byte
	Instance int
}

type Origin int

const (
	ABA Origin = iota
	BLA
	RBC
	ACS
	ABC
)