package utils

type Message struct {
	Sender  int
	Payload interface{}
}

type Origin int

const (
	ABA Origin = iota
	BLA
	RBC
	ACS
	ABC
)