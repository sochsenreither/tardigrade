package broadcast

import (
	"crypto"
	"crypto/sha256"

	//"log"
	"strconv"

	"github.com/niclabs/tcrsa"
	"github.com/sochsenreither/upgrade/utils"
)

// TODO:
// - hash length is hardcoded to 32 for now

type ReliableBroadcast struct {
	n         int                      // Number of nodes
	nodeId    int                      // Id of node
	t         int                      // Number of maximum faulty nodes
	tk        int                      // Threshold for distinct committee messages
	senderId  int                      // Id of sender
	committee map[int]bool             // List of committee members
	value     *utils.BlockShare        // Input value of the sender
	out       chan *utils.BlockShare   // Output channel
	Sig       *Signature               // Personal signature and keymeta
	multicast func(msg *utils.Message) // Function for multicasting messages
	receive   func() *utils.Message    // Blocking function for receiving messages
}

type Signature struct {
	SigShare *tcrsa.SigShare // Signature on node index signed by the dealer
	KeyMeta  *tcrsa.KeyMeta  // Contains public keys to verify signatures
}

// Struct representing a message for Bracha's asynchronous reliable broadcast protocol
type BMessage struct {
	sender int
	status string // This can be be either "VAL", "ECHO", or "READY"
	value  [32]byte
}

// Struct representing a message for the committee based reliable broadcast protocol
type CMessage struct {
	sender int
	value  *utils.BlockShare
	hash   [32]byte
	proof  *tcrsa.SigShare // sigShare on the nodeId as proof that the sender is in the committee
}

// Struct repesenting a value send from the sender to the committee
type SMessage struct {
	sender int
	value  *utils.BlockShare
}

type ReliableBroadcastConfig struct {
	N        int
	NodeId   int
	T        int
	Kappa    int
	Epsilon  int
	SenderId int
	Round    int
}

func NewReliableBroadcast(cfg *ReliableBroadcastConfig, committee map[int]bool, out chan *utils.BlockShare, sig *Signature, multicastFunc func(nodeId, instance, round int, msg *utils.Message), receiveFunc func(nodeId, instance, round int) *utils.Message) *ReliableBroadcast {
	tk := (((1 - cfg.Epsilon) * cfg.Kappa * cfg.T) / cfg.N)
	multicast := func(msg *utils.Message) {
		multicastFunc(cfg.NodeId, cfg.SenderId, cfg.Round, msg)
	}
	receive := func() *utils.Message {
		return receiveFunc(cfg.NodeId, cfg.SenderId, cfg.Round)
	}
	rbc := &ReliableBroadcast{
		n:         cfg.N,
		nodeId:    cfg.NodeId,
		t:         cfg.T,
		tk:        tk,
		senderId:  cfg.SenderId,
		committee: committee,
		value:     nil,
		out:       out,
		Sig:       sig,
		multicast: multicast,
		receive:   receive,
	}
	return rbc
}

func (rbc *ReliableBroadcast) Run() {
	// READY message was already sent
	ready := false
	// Received value from sender
	senderSent := false
	// Initial VAL message from sender was sent
	initialVal := false
	broadcastDone := false
	// Keep track of received messages. Maps hash(val) -> nodeId
	echoReceived := make(map[[32]byte]map[int]bool)
	readyReceived := make(map[[32]byte]map[int]bool)
	committeeReceived := make(map[[32]byte]map[int]bool)
	// Value received after running Bracha's broadcast
	var broadcastValue [32]byte
	// Value received from Sender
	var senderValue *utils.BlockShare

	if rbc.isSender() {
		rbc.multicastToCommittee()
		rbc.multicastVal()
	}

	for {
		if senderSent && broadcastDone && rbc.committee[rbc.nodeId] {
			rbc.multicastCommitteeMessage(senderValue, broadcastValue)
		}
		mes := rbc.receive()
		switch m := mes.Payload.(type) {
		case *BMessage:
			if broadcastDone {
				break
			}
			switch m.status {
			case "VAL":
				rbc.handleVal(m, &initialVal)
			case "ECHO":
				rbc.handleEcho(m, echoReceived, &ready)
			case "READY":
				rbc.handleReady(m, readyReceived, &ready, &broadcastDone, &broadcastValue)
			}
		case *CMessage:
			if rbc.isValidCommitteeMessage(m) {
				if broadcastDone && rbc.committee[rbc.nodeId] {
					rbc.multicastCommitteeMessage(m.value, broadcastValue)
				}
				if rbc.handleCommitteeMessage(m, committeeReceived) {
					return
				}
			}
		case *SMessage:
			senderSent = true
			senderValue = m.value
		}
	}
}

// isSender returns if a node is the sender.
func (rbc *ReliableBroadcast) isSender() bool {
	return rbc.nodeId == rbc.senderId
}

// SetValue sets a given value for the sender.
func (rbc *ReliableBroadcast) SetValue(value *utils.BlockShare) {
	rbc.value = value
}

// handleVal sends an ECHO message for a given VAL message
func (rbc *ReliableBroadcast) handleVal(m *BMessage, initialVal *bool) {
	if !*initialVal {
		*initialVal = true
		// log.Printf("%d received value from %d", rbc.nodeId, m.sender)
		rbc.multicastEcho(m)
	}
}

// handleEcho saves received ECHO messages and if ECHO messages from n-t distinct nodes are
// received, a READY message will be multicasted.
func (rbc *ReliableBroadcast) handleEcho(m *BMessage, echoReceived map[[32]byte]map[int]bool, ready *bool) {
	// log.Printf("%d received ECHO from %d", rbc.nodeId, m.sender)
	hash := sha256.Sum256(m.value[:])
	if echoReceived[hash] == nil {
		echoReceived[hash] = make(map[int]bool)
	}
	echoReceived[hash][m.sender] = true

	// Check if there are enough ECHO messages on the same value.
	if len(echoReceived[hash]) >= rbc.n-rbc.t && !*ready {
		// log.Printf("%d received enough ECHOs. Sending READY..", rbc.nodeId)
		*ready = true
		rbc.multicastReady(m)
	}
}

// handleReady saved received READY messages and if READY messages from t+1 distinct nodes are
// received, a READY will be multicasted. If n-t READY messages on some value v* are received,
// output v*.
func (rbc *ReliableBroadcast) handleReady(m *BMessage, readyMap map[[32]byte]map[int]bool, ready, broadcastDone *bool, broadcastValue *[32]byte) {
	// log.Printf("%d received READY from %d", rbc.nodeId, m.sender)
	hash := sha256.Sum256(m.value[:])
	if readyMap[hash] == nil {
		readyMap[hash] = make(map[int]bool)
	}
	readyMap[hash][m.sender] = true

	// Check if there are enough READY messages on the same value.
	if len(readyMap[hash]) >= rbc.t+1 && !*ready {
		// log.Printf("%d received %d READY messages. Sending READY..", rbc.nodeId, len(readyMap[hash]))
		*ready = true
		rbc.multicastReady(m)
	}

	// If enough READY messages on the same value v* are received, output v*.
	if len(readyMap[hash]) >= rbc.n-rbc.t {
		// log.Printf("%d received %d READY messages. Outputting..", rbc.nodeId, len(readyMap[hash]))
		*broadcastDone = true
		*broadcastValue = m.value
	}
}

// handleCommitteeMessage saved received messages from committee members. If enough messages are
// received, it will return true in so the protocol can terminate.
func (rbc *ReliableBroadcast) handleCommitteeMessage(m *CMessage, committeeReceived map[[32]byte]map[int]bool) bool {
	if committeeReceived[m.hash] == nil {
		committeeReceived[m.hash] = make(map[int]bool)
	}
	committeeReceived[m.hash][m.sender] = true

	// Upon receiving messages on the same value v from tk+1 distinct committee members, output v
	// and terminate.
	if len(committeeReceived[m.hash]) >= rbc.tk+1 {
		// log.Printf("Node %d, instance %d: outputting '%s' and terminating..", rbc.nodeId, rbc.senderId, string(m.value))
		rbc.out <- m.value
		return true
	}
	return false
}

// multicastToCommittee sends a value to every committee member.
func (rbc *ReliableBroadcast) multicastToCommittee() {
	mes := &utils.Message{
		Sender: rbc.nodeId,
		Payload: &SMessage{
			sender: rbc.nodeId,
			value:  rbc.value,
		},
	}
	rbc.multicast(mes)
}

// multicastVal multicasts a VAL message.
func (rbc *ReliableBroadcast) multicastVal() {
	// log.Printf("%d multicasting VAL", rbc.nodeId)
	hash := rbc.value.Hash()
	mes := &utils.Message{
		Sender: rbc.nodeId,
		Payload: &BMessage{
			sender: rbc.nodeId,
			status: "VAL",
			value:  hash,
		},
	}
	rbc.multicast(mes)
}

// muticastEcho multicasts a ECHO message.
func (rbc *ReliableBroadcast) multicastEcho(m *BMessage) {
	// log.Printf("%d multicasting ECHO", rbc.nodeId)
	mes := &utils.Message{
		Sender: rbc.nodeId,
		Payload: &BMessage{
			sender: rbc.nodeId,
			status: "ECHO",
			value:  m.value,
		},
	}
	rbc.multicast(mes)
}

// multicastReady multicasts a READY message.
func (rbc *ReliableBroadcast) multicastReady(m *BMessage) {
	// log.Printf("%d multicasting READY", rbc.nodeId)
	mes := &utils.Message{
		Sender: rbc.nodeId,
		Payload: &BMessage{
			sender: rbc.nodeId,
			status: "READY",
			value:  m.value,
		},
	}
	rbc.multicast(mes)
}

// multicastCommitteeMessage multicasts a message from a committee member if the hash received by
// the broadcast matches the hash of the sender value.
func (rbc *ReliableBroadcast) multicastCommitteeMessage(senderValue *utils.BlockShare, broadcastValue [32]byte) {
	if h := senderValue.Hash(); h == broadcastValue {
		mes := &utils.Message{
			Sender: rbc.nodeId,
			Payload: &CMessage{
				sender: rbc.nodeId,
				value:  senderValue,
				hash:   broadcastValue,
				proof:  rbc.Sig.SigShare,
			},
		}
		rbc.multicast(mes)
	}
}

// isValidCommitteeMessage return wheter a message from a committee member is valid. The sender
// must be in the committee, the hash must be correct and the signature must be valid.
func (rbc *ReliableBroadcast) isValidCommitteeMessage(m *CMessage) bool {
	if !rbc.committee[m.sender] {
		return false
	}
	hash := m.value.Hash()
	if hash != m.hash {
		return false
	}
	return rbc.isValidSignature(m)
}

// isValidSignature returns whether a signature is valid.
func (rbc *ReliableBroadcast) isValidSignature(m *CMessage) bool {
	hash := sha256.Sum256([]byte(strconv.Itoa(m.sender)))
	paddedHash, err := tcrsa.PrepareDocumentHash(rbc.Sig.KeyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		// log.Printf("%d failed to hash id of %d, err: %s", rbc.nodeId, m.sender, err)
		return false
	}
	if err = m.proof.Verify(paddedHash, rbc.Sig.KeyMeta); err != nil {
		// log.Printf("%d received invalid signature from %d", rbc.nodeId, m.sender)
		return false
	}
	return true
}

// GetValue returns the output of the broadcast (blocking)
func (rbc *ReliableBroadcast) GetValue() *utils.BlockShare {
	return <-rbc.out
}
