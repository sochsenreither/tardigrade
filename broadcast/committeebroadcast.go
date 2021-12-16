package broadcast

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"log"
	"strconv"

	"github.com/niclabs/tcrsa"
)

// TODO:
// - hash size security parameter
// - change value from []byte to correct type

type CommitteeBroadcast struct {
	n                int                                    // Number of nodes
	nodeId           int                                    // Id of node
	t                int                                    // Number of maximum faulty nodes
	tk               int                                    // Threshold for distinct committee messages
	kappa            int                                    // Security parameter
	epsilon          int                                    // TODO: ??
	senderId         int                                    // Id of sender
	committee        map[int]bool                           // List of committee members
	value            []byte                                 // Input value of the sender
	out              chan []byte                            // Output channel
	broadcast        *broadcast                             // Underlying broadcast protocol
	sig              *signatureScheme                       // PKI // TODO: better name
	senderValue      []byte                                 // Value received from sender
	broadcastValue   []byte                                 // Value received from broadcast
	senderFunc       func(val []byte)                       // For sending a value to the committee
	multicastFunc    func(msg *committeeBroadcastMessage)   // For multicasting messages
	receive          func() chan *committeeBroadcastMessage // Blocking function for receiving messages
	receiveSenderVal func() chan []byte                     // Blocking function for receiving initial value from Sender
}

type signatureScheme struct {
	sig     *tcrsa.SigShare // Signature on node index signed by the dealer
	keyMeta *tcrsa.KeyMeta  // Contains public keys to verify signature
}

type committeeBroadcastMessage struct {
	sender int
	value  []byte
	hash   []byte
	sig    *tcrsa.SigShare
}

func NewCommitteeBroadcast(n, nodeId, t, kappa, senderId, epsilon int, committee map[int]bool, bbInputChan chan *broadcastMessage, senderChans []chan []byte, out chan []byte, sig *signatureScheme, bbMulticastFunc func(msg *broadcastMessage), bbReceiveFunc func() chan *broadcastMessage, senderFunc func(val []byte), cbbMulticastFunc func(msg *committeeBroadcastMessage), receiveFunc func() chan *committeeBroadcastMessage, receiveSenderVal func() chan []byte) *CommitteeBroadcast {
	tk := (((1 - epsilon) * kappa * t) / n)

	broadcastOutput := make(chan []byte, 1)
	killBroadcast := make(chan struct{}, 1)
	broadcast := NewBroadcast(n, nodeId, t, senderId, killBroadcast, broadcastOutput, bbMulticastFunc, bbReceiveFunc)

	cbb := &CommitteeBroadcast{
		n:              n,
		nodeId:         nodeId,
		t:              t,
		tk:             tk,
		kappa:          kappa,
		epsilon:        epsilon,
		senderId:       senderId,
		committee:      committee,
		value:          nil,
		out:            out,
		broadcast:      broadcast,
		sig:            sig,
		senderValue:    nil,
		broadcastValue: nil,
		senderFunc:     senderFunc,
		multicastFunc:  cbbMulticastFunc,
		receive:        receiveFunc,
		receiveSenderVal: receiveSenderVal,
	}

	return cbb
}

func (cbb *CommitteeBroadcast) run() {
	// Sender sends his value to committee and inputs Hash(value) to BB
	if cbb.isSender() {
		log.Println("Sender is multicasting value to committee")
		cbb.senderFunc(cbb.value)
		// Input H(v) to BB
		hash := sha256.Sum256(cbb.value)
		cbb.broadcast.setValue(hash[:])
	}

	cbbMessagesReceived := make(map[int]bool)

	// Run BB
	go cbb.broadcast.run()

	for {
		select {
		case h := <-cbb.broadcast.out:
			// If node is in the committee, has received a value from the sender and output from
			// broadcast : If H(senderValue) = h, multicast (senderValue, h, sig_i)
			log.Println(cbb.nodeId, "got output from broadcast")
			cbb.broadcastValue = h
			cbb.prepareMulticastCBBMessage()
		case v := <-cbb.receiveSenderVal():
			// If node is in the committee, has received output from broadcast and value from
			// sender: If H(senderValue) = h, multicast (senderValue, h, sig_i)
			log.Println(cbb.nodeId, "received value from leader")
			cbb.senderValue = v
			cbb.prepareMulticastCBBMessage()
		case m := <-cbb.receive():
			if cbb.committee[m.sender] && cbb.isValidSignature(m.sig, m.sender) {
				log.Println(cbb.nodeId, "received value from committee")
				// If node is in the committee, has received output from broadcast and a message
				// from a committee member: If H(m.value) = h, multicast (senderValue, h, sig_i)
				if cbb.committee[cbb.nodeId] && cbb.broadcastValue != nil {
					if hash := sha256.Sum256(m.value); bytes.Equal(cbb.broadcastValue, hash[:]) {
						cbb.multicast(m.value, m.hash)
					}
				}
				cbbMessagesReceived[m.sender] = true
				// Upon receiving committeeBroadcastMessages from at least t_k +1 distinct
				// committee members: output the value of those messages and terminate.
				if len(cbbMessagesReceived) >= cbb.tk+1 {
					log.Println(cbb.nodeId, "received enough messages from committee members, terminating..")
					cbb.out <- m.value
					cbb.broadcast.killBroadcast <- struct{}{}
					return
				}
			}
		}
	}
}

// Checks if the conditions are met for multicasting a committeeBroadcastMessage
func (cbb *CommitteeBroadcast) prepareMulticastCBBMessage() {
	if cbb.committee[cbb.nodeId] && cbb.senderValue != nil && cbb.broadcastValue != nil {
		if hash := sha256.Sum256(cbb.senderValue); bytes.Equal(cbb.broadcastValue, hash[:]) {
			cbb.multicast(cbb.senderValue, cbb.broadcastValue)
		}
	}
}

// Returns whether the current node is the sender
func (cbb *CommitteeBroadcast) isSender() bool {
	return cbb.nodeId == cbb.senderId
}

// SetValue sets a given value
func (cbb *CommitteeBroadcast) SetValue(input []byte) {
	cbb.value = input
}

// Sends a message to every node
func (cbb *CommitteeBroadcast) multicast(value []byte, hash []byte) {
	message := &committeeBroadcastMessage{
		sender: cbb.nodeId,
		value:  value,
		hash:   hash[:],
		sig:    cbb.sig.sig,
	}
	cbb.multicastFunc(message)
}

// Returns whether a signature is valid
func (cbb *CommitteeBroadcast) isValidSignature(sig *tcrsa.SigShare, id int) bool {
	hash := sha256.Sum256([]byte(strconv.Itoa(id)))
	hashPadded, err := tcrsa.PrepareDocumentHash(cbb.sig.keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		log.Println(cbb.nodeId, "failed to hash id of", id, " ", err)
		return false
	}
	if err = sig.Verify(hashPadded, cbb.sig.keyMeta); err != nil {
		log.Println(cbb.nodeId, "received invalid signature from", id)
		return false
	}
	return true
}
