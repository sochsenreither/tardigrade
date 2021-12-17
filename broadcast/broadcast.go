package broadcast

import (
	"crypto/sha256"
	"log"
)

// TODO: change output and input value types

type broadcast struct {
	n             int                           // Number of nodes
	nodeId        int                           // Id of node
	t             int                           // Number of maximum faulty nodes
	round         int                           // Current round
	senderId      int                           // Id of sender
	value         []byte                        // Input value of the sender
	killBroadcast chan struct{}                 // Termination channel
	out           chan []byte                   // Output channel
	multicast     func(msg *broadcastMessage)   // Function for multicasting values
	receive       func() chan *broadcastMessage // Blocking function for receiving messages
}

type broadcastStatus string

type broadcastMessage struct {
	sender int
	status broadcastStatus
	value  []byte
}

func NewBroadcast(n, nodeId, t, round, senderId int, killBroadcast chan struct{}, out chan []byte, multicastFunc func(instance, round int, msg *broadcastMessage), receiveFunc func(instance, round int) chan *broadcastMessage) *broadcast {
	multicast := func(msg *broadcastMessage) {
		multicastFunc(senderId, round, msg)
	}
	receive := func() chan *broadcastMessage {
		return receiveFunc(senderId, round)
	}
	broadcast := &broadcast{
		n:             n,
		nodeId:        nodeId,
		t:             t,
		round:         round,
		senderId:      senderId,
		value:         nil,
		killBroadcast: killBroadcast,
		out:           out,
		multicast:     multicast,
		receive:       receive,
	}
	return broadcast
}

func (bb *broadcast) run() {
	ready := false
	leaderSent := false
	// maps have structure hash(val) -> nodeId
	echoMap := make(map[[32]byte]map[int]bool)
	readyMap := make(map[[32]byte]map[int]bool)

	if bb.isSender() {
		log.Println(bb.nodeId, "is multicasting the initial value:", string(bb.value))
		message := &broadcastMessage{
			sender: bb.nodeId,
			status: "val",
			value:  bb.value,
		}
		bb.multicast(message)
	}

	for {
		select {
		case <-bb.killBroadcast:
			log.Println(bb.nodeId, "received kill signal.. terminating")
			return
		case m := <-bb.receive():
			switch m.status {
			case "val":
				// Upon receiving initial value v from sender, multicast (echo, v)
				if !leaderSent {
					log.Println(bb.nodeId, "received value from", m.sender, ":", string(m.value))
					leaderSent = true
					message := &broadcastMessage{
						sender: bb.nodeId,
						status: "echo",
						value:  m.value,
					}
					bb.multicast(message)
				}
			case "echo":
				// Upon receiving (echo, v) messages on the same value v from n-t distinct nodes:
				// If ready = false, set ready = true and multicast (ready, v)
				// Check if received value is the same as the initial sender value
				hash := sha256.Sum256(m.value)
				if echoMap[hash] == nil {
					echoMap[hash] = make(map[int]bool)
				}
				echoMap[hash][m.sender] = true

				// Check if there are enough received echo messages.
				if len(echoMap[hash]) >= bb.n-bb.t && !ready {
					log.Println(bb.nodeId, "received", len(echoMap[hash]), "echos.", "needed", bb.n-bb.t, "Sending ready")
					ready = true
					message := &broadcastMessage{
						sender: bb.nodeId,
						status: "ready",
						value:  m.value,
					}
					bb.multicast(message)
				}
			case "ready":
				// Upon receiving (ready, v) messages on the same value v from t+1 distinct nodes:
				// If ready = false, set ready = true and multicast (ready, v)
				// Check if received value is the same as the initial sender value
				hash := sha256.Sum256(m.value)
				if readyMap[hash] == nil {
					readyMap[hash] = make(map[int]bool)
				}
				readyMap[hash][m.sender] = true

				// Check if there are enough received ready messages.
				if len(readyMap[hash]) >= bb.t+1 && !ready {
					log.Println(bb.nodeId, "received", len(readyMap[hash]), "ready messages. Sending ready")
					ready = true
					message := &broadcastMessage{
						sender: bb.nodeId,
						status: "ready",
						value:  m.value,
					}
					bb.multicast(message)
				}

				// Upon receiving (ready, v) messages on the same value v from n-t distinct nodes:
				// Output v and terminate
				if len(readyMap[hash]) >= bb.n-bb.t {
					log.Println(bb.nodeId, "received", len(readyMap[hash]), "ready messages. Outputting value:", string(m.value))
					bb.out <- m.value
					return
				}

			default:
				log.Println(bb.nodeId, "received unknown status code from", m.sender)
			}
		}
	}
}

// Sets a given value
func (bb *broadcast) setValue(value []byte) {
	bb.value = value
}

// Returns whether the current node is the sender
func (bb *broadcast) isSender() bool {
	return bb.nodeId == bb.senderId
}
