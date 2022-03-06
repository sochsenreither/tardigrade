package binaryagreement

import (
	"crypto"
	"crypto/sha256"

	//"log"
	"strconv"
	"sync"

	"github.com/niclabs/tcrsa"
)

// TODO: abstract common coin call

type BinaryAgreement struct {
	UROUND int
	n               int                   // Number of nodes
	nodeId          int                   // Id of node
	t               int                   // Number of maximum faulty nodes
	value           int                   // Initial input
	round           int                   // Current round of aba, not the round of the top protocol
	instance        int                   // Id of the current instance
	coin            *CommonCoin           // Common coin for randomness
	thresholdCrypto *ThresholdCrypto      // Struct containing the secret key and key meta
	multicast       func(msg *AbaMessage) // Function for multicasting
	receive         func() *AbaMessage    // Blocking function for receiving messages
	out             chan int              // Output channel
	sync.Mutex                            // Lock
}

type AbaMessage struct {
	sender int
	value  int
	round  int
	status string
}

type ThresholdCrypto struct {
	KeyShare *tcrsa.KeyShare
	KeyMeta  *tcrsa.KeyMeta
}

func NewBinaryAgreement(n, nodeId, t, value, instance int, coin *CommonCoin, thresholdCrypto *ThresholdCrypto, multicastFunc func(nodeId, instance, round int, msg *AbaMessage), receiveFunc func(nodeId, instance, round int) *AbaMessage) *BinaryAgreement {
	out := make(chan int, 100)
	aba := &BinaryAgreement{
		n:               n,
		nodeId:          nodeId,
		t:               t,
		value:           value,
		round:           0,
		instance:        instance,
		coin:            coin,
		thresholdCrypto: thresholdCrypto,
		multicast:       nil,
		receive:         nil,
		out:             out,
	}

	multicast := func(msg *AbaMessage) {
		multicastFunc(aba.nodeId, instance, aba.round, msg)
	}
	receive := func() *AbaMessage {
		aba.Lock()
		r := aba.round
		aba.Unlock()
		return receiveFunc(aba.nodeId, instance, r)
	}

	aba.multicast = multicast
	aba.receive = receive

	return aba
}

func (aba *BinaryAgreement) Run() {
	// Keep track of values received from broadcast. Maps round -> received values
	binValues := make(map[int]map[int]bool)
	// Keep track of received EST values. Maps round -> value -> nodes that sent this value
	estValues := make(map[int]map[int]map[int]bool)
	// Keep track of received AUX values. Maps round -> value -> nodes that sent this value
	auxValues := make(map[int]map[int]map[int]bool)
	// Keep track of already sent values
	estSent := make(map[int]map[int]bool)
	// Keep track of echoed EST messages. Maps round -> value
	estEchoes := make(map[int]map[int]bool)
	notifyEST := make(map[int]chan []int)
	notifyAUX := make(map[int]chan []int)

	est := aba.value

	messageHandler := func() {
		for {
			m := aba.receive()
			r, v, s := m.round, m.value, m.sender
			switch m.status {
			case "EST":
				// // log.Println("Round", aba.round, "instance", aba.instance, "-", aba.nodeId, "received EST from", s, "on", v)
				handleBcs(r, v, s, estValues)

				// If a node received t+1 messages on value from distinct nodes, it multicasts this value (only once).
				if len(estValues[r][v]) >= aba.t+1 {
					//// log.Println("Round", aba.round, "-",  aba.nodeId, "received t+1 ESTs")
					aba.echoEST(r, v, aba.nodeId, estEchoes)
				}

				// If a node received 2t+1 messages on value from distinct nodes, it adds this value to its binary value list.
				if len(estValues[r][v]) >= 2*aba.t+1 {
					if binValues[r] == nil {
						binValues[r] = make(map[int]bool)
					}
					binValues[r][v] = true
					aba.Lock()
					if notifyEST[r] == nil {
						notifyEST[r] = make(chan []int, 999)
					}
					aba.Unlock()
					//// log.Println("Round", aba.round, "instance", aba.instance, "-", aba.nodeId, "received 2t+1 ESTs, updating values")
					notifyEST[r] <- []int{v}
				}
			case "AUX":
				//// log.Println("Round", aba.round, "instance", aba.instance, "-", aba.nodeId, "received AUX from", s, "on", v)
				handleBcs(r, v, s, auxValues)
				aba.Lock()
				if notifyAUX[r] == nil {
					notifyAUX[r] = make(chan []int, 999)
				}
				aba.Unlock()

				// If a node received n-t AUX messages on value(s) from distinct nodes, it can proceed in the algorithm. TODO: better description
				if binValues[r][0] && len(auxValues[r][0]) >= aba.n-aba.t {
					notifyAUX[r] <- []int{0}
				}
				if binValues[r][1] && len(auxValues[r][1]) >= aba.n-aba.t {
					notifyAUX[r] <- []int{1}
				}
				if len(binValues[r]) == 2 && len(auxValues[r][0])+len(auxValues[r][1]) >= aba.n-aba.t {
					notifyAUX[r] <- []int{0, 1}
				}
			}
		}
	}

	for {
		// Start message handler
		go messageHandler()

		//log.Println("Node:", aba.nodeId, "----- new round:", aba.round, "-----", "instance:", aba.instance)
		aba.Lock()
		if notifyEST[aba.round] == nil {
			notifyEST[aba.round] = make(chan []int, 999)
		}
		if notifyAUX[aba.round] == nil {
			notifyAUX[aba.round] = make(chan []int, 999)
		}
		aba.Unlock()

		// Send est value
		aba.sendEST(aba.round, est, aba.nodeId, estSent)

		// Wait until binValues contains a value
		w := <-notifyEST[aba.round]

		// Broadcast value contained in binValues. Note: w always contains one element
		//// log.Println("Round", aba.round, "instance", aba.instance, "-", aba.nodeId, "broadcasts value from binValues")
		aba.sendAUX(aba.round, w[0], aba.nodeId)

		// Wait until enough AUX messages are received
		values := <-notifyAUX[aba.round]
		// log.Printf("Node %d UROUND %d round %d instance %d calling coin", aba.nodeId, aba.UROUND, aba.round, aba.instance)

		// Call the common coin
		coin := aba.callCommonCoin()

		// log.Printf("Node %d UROUND %d round %d instance %d got value %d", aba.nodeId, aba.UROUND, aba.round, aba.instance, coin)

		// Decide
		if len(values) == 1 {
			// log.Printf("Node %d, instance %d, round %d - val %d - coin %d", aba.nodeId, aba.instance, aba.round, values[0], coin)
			if values[0] == coin {
				// log.Printf("Node %d UROUND %d round %d instance %d. Value %d - Coin %d - Returning", aba.nodeId, aba.UROUND, aba.round, aba.instance, values[0], coin)
				aba.out <- coin
				return
			} else {
				//// log.Println("Round", aba.round, "instance", aba.instance, "-", aba.nodeId, "sets est to", values[0])
				est = values[0]
			}
		} else {
			est = coin
		}

		aba.Lock()
		aba.round++
		aba.Unlock()
	}
}

// handleBcs saves a received EST/AUX message in a map. TODO: better name
func handleBcs(r, v, s int, vals map[int]map[int]map[int]bool) {
	if vals[r] == nil {
		vals[r] = make(map[int]map[int]bool)
	}
	if vals[r][v] == nil {
		vals[r][v] = make(map[int]bool)
	}
	vals[r][v][s] = true
}

// sendEST first checks if a EST message with v was already sent. If not it multicasts it to all nodes.
func (aba *BinaryAgreement) sendEST(round, value, sender int, estSent map[int]map[int]bool) {
	if estSent[round] == nil {
		estSent[round] = make(map[int]bool)
	}
	if !estSent[round][value] {
		estSent[round][value] = true
		mes := &AbaMessage{
			sender: sender,
			value:  value,
			round:  round,
			status: "EST",
		}

		//// log.Println("Round", aba.round, "-",  aba.nodeId, "multicasting EST. val:", value, "round:", round)
		aba.multicast(mes)
	}
}

// echoEst echoes a EST, but only echoes a value once
func (aba *BinaryAgreement) echoEST(round, value, sender int, estEchoes map[int]map[int]bool) {
	if estEchoes[round] == nil {
		estEchoes[round] = make(map[int]bool)
	}
	if !estEchoes[round][value] {
		estEchoes[round][value] = true
		mes := &AbaMessage{
			sender: sender,
			value:  value,
			round:  round,
			status: "EST",
		}
		//// log.Println("Round", aba.round, "-",  aba.nodeId, "echoing EST. val:", value, "round:", round)
		aba.multicast(mes)
	}
}

// sendAUX sends an AUX message.
func (aba *BinaryAgreement) sendAUX(round, value, sender int) {
	mes := &AbaMessage{
		sender: sender,
		value:  value,
		round:  round,
		status: "AUX",
	}
	aba.multicast(mes)
}

// callCommonCoin calls the common coin and blocks until it returns a value.
func (aba *BinaryAgreement) callCommonCoin() int {
	h := sha256.Sum256([]byte(strconv.Itoa(aba.round)))
	hash, _ := tcrsa.PrepareDocumentHash(aba.thresholdCrypto.KeyMeta.PublicKey.Size(), crypto.SHA256, h[:])
	sig, err := aba.thresholdCrypto.KeyShare.Sign(hash, crypto.SHA256, aba.thresholdCrypto.KeyMeta)
	if err != nil {
		// log.Panicln(aba.nodeId, "failed to create signature on round", aba.round)
	}
	answerChan := make(chan byte, 100)

	// log.Println("Round", aba.round, "instance", aba.instance, "-", aba.nodeId, "sending request to coin")
	aba.coin.RequestChan <- &CoinRequest{
		sender:   aba.nodeId,
		round:    aba.round,
		sig:      sig,
		answer:   answerChan,
		instance: aba.instance,
	}

	val := <-answerChan
	return int(val)
}

// GetValue returns the output of the binary agreement (blocking)
func (aba *BinaryAgreement) GetValue() int {
	return <-aba.out
}

// SetValue sets the input value to the given value
func (aba *BinaryAgreement) SetValue(val int) {
	aba.value = val
}