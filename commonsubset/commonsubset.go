package commonsubset

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"log"
	"strconv"
	"sync"

	"github.com/niclabs/tcrsa"
	aba "github.com/sochsenreither/upgrade/binaryagreement"
	rbc "github.com/sochsenreither/upgrade/broadcast"
	"github.com/sochsenreither/upgrade/utils"
)

// TODO:
// - hash size?

type CommonSubset struct {
	n         int                      // Number of nodes
	nodeId    int                      // Id of node
	t         int                      // Number of maximum faulty nodes
	tk        int                      // Threshold for distinct committee messages
	round     int                      // Current round
	committee map[int]bool             // List of committee members
	input     *utils.BlockShare        // Input value
	out       chan []*utils.BlockShare // Output values
	rbcs      []*rbc.ReliableBroadcast // N instances of reliable broadcast
	abas      []*aba.BinaryAgreement   // N instances of binary agreement
	tc        *ThresholdCrypto         // Personal signature, key meta and signing key
	multicast func(msg *utils.Message) // Function for multicasting messages
	receive   func() *utils.Message    // Blocking function for receiving messages
	sync.Mutex
}

type ThresholdCrypto struct {
	Sk       *tcrsa.KeyShare // Private signing key
	KeyMeta  *tcrsa.KeyMeta  // Contains public keys to verify signatures
	SigShare *tcrsa.SigShare // Signature on node index signed by the dealer
}

type acsMessage struct {
	sender   int
	values   []*utils.BlockShare
	sigShare *tcrsa.SigShare // sigShare on values
}

type acsSignatureMessage struct {
	sender int
	hash   [32]byte
	sig    *tcrsa.Signature // combined signature on values
}

type acsCommitteeMessage struct {
	sender   int
	values   []*utils.BlockShare
	hash     [32]byte
	sigShare *tcrsa.SigShare // sigShare on hash
	proof    *tcrsa.SigShare // sigShare on the nodeId as proof that the sender is in the committee
}

type ACSConfig struct {
	N       int
	NodeId  int
	T       int
	Kappa   int
	Epsilon int
	Round   int
}

func NewACS(cfg *ACSConfig, comittee map[int]bool, input *utils.BlockShare, out chan []*utils.BlockShare, rbcs []*rbc.ReliableBroadcast, abas []*aba.BinaryAgreement, sig *ThresholdCrypto, multicastFunc func(nodeId, round int, msg *utils.Message), receiveFunc func(nodeId, round int) *utils.Message) *CommonSubset {
	tk := (((1 - cfg.Epsilon) * cfg.Kappa * cfg.T) / cfg.N)
	multicast := func(msg *utils.Message) {
		multicastFunc(cfg.NodeId, cfg.Round, msg)
	}
	receive := func() *utils.Message {
		return receiveFunc(cfg.NodeId, cfg.Round)
	}
	acs := &CommonSubset{
		n:         cfg.N,
		nodeId:    cfg.NodeId,
		t:         cfg.T,
		tk:        tk,
		round:     cfg.Round,
		committee: comittee,
		input:     input,
		out:       out,
		rbcs:      rbcs,
		abas:      abas,
		tc:        sig,
		multicast: multicast,
		receive:   receive,
	}
	return acs
}

func (acs *CommonSubset) Run() {
	commit := false

	var acsFinished []*utils.BlockShare // return value of the inner acs protocol
	var signature tcrsa.Signature       // combined signature of signature shares of committee members
	var receivedHash []byte             // received hash on s by committee members

	rbcVals := make(map[int]*utils.BlockShare)                   // map containint rbc results
	s := make(map[int]bool)                                      // maps NodeId -> true/false
	startAba := make(chan struct{}, acs.n)                       // channel to get unstarted aba instances started
	acsOut := make(chan []*utils.BlockShare, 999)                // channel for the output of the inner acs protocol
	rbcDone := make(chan int, acs.n)                             // channel for notifying if a rbc instance terminated
	abaRunning := make(map[int]bool)                             // tracks aba instances that are already running
	abaFinished := make(map[int]bool)                            // tracks aba instances that terminated
	messageChan := make(chan *utils.Message, acs.n*acs.n*9999)   // channel for routing incoming messages
	sharesReceived := make(map[[32]byte]map[int]*tcrsa.SigShare) // Maps hash -> nodeId -> sig

	messageHandler := func() {
		for {
			m := acs.receive()
			messageChan <- m
		}
	}

	go messageHandler()

	handleAba := func(i int) {
		// log.Printf("Node %d starting aba instance %d", acs.nodeId, i)
		go acs.abas[i].Run()
		acs.Lock()
		abaRunning[i] = true
		acs.Unlock()
		abaOut := acs.abas[i].GetValue()
		// log.Printf("Node %d received %d as value from aba instance %d", acs.nodeId, abaOut, i)
		acs.Lock()
		abaFinished[i] = true
		// If aba_i terminated with 1 as output, add it to s
		if abaOut == 1 {
			s[i] = true
			// if |s| >= n-t begin running all rbc instances with 0 (that have not yet begun to run)
			if len(s) >= acs.n-acs.t {
				startAba <- struct{}{}
			}
		}
		acs.Unlock()
		acs.eventHandler(rbcVals, s, abaFinished, &commit, acsOut)
	}

	// Start rbc instances
	for i := 0; i < acs.n; i++ {
		i := i
		go func() {
			// log.Printf("Node %d starting rbc instance %d", acs.nodeId, i)
			go acs.rbcs[i].Run()
			rbcOut := acs.rbcs[i].GetValue()
			// log.Printf("Node %d got output from rbc instance %d: %s", acs.nodeId, i, string(rbcOut))
			acs.Lock()
			rbcVals[i] = rbcOut
			rbcDone <- i
			acs.Unlock()
			acs.eventHandler(rbcVals, s, abaFinished, &commit, acsOut)
		}()
	}

	for {
		select {
		case i := <-rbcDone:
			// rbc_i finished, start aba_i with 1 as input
			acs.Lock()
			if !abaRunning[i] {
				acs.abas[i].SetValue(1)
				go handleAba(i)
			}
			acs.Unlock()
		case <-startAba:
			// Enough abas finished, start remaining abas with input 0
			acs.Lock()
			for i := 0; i < acs.n; i++ {
				if !abaRunning[i] {
					acs.abas[i].SetValue(0)
					go handleAba(i)
				}
			}
			acs.Unlock()
		case ret := <-acsOut:
			acsFinished = ret
		case mes := <-messageChan:
			switch m := mes.Payload.(type) {
			case *acsSignatureMessage:
				h, s := acs.handleSignatureMessage(m)
				if h != nil {
					receivedHash = h
				}
				if s != nil {
					signature = s
				}
			case *acsCommitteeMessage:
				h, s := acs.handleCommit(m, sharesReceived)
				if h != nil {
					receivedHash = h
				}
				if s != nil {
					signature = s
				}
			}
		}
		if acs.canTerminate(acsFinished, signature, receivedHash) {
			acs.out <- acsFinished
			return
		}
	}
}

// Predicates

//cOneHelper returns whether at least n-t executions of rbc_i have output val.
func (acs *CommonSubset) cOneHelper(val *utils.BlockShare, rbcVals map[int]*utils.BlockShare) bool {
	count := 0
	for _, v := range rbcVals {
		if val.Hash() == v.Hash() {
			count++
		}
	}
	return count >= acs.n-acs.t
}

// cOne returns whether there exists a val for which cOneHelper is true.
func (acs *CommonSubset) cOne(rbcVals map[int]*utils.BlockShare) (bool, *utils.BlockShare) {
	if len(rbcVals) < acs.n-acs.t {
		return false, nil
	}
	// TODO: bad runtime?
	for _, v := range rbcVals {
		if acs.cOneHelper(v, rbcVals) {
			return true, v
		}
	}
	return false, nil
}

// cTwoHelper returns whether all aba instances have terminated, |s| >= n-t and wheter val is returned by the majority of rbc instances.
func (acs *CommonSubset) cTwoHelper(val *utils.BlockShare, rbcVals map[int]*utils.BlockShare, s map[int]bool, abaFinished map[int]bool) bool {
	if len(s) < acs.n-acs.t {
		return false
	}
	if len(abaFinished) < acs.n {
		return false
	}

	count := 0
	for _, v := range rbcVals {
		if val.Hash() == v.Hash() {
			count++
		}
	}
	return count > len(rbcVals)/2
}

// cTwo returns whether there exists a val for which cTwoHelper is true.
func (acs *CommonSubset) cTwo(rbcVals map[int]*utils.BlockShare, s map[int]bool, abaFinished map[int]bool) (bool, *utils.BlockShare) {
	if len(s) < acs.n-acs.t {
		return false, nil
	}

	for _, v := range rbcVals {
		if acs.cTwoHelper(v, rbcVals, s, abaFinished) {
			return true, v
		}
	}
	return false, nil
}

// cThree returns whether |s| >= n-t and all executions of rbc and aba have terminated.
func (acs *CommonSubset) cThree(rbcVals map[int]*utils.BlockShare, s map[int]bool, abaFinished map[int]bool) bool {
	return len(s) >= acs.n-acs.t && len(abaFinished) == acs.n && len(rbcVals) == acs.n
}

// eventHandler checks for the three output conditions and sends a commit message if one condition
// is met and the node is in the committee.
func (acs *CommonSubset) eventHandler(rbcVals map[int]*utils.BlockShare, s map[int]bool, abaFinished map[int]bool, commit *bool, acsOut chan []*utils.BlockShare) {
	acs.Lock()
	defer acs.Unlock()
	if *commit {
		return
	}

	bOne, vOne := acs.cOne(rbcVals)
	if bOne && !*commit {
		log.Printf("Node %d: Condition C1 is true", acs.nodeId)
		*commit = true
		out := []*utils.BlockShare{vOne}
		acsOut <- out
		if acs.committee[acs.nodeId] {
			acs.multicastCommit(out)
		}
		return
	}

	bTwo, vTwo := acs.cTwo(rbcVals, s, abaFinished)
	if bTwo && !*commit {
		log.Printf("Node %d: Condition C2 is true", acs.nodeId)
		*commit = true
		out := []*utils.BlockShare{vTwo}
		acsOut <- out
		if acs.committee[acs.nodeId] {
			acs.multicastCommit(out)
		}
		return
	}
	bThree := acs.cThree(rbcVals, s, abaFinished)
	if bThree && !*commit {
		log.Printf("Node %d: Condition C3 is true", acs.nodeId)
		*commit = true
		var outputs []*utils.BlockShare
		for i := 0; i < acs.n; i++ {
			if s[i] {
				outputs = append(outputs, rbcVals[i])
			}
		}
		acsOut <- outputs
		if acs.committee[acs.nodeId] {
			acs.multicastCommit(outputs)
		}
		return
	}
}

// multicastCommit creates and multicasts a commit message with a given value slice
func (acs *CommonSubset) multicastCommit(values []*utils.BlockShare) {
	hash := acs.hashValues(values)
	sig, err := acs.signHash(hash)
	if err != nil {
		log.Printf("Node %d failed to create signature", acs.nodeId)
		return
	}
	payload := &acsCommitteeMessage{
		sender:   acs.nodeId,
		values:   values,
		hash:     hash,
		sigShare: sig,
		proof:    acs.tc.SigShare,
	}
	mes := &utils.Message{
		Sender:  acs.nodeId,
		Payload: payload,
	}

	log.Printf("Node %d is multicasting commit on %p", acs.nodeId, values)
	acs.multicast(mes)
}

// hashValues returns the hash of a slice of byte slices
func (acs *CommonSubset) hashValues(values []*utils.BlockShare) [32]byte {
	var data []byte
	for _, v := range values {
		h := v.Hash()
		data = append(data, h[:]...)
	}
	hash := sha256.Sum256(data)
	return hash
}

// signHash signs a given hash
func (acs *CommonSubset) signHash(hash [32]byte) (*tcrsa.SigShare, error) {
	paddedHash, err := tcrsa.PrepareDocumentHash(acs.tc.KeyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		log.Printf("Node %d failed to create padded hash", acs.nodeId)
		return nil, err
	}
	sig, err := acs.tc.Sk.Sign(paddedHash, crypto.SHA256, acs.tc.KeyMeta)
	return sig, err
}

// handleCommit checks if a received commit message is valid and checks if enough are received on
// the same value and then forms a signature and multicasts it.
func (acs *CommonSubset) handleCommit(m *acsCommitteeMessage, sharesReceived map[[32]byte]map[int]*tcrsa.SigShare) ([]byte, tcrsa.Signature) {
	if !acs.committee[m.sender] {
		return nil, nil
	}
	if !acs.isValidSignature(m) {
		return nil, nil
	}
	if sharesReceived[m.hash] == nil {
		sharesReceived[m.hash] = make(map[int]*tcrsa.SigShare)
	}
	sharesReceived[m.hash][m.sender] = m.sigShare
	log.Printf("Node %d received commit from %d, total received: %d", acs.nodeId, m.sender, len(sharesReceived[m.hash]))
	// TODO: can't create signature with less than n/2+1 shares. This is a restriction by the used library. Following the paper the value should be tk+1.
	if len(sharesReceived[m.hash]) >= acs.n/2+1 {
		log.Printf("Node %d received enough valid signature shares, creating signature", acs.nodeId)
		var sigShares tcrsa.SigShareList
		for _, sig := range sharesReceived[m.hash] {
			sigShares = append(sigShares, sig)
		}
		paddedHash, err := tcrsa.PrepareDocumentHash(acs.tc.KeyMeta.PublicKey.Size(), crypto.SHA256, m.hash[:])
		if err != nil {
			log.Printf("Node %d failed to create padded hash", acs.nodeId)
			return nil, nil
		}
		signature, err := sigShares.Join(paddedHash, acs.tc.KeyMeta)
		if err != nil {
			log.Printf("Node %d failed to create joined signature, %s", acs.nodeId, err)
			return nil, nil
		}
		mes := &utils.Message{
			Sender: acs.nodeId,
			Payload: &acsSignatureMessage{
				sender: acs.nodeId,
				hash:   m.hash,
				sig:    &signature,
			},
		}
		log.Printf("Node %d is multicasting joined signature", acs.nodeId)
		acs.multicast(mes)
		return m.hash[:], signature
	}
	return nil, nil
}

// handleSignatureMessage verifies a combined signature and if it is valid multicasts it.
func (acs *CommonSubset) handleSignatureMessage(m *acsSignatureMessage) ([]byte, tcrsa.Signature) {
	err := rsa.VerifyPKCS1v15(acs.tc.KeyMeta.PublicKey, crypto.SHA256, m.hash[:], *m.sig)
	if err != nil {
		log.Printf("Node %d received signature message with invalid signature", acs.nodeId)
		return nil, nil
	}
	mes := &utils.Message{
		Sender: acs.nodeId,
		Payload: &acsSignatureMessage{
			sender: acs.nodeId,
			hash:   m.hash,
			sig:    m.sig,
		},
	}
	log.Printf("Node %d echoing signature and hash", acs.nodeId)
	acs.multicast(mes)
	return m.hash[:], *m.sig
}

// isValidSignature returns whether a signature for a hash and a proof on the nodeId is valid.
func (acs *CommonSubset) isValidSignature(m *acsCommitteeMessage) bool {
	hash := acs.hashValues(m.values)
	if hash != m.hash {
		log.Printf("Node %d received message with invalid hash", acs.nodeId)
		return false
	}
	paddedHash, err := tcrsa.PrepareDocumentHash(acs.tc.KeyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		log.Printf("Node %d failed to create padded hash", acs.nodeId)
		return false
	}
	if err = m.sigShare.Verify(paddedHash, acs.tc.KeyMeta); err != nil {
		log.Printf("Node %d received commit with invalid signature", acs.nodeId)
		return false
	}
	hash = sha256.Sum256([]byte(strconv.Itoa(m.sender)))
	paddedHash, err = tcrsa.PrepareDocumentHash(acs.tc.KeyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		log.Printf("%d failed to hash id of %d, err: %s", acs.nodeId, m.sender, err)
		return false
	}
	if err = m.proof.Verify(paddedHash, acs.tc.KeyMeta); err != nil {
		log.Printf("%d received invalid signature from %d", acs.nodeId, m.sender)
		return false
	}
	return true
}

// canTerminate returns whether the termination conditions are met.
func (acs *CommonSubset) canTerminate(acsFinished []*utils.BlockShare, signature tcrsa.Signature, receivedHash []byte) bool {
	if acsFinished == nil || signature == nil || receivedHash == nil {
		return false
	}
	hash := acs.hashValues(acsFinished)

	return bytes.Equal(hash[:], receivedHash)
}

// getValue returns the output of the acs protocol (blocking)
func (acs *CommonSubset) getValue() []*utils.BlockShare {
	return <-acs.out
}
