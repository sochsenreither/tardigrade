package upgrade

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"log"
	"math/big"
	"math/rand"
	"strconv"
	"sync"
	"time"

	"github.com/niclabs/tcpaillier"
	"github.com/niclabs/tcrsa"
	ba "github.com/sochsenreither/upgrade/blockagreement"
	acs "github.com/sochsenreither/upgrade/commonsubset"
	utils "github.com/sochsenreither/upgrade/utils"
)

type Upgrade struct {
	cfg       *UpgradeConfig                          // Parameters for protocol
	acs       *acs.CommonSubset                       // Subset instance
	ba        *ba.BlockAgreement                      // Blockagreement instance
	tcs       *tcs                                    // Keys for threshold crypto system
	buf       [][]byte                                // Transaction buffer
	multicast func(msg *utils.Message, params ...int) // Function for multicasting messages
	receive   func(round int) *utils.Message          // Blocking function for receiving messages
	locks     map[int]*sync.Mutex                     // Lock per round
}

type tcs struct {
	keyMeta *tcrsa.KeyMeta       // KeyMeta containig pks for verifying
	proof   *tcrsa.SigShare      // Signature on the node index signed by the dealer
	sigSk   *tcrsa.KeyShare      // Private signing key
	encSk   *tcpaillier.KeyShare // Private encryption key
	encPk   *tcpaillier.PubKey   // Public encryption key
}

type UpgradeConfig struct {
	n         int          // Number of nodes
	nodeId    int          // Id of node
	t         int          // Number of maximum faulty nodes
	tk        int          // Threshold for distinct committee messages
	kappa     int          // Security parameter
	lambda    int          // spacing paramter
	committee map[int]bool // List of committee members
}

type blockMessage struct {
	sender  int
	status  string          // "large" or "small"
	payload []byte          // Encrypted data
	sig     *tcrsa.SigShare // Signature on payload
}

type committeeMessage struct {
	sender   int
	preBlock *utils.PreBlock
	hash     [32]byte        // Hash of the pre-block
	hashSig  *tcrsa.SigShare // Signature of the hash
	proof    *tcrsa.SigShare // Signature of the dealer on the nodeId of the sender
}

type pointerMessage struct {
	sender  int
	pointer *utils.BlockPointer
}

func NewUpgrade(cfg *UpgradeConfig, acs *acs.CommonSubset, ba *ba.BlockAgreement, tcs *tcs, multicastFunc func(nodeId int, msg *utils.Message, params ...int), receiveFunc func(nodeId, round int) *utils.Message) *Upgrade {
	multicast := func(msg *utils.Message, params ...int) {
		multicastFunc(cfg.nodeId, msg, params...)
	}
	receive := func(round int) *utils.Message {
		return receiveFunc(cfg.nodeId, round)
	}
	buf := make([][]byte, 0)
	u := &Upgrade{
		cfg:       cfg,
		acs:       acs,
		ba:        ba,
		tcs:       tcs,
		buf:       buf,
		multicast: multicast,
		receive:   receive,
	}
	return u
}

func (u *Upgrade) run() {
	k := 1
	ticker := time.NewTicker(time.Duration(u.cfg.lambda) * time.Millisecond)
	for range ticker.C {
		log.Printf("Node %d starting round %d", u.cfg.nodeId, k)
		go u.runProtocol(k)
		k++
	}
}

func (u *Upgrade) runProtocol(r int) {
	// Every round needs a unique lock. Otherwise we could have the case of 10 rounds running in
	// parallel and one agent of round x blocking every other agent in rounds y != x when taking
	// the lock.
	var mu sync.Mutex
	u.locks[r] = &mu
	// Following two variables are only used by committee members
	// Create a new large pre-block
	largePb := utils.NewPreBlock(u.cfg.n)
	readyLarge := false

	// Create a new small pre-block and block pointer
	smallPb := utils.NewPreBlock(u.cfg.n) // needs lock
	readySmall := false                   // needs lock
	var ptr *utils.BlockPointer           // needs lock
	// Keep track if a committee message was already received
	mesRec := false

	// Listener functions that handles incoming messages
	// TODO: check for data races
	listener := func() {
		// Maps hash(block) -> nodeId -> sigShare
		blocksReceived := make(map[[32]byte]map[int]*tcrsa.SigShare)
		for {
			msg := u.receive(r)
			switch m := msg.Payload.(type) {
			case *blockMessage:
				if m.status == "large" && u.cfg.committee[u.cfg.nodeId] {
					u.handleLargeBlockMessage(r, m, largePb, &readyLarge, u.locks[r])
				} else {
					u.handleSmallBlockMessage(r, m, smallPb, &readySmall, u.locks[r])
				}
			case *pointerMessage:
				u.handlePointerMessage(r, m, ptr, u.locks[r])
			case *committeeMessage:
				u.handleCommitteeMessage(r, m, ptr, &mesRec, blocksReceived, u.locks[r])
			}
		}
	}
	go listener()

	// At time 0 propose Txs:
	l := u.cfg.n * u.cfg.n * u.cfg.kappa
	v := u.proposeTxs(l/u.cfg.n, l)
	w := u.proposeTxs(l/u.cfg.n, l)

	// Encrypt each v_i in v and send it to node_i
	for i, tx := range v {
		u.handleSmallTransaction(i, r, tx)
	}

	// Encrypt w and send it to each committee member
	u.handleLargeTransaction(r, w)

	// At time 4 delta run BLA:

	// At time 5 delta + 5 kappa delta run ACS:
}

// handleLargeTransaction sends a blockMessage containing encrypted transactions w to the committee.
func (u *Upgrade) handleLargeTransaction(r int, w [][]byte) {
	// TODO: only multicast to committee. Handle in multicast func? check for message status and
	//then only send to committee members?
	// Merge slice of byte slices to one byte slice
	tx := make([]byte, 0)
	for _, t := range w {
		tx = append(tx, t...)
	}
	data := new(big.Int)
	data.SetBytes(tx)

	m, err := u.encryptAndSign(data, "large")
	if err != nil {
		return
	}
	// TODO: only send to committee members
	u.multicast(m, r)
}

// handleSmallTransaction sends a blockMessage containing encrypted transaction tx to node i.
func (u *Upgrade) handleSmallTransaction(i, r int, tx []byte) {
	data := new(big.Int)
	data.SetBytes(tx)
	m, err := u.encryptAndSign(data, "small")
	if err != nil {
		return
	}
	// TODO: only send to party i. CHECK IF THIS WORKS
	u.multicast(m, r, i)
}

// encryptAndSign encrypts data, signs the hash of the encrypted value and returns a blockMessage
// wrapped into a Message
func (u *Upgrade) encryptAndSign(data *big.Int, status string) (*utils.Message, error) {
	tx := string(data.Bytes())
	// Encrypt transaction
	e, _, err := u.tcs.encPk.Encrypt(data)
	if err != nil {
		log.Printf("Node %d failed to encrypt transaction %s", u.cfg.nodeId, tx)
		return nil, err
	}
	// Sign encryption transaction
	h := sha256.Sum256(e.Bytes())
	pH, err := tcrsa.PrepareDocumentHash(u.tcs.keyMeta.PublicKey.Size(), crypto.SHA256, h[:])
	if err != nil {
		log.Printf("Node %d failed to hash transaction %s", u.cfg.nodeId, tx)
		return nil, err
	}
	sig, err := u.tcs.sigSk.Sign(pH, crypto.SHA256, u.tcs.keyMeta)
	if err != nil {
		log.Printf("Node %d failed to sign transaction %s", u.cfg.nodeId, tx)
		return nil, err
	}
	mes := &blockMessage{
		sender:  u.cfg.nodeId,
		status:  status,
		payload: e.Bytes(),
		sig:     sig,
	}
	m := &utils.Message{
		Sender:  u.cfg.nodeId,
		Payload: mes,
	}
	return m, nil
}

// handleSmallBlockMessage saves incoming blockMessages containing small blocks.
func (u *Upgrade) handleSmallBlockMessage(r int, m *blockMessage, b *utils.PreBlock, rdy *bool, mu *sync.Mutex) {
	mu.Lock()
	defer mu.Unlock()
	if b.Vec[m.sender] == nil {
		pbMes := &utils.PreBlockMessage{
			Message: m.payload,
			Sig:     m.sig,
		}
		b.Vec[m.sender] = pbMes
		if b.Quality() >= u.cfg.n-u.cfg.t && !*rdy {
			*rdy = true
		}
	}
}

// handleLargeBlockMessage saves incoming blockMessages containing large blocks.
func (u *Upgrade) handleLargeBlockMessage(r int, m *blockMessage, b *utils.PreBlock, rdy *bool, mu *sync.Mutex) {
	mu.Lock()
	defer mu.Unlock()
	if b.Vec[m.sender] == nil {
		pbMes := &utils.PreBlockMessage{
			Message: m.payload,
			Sig:     m.sig,
		}
		b.Vec[m.sender] = pbMes

		if b.Quality() >= u.cfg.n-u.cfg.t && !*rdy {
			log.Printf("Node %d has a %d-quality pre-block", u.cfg.nodeId, b.Quality())
			*rdy = true
			h := b.Hash()
			paddedHash, err := tcrsa.PrepareDocumentHash(u.tcs.keyMeta.PublicKey.Size(), crypto.SHA256, h[:])
			if err != nil {
				log.Printf("Node %d failed to create a padded hash", u.cfg.nodeId)
				return
			}
			sig, err := u.tcs.sigSk.Sign(paddedHash, crypto.SHA256, u.tcs.keyMeta)
			if err != nil {
				log.Printf("Node %d failed to sign pre-block hash", u.cfg.nodeId)
				return
			}
			mes := &committeeMessage{
				sender:   u.cfg.nodeId,
				preBlock: b,
				hash:     h,
				hashSig:  sig,
				proof:    u.tcs.proof,
			}
			m := &utils.Message{
				Sender:  u.cfg.nodeId,
				Payload: mes,
			}
			u.multicast(m, r)
		}
	}
}

// handlePointerMessage saves a received block pointer, if the node has no current block pointer.
// If the node is in the committee and receives a well-formed block pointer, it multicasts it
func (u *Upgrade) handlePointerMessage(r int, m *pointerMessage, ptr *utils.BlockPointer, mu *sync.Mutex) {
	mu.Lock()
	defer mu.Unlock()
	// Only set pointer if there isn't already one.
	if ptr == nil {
		return
	}
	// If node is in committee check and pointer is well-formed, multicast it
	if u.cfg.committee[u.cfg.nodeId] {
		err := rsa.VerifyPKCS1v15(u.tcs.keyMeta.PublicKey, crypto.SHA256, m.pointer.BlockHash, m.pointer.Sig)
		if err != nil {
			log.Printf("Node %d received block pointer with invalid signature", u.cfg.nodeId)
			return
		}
		ptr = m.pointer
		ptrMes := &pointerMessage{
			sender:  u.cfg.nodeId,
			pointer: ptr,
		}
		m := &utils.Message{
			Sender:  u.cfg.nodeId,
			Payload: ptrMes,
		}
		u.multicast(m, r)
		return
	}
	// If ptr came from committee: if ptr == nil: set ptr
	if u.cfg.committee[m.sender] {
		*ptr = *m.pointer
	}
}

// handleCommitteeMessage saves incoming committeeMessages containing large blocks. If enough
// messages on the same block are received it combines a signature and multicasts a block pointer.
func (u *Upgrade) handleCommitteeMessage(r int, m *committeeMessage, ptr *utils.BlockPointer, mesRec *bool, blocksReceived map[[32]byte]map[int]*tcrsa.SigShare, mu *sync.Mutex) {
	// TODO: only multicast to committee. Handle in multicast func? check for message type and then
	// only send to committee members?
	mu.Lock()
	defer mu.Unlock()
	// Only if in committee
	if !u.cfg.committee[u.cfg.nodeId] {
		return
	}
	// If the committee message is invalid don't do anything
	if !u.isValidCommitteeMessage(m) {
		return
	}
	// TODO: upon receiving first mes from node or first mes per node?
	// Upon receiving first valid committee message, send to committee
	if !*mesRec {
		*mesRec = true
		paddedHash, err := tcrsa.PrepareDocumentHash(u.tcs.keyMeta.PublicKey.Size(), crypto.SHA256, m.hash[:])
		if err != nil {
			log.Printf("Node %d failed to hash pre-block", u.cfg.nodeId)
			return
		}
		hashSig, err := u.tcs.sigSk.Sign(paddedHash, crypto.SHA256, u.tcs.keyMeta)
		if err != nil {
			log.Printf("Node %d failed to sign hash of pre-block", u.cfg.nodeId)
			return
		}
		mes := &committeeMessage{
			sender:   u.cfg.nodeId,
			preBlock: m.preBlock,
			hash:     m.hash,
			hashSig:  hashSig,
			proof:    u.tcs.proof,
		}
		m := &utils.Message{
			Sender:  u.cfg.nodeId,
			Payload: mes,
		}
		u.multicast(m, r)
	}
	// Upon receiving tk+1 messages from distinct parties on same block: combine sig
	if blocksReceived[m.hash] == nil {
		blocksReceived[m.hash] = make(map[int]*tcrsa.SigShare)
	}
	blocksReceived[m.hash][m.sender] = m.hashSig
	if len(blocksReceived[m.hash]) >= u.cfg.tk+1 {
		log.Printf("Node %d received enough committee messages on same pre-block. Creating signature", u.cfg.nodeId)
		var sigShares tcrsa.SigShareList
		for _, s := range blocksReceived[m.hash] {
			sigShares = append(sigShares, s)
		}
		signature, err := sigShares.Join(m.hash[:], u.tcs.keyMeta)
		if err != nil {
			log.Printf("Node %d failed to create signature on pre-block hash. %s", u.cfg.nodeId, err)
		}
		bPtr := utils.NewBlockPointer(m.hash[:], signature)
		ptr = bPtr
		mes := &pointerMessage{
			sender:  u.cfg.nodeId,
			pointer: bPtr,
		}
		m := &utils.Message{
			Sender:  u.cfg.nodeId,
			Payload: mes,
		}
		u.multicast(m, r)
	}
}

// proposeTxs chooses l values v1, ..., vl uniformaly at random (without replacement) from the first
// m values in buf.
func (u *Upgrade) proposeTxs(l, m int) [][]byte {
	if m > len(u.buf) {
		m = len(u.buf)
	}
	indices := make(map[int]bool)
	result := make([][]byte, 0)
	for j := 0; j < l; j++ {
		i := rand.Intn(m)
		for indices[i] {
			i = rand.Intn(m)
		}
		indices[i] = true
		result = append(result, u.buf[i])
	}
	return result
}

// isValidCommitteeMessage returns whether a message from a committee member is valid. Three
// conditions must hold:
// 1. The signature on the id is valid.
// 2. The signature of the hash is valid.
// 3. The hash matches the hashed pre-block
func (u *Upgrade) isValidCommitteeMessage(m *committeeMessage) bool {
	// Condition 1:
	hash := sha256.Sum256([]byte(strconv.Itoa(m.sender)))
	paddedHash, err := tcrsa.PrepareDocumentHash(u.tcs.keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		log.Printf("Node %d was unable to hash sender id", u.cfg.nodeId)
		return false
	}
	if err = m.proof.Verify(paddedHash, u.tcs.keyMeta); err != nil {
		log.Printf("Node %d received invalid committee message: invalid id proof", u.cfg.nodeId)
		return false
	}

	// Condition 2:
	if err = m.hashSig.Verify(m.hash[:], u.tcs.keyMeta); err != nil {
		log.Printf("Node %d received invalid committee message: invalid signature on hash", u.cfg.nodeId)
		return false
	}

	// Condition 3:
	if m.preBlock.Hash() != m.hash {
		log.Printf("Node %d received invalid committee message: invalid block hash", u.cfg.nodeId)
		return false
	}
	return true
}
