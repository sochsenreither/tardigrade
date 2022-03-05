package upgrade

import (
	"bytes"
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
	bla "github.com/sochsenreither/upgrade/blockagreement"
	acs "github.com/sochsenreither/upgrade/commonsubset"
	utils "github.com/sochsenreither/upgrade/utils"
)

type ABC struct {
	cfg       *UpgradeConfig                          // Parameters for protocol
	acs       []*acs.CommonSubset                     // Subset instances
	bla       []*bla.BlockAgreement                   // Blockagreement instances
	tcs       *tcs                                    // Keys for threshold crypto system
	buf       [][]byte                                // Transaction buffer
	multicast func(msg *utils.Message, params ...int) // Function for multicasting messages
	receive   func(round int) *utils.Message          // Blocking function for receiving messages
	locks     map[int]*sync.Mutex                     // Lock per round
	blocks    map[int]*utils.Block                    // Maps round -> block
	sync.Mutex
}

type tcs struct {
	keyMeta *tcrsa.KeyMeta       // KeyMeta containig pks for verifying
	proof   *tcrsa.SigShare      // Signature on the node index signed by the dealer
	sigSk   *tcrsa.KeyShare      // Private signing key
	encSk   tcpaillier.KeyShare // Private encryption key
	encPk   tcpaillier.PubKey   // Public encryption key
	sync.Mutex
}

type UpgradeConfig struct {
	n         int          // Number of nodes
	nodeId    int          // Id of node
	t         int          // Number of maximum faulty nodes
	tk        int          // Threshold for distinct committee messages
	kappa     int          // Security parameter
	delta     int          // Round timer
	lambda    int          // spacing paramter
	epsilon   int          //
	committee map[int]bool // List of committee members
	txSize    int          // Transaction size in bytes
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

type preBlockMessage struct {
	sender   int
	preBlock *utils.PreBlock
}

// pbDecryptionShareMessage contains decryption shares per block of the acs output
type pbDecryptionShareMessage struct {
	sender    int
	decShares [][]*tcpaillier.DecryptionShare // One decryption share for every message in the block
}

func NewABC(cfg *UpgradeConfig, acs []*acs.CommonSubset, ba []*bla.BlockAgreement, tcs *tcs, multicastFunc func(msg *utils.Message, params ...int), receiveFunc func(nodeId, round int) *utils.Message) *ABC {
	tk := (((1 - cfg.epsilon) * cfg.kappa * cfg.t) / cfg.n)
	cfg.tk = tk
	receive := func(round int) *utils.Message {
		return receiveFunc(cfg.nodeId, round)
	}

	u := &ABC{
		cfg:       cfg,
		acs:       acs,
		bla:       ba,
		tcs:       tcs,
		buf:       make([][]byte, 0),
		multicast: multicastFunc,
		receive:   receive,
		locks:     make(map[int]*sync.Mutex),
		blocks:    make(map[int]*utils.Block),
	}
	return u
}

func (abc *ABC) Run(maxRound int) {
	stop := make(chan struct{}, maxRound*99)
	var wg sync.WaitGroup
	round := 0
	ticker := time.NewTicker(time.Duration(abc.cfg.lambda) * time.Millisecond)
	wg.Add(maxRound)
	// Start first round immediately
	go func() {
		abc.runProtocol(round)
		wg.Done()
	}()
	for {
		select {
		case <-stop:
			wg.Wait()
			log.Printf("Node %d: exiting", abc.cfg.nodeId)
			ticker.Stop()
			return
		case <-ticker.C:
			round++
			r := round
			go func() {
				if r >= maxRound {
					stop <- struct{}{}
					return
				}
				abc.runProtocol(r)
				wg.Done()
			}()
		}
	}
}

func (abc *ABC) runProtocol(r int) {
	log.Printf("Node %d: starting round %d", abc.cfg.nodeId, r)
	// Ticker for starting BLA
	blaTicker := time.NewTicker(time.Duration(4*abc.cfg.delta) * time.Millisecond)

	// Every round needs a unique lock. Otherwise we could have the case of 10 rounds running in
	// parallel and one agent of round x blocking every other agent in rounds y != x when taking
	// the lock.
	var mu sync.Mutex
	abc.Lock()
	abc.locks[r] = &mu
	abc.Unlock()

	largePb := utils.NewPreBlock(abc.cfg.n)            // large pre-block
	readyLarge := false                                // Set when n-t-quality pre-block is received
	smallPb := utils.NewPreBlock(abc.cfg.n)            // Small pre-pointer
	readySmall := false                                // Set when n-t-quality pre-block is received
	readyChan := make(chan struct{}, 9999)             // Notify when ready == true
	ptrChan := make(chan struct{}, 9999)               // Notify when ptr != nil
	mesRec := make(map[int]bool)                       // NodeId -> message received
	var ptr *utils.BlockPointer                        // Blockpointer
	largeBlockChan := make(chan *utils.PreBlock, 9999) // Buffer for received large pre-blocks
	pbChan := make(chan *utils.PreBlock, 9999)         // Chan for pre-block that matches ptr from acs
	decChan := make(chan [][]*tcpaillier.DecryptionShare, abc.cfg.n*99)

	// Listener functions that handles incoming messages
	listener := func() {
		// Maps hash(block) -> nodeId -> sigShare
		blocksReceived := make(map[[32]byte]map[int]*tcrsa.SigShare)
		for {
			msg := abc.receive(r)
			switch m := msg.Payload.(type) {
			case *blockMessage:
				if m.status == "large" && abc.cfg.committee[abc.cfg.nodeId] {
					abc.handleLargeBlockMessage(r, m, largePb, &readyLarge, abc.locks[r], readyChan)
				} else {
					abc.handleSmallBlockMessage(r, m, smallPb, &readySmall, abc.locks[r], readyChan)
				}
			case *pointerMessage:
				abc.Lock()
				l := abc.locks[r]
				abc.Unlock()
				abc.handlePointerMessage(r, m, &ptr, l, ptrChan)
			case *committeeMessage:
				largeBlockChan <- m.preBlock
				abc.handleCommitteeMessage(r, m, &ptr, mesRec, blocksReceived, abc.locks[r], ptrChan)
			case *pbDecryptionShareMessage:
				//log.Printf("Node %d: receiving decryption share. decshares: %d from %d", abc.cfg.nodeId, len(m.decShares), m.sender)
				decChan <- m.decShares
			case *preBlockMessage:
				//log.Printf("Node %d: receiving pre-block", abc.cfg.nodeId)
				pbChan <- m.preBlock
			}
		}
	}
	go listener()

	// At time 0 propose transactions:
	go func() {
		l := abc.cfg.n * abc.cfg.n * abc.cfg.kappa
		v := abc.proposeTxs(l/abc.cfg.n, l)
		w := abc.proposeTxs(l/abc.cfg.n, l)

		// Encrypt each v_i in v and send it to node_i
		// TODO: how to handle the case where the buffer is not large enough and v can't be splitted
		// into n txs?
		//log.Printf("Node %d: is sending small blocks to nodes", abc.cfg.nodeId)
		for i, tx := range v {
			abc.handleSmallTransaction(i, r, tx)
		}

		// Encrypt w and send it to each committee member
		//log.Printf("Node %d: is sending a large block to the committee", abc.cfg.nodeId)
		abc.handleLargeTransaction(r, w)
	}()

	// At time 4 delta, run BLA:
	<-blaTicker.C
	blaTicker.Stop()

	mu.Lock()
	if readySmall && ptr != nil {
		//log.Printf("Node %d: starting BLA in round %d", abc.cfg.nodeId, r)
		bs := utils.NewBlockShare(smallPb, ptr)
		mu.Unlock()
		abc.bla[r].SetInput(bs)
		abc.bla[r].Run()
	} else {
		mu.Unlock()
	}

	// At time 5 delta + 5 kappa delta, get output of BLA and run ACS:
	// TODO: for testing set blaOutput to nil.
	blaOutput := abc.bla[r].GetValue()

	if blaOutput == nil {
		//log.Printf("Node %d: BLA failed in round %d", abc.cfg.nodeId, r)
	} else {
		//log.Printf("Node %d: received output from BLA", abc.cfg.nodeId)
	}

	if abc.isWellFormedBlockShare(blaOutput) {
		// If blaOutput is well-formed, input it to ACS
		//log.Printf("Node %d: Running ACS with BLA output", abc.cfg.nodeId)
		abc.acs[r].SetInput(blaOutput)
		abc.acs[r].Run()
	} else {
		// Else wait until ready is true and pointer != nil and input that to ACS
		//log.Printf("Node %d: Waiting for blocks", abc.cfg.nodeId)
		<-readyChan
		<-ptrChan
		bs := utils.NewBlockShare(smallPb, ptr)
		//log.Printf("Node %d: Running ACS after failed BLA", abc.cfg.nodeId)
		abc.acs[r].SetInput(bs)
		go abc.acs[r].Run()
	}

	acsOutput := abc.acs[r].GetValue()
	var block *utils.Block
	//log.Printf("Node %d: received output from ACS. len: %d", abc.cfg.nodeId, len(acsOutput))
	if len(acsOutput) == 1 {
		if abc.cfg.committee[abc.cfg.nodeId] {
			abc.waitForMatchingBlock(r, acsOutput[0].Pointer, largeBlockChan)
		}
		for pb := range pbChan {
			h := pb.Hash()
			if bytes.Equal(acsOutput[0].Pointer.BlockHash, h[:]) {
				block = abc.constructBlock(r, []*utils.PreBlock{pb}, decChan)
			}
			if block != nil {
				break
			}
		}
	} else {
		if abc.cfg.committee[abc.cfg.nodeId] {
			abc.sendDecryptionShares(r, acsOutput)
		}
		preBlocks := make([]*utils.PreBlock, len(acsOutput))
		for i, bs := range acsOutput {
			preBlocks[i] = bs.Block
		}
		block = abc.constructBlock(r, preBlocks, decChan)
	}

	count := abc.setBlock(r, block)
	log.Printf("Node %d: finishing round %d with %d transactions", abc.cfg.nodeId, r, count)
}

// SetBlock removes all transactions from the buffer that are in the block and sets the block of
// the current round. Note: duplicate transactions in the buffer won't get removed, but there
// souldn't be duplicates anyway. Returns the amount of transactions in the block.
func (abc *ABC) setBlock(r int, block *utils.Block) int {
	// Merge all transactions into one byte slice
	var txs []byte
	for _, tx := range block.Txs {
		txs = append(txs, tx...)
	}

	// Iterate over the array and split it into txSized chunks
	var committedTxs [][]byte
	for i := 0; i < len(txs); i += abc.cfg.txSize {
		end := i + abc.cfg.txSize

		if end > len(txs) {
			end = len(txs)
		}

		committedTxs = append(committedTxs, txs[i:end])
	}

	// Removes an element at index i
	remove := func(arr [][]byte, i int) [][]byte {
		arr[i] = arr[len(arr)-1]
		// Setup last element to nil, so that the garbage collector can clean up properly
		arr[len(arr)-1] = nil
		return arr[:len(arr)-1]
	}

	abc.Lock()
	for _, tx := range committedTxs {
		for i, bufTx := range abc.buf {
			if bytes.Equal(tx, bufTx) {
				abc.buf = remove(abc.buf, i)
			}
		}
	}

	abc.blocks[r] = block
	abc.Unlock()

	return len(txs) / abc.cfg.txSize
}

func (abc *ABC) constructBlock(r int, b []*utils.PreBlock, decChan chan [][]*tcpaillier.DecryptionShare) *utils.Block {
	//log.Printf("Node %d: constructing block. Block is of %d-quality.", abc.cfg.nodeId, b[0].Quality())
	txs := make([][]byte, 0)

	// bl := b[0]
	// for i, v := range bl.Vec {
	// 	log.Printf("Node %d: %d - %x", abc.cfg.nodeId, i, v.Message)
	// }
	decshares := make([][][]*tcpaillier.DecryptionShare, len(b))
	for i := range decshares {
		decshares[i] = make([][]*tcpaillier.DecryptionShare, abc.cfg.n)
	}
	decCounter := 0
	bytesCounter := 0

	for s := range decChan {
		for i, shares := range s {
			for j, share := range shares {
				decshares[i][j] = append(decshares[i][j], share)
				if len(decshares[i][j]) > abc.cfg.n/2 {
					dec, err := abc.tcs.encPk.CombineShares(decshares[i][j]...)
					if err != nil {
						log.Printf("Node %d: failed to decrypt ciphertext. %s", abc.cfg.nodeId, err)
					}
					txs = append(txs, dec.Bytes())
					//log.Printf("Node %d: %d - %s", abc.cfg.nodeId, j, dec.Bytes())
					bytesCounter += len(dec.Bytes())
					decCounter++
					if decCounter == abc.cfg.n-abc.cfg.t {
						goto Done
					}
				}
			}
		}
	}

Done:
	//log.Printf("Node %d: done constructing block. Total of %d bytes", abc.cfg.nodeId, bytesCounter)
	block := &utils.Block{
		Txs: txs,
	}
	// for _, tx := range txs {
	// 	log.Printf("Node %d round %d: final txs: %x - %dB", abc.cfg.nodeId, r, tx, len(tx))
	// }
	return block
}

// sendDecryptionShares sends for every tx in every block a decryption share
func (abc *ABC) sendDecryptionShares(r int, acsOutput []*utils.BlockShare) {
	decShares := make([][]*tcpaillier.DecryptionShare, len(acsOutput))
	for i, bs := range acsOutput {
		decShares[i] = make([]*tcpaillier.DecryptionShare, len(bs.Block.Vec))
		for j, v := range bs.Block.Vec {
			if v == nil {
				// TODO: bug? why can there be a mes == nil in here?
				continue
			}
			tmp := new(big.Int)
			tmp.SetBytes(v.Message)
			decShare, err := abc.tcs.encSk.PartialDecrypt(tmp)
			if err != nil {
				log.Printf("Node %d: is unable to partially decrypt message[%d]: %s. %s", abc.cfg.nodeId, j, v.Message, err)
				continue
			}
			decShares[i][j] = decShare
		}
	}

	mes := &pbDecryptionShareMessage{
		sender:    abc.cfg.nodeId,
		decShares: decShares,
	}
	m := &utils.Message{
		Sender:  abc.cfg.nodeId,
		Payload: mes,
	}
	//log.Printf("Node %d: multicasting decryption shares", abc.cfg.nodeId)
	abc.multicast(m, r)
}

// TODO: description. committee sends matching pre-block + dec share or waits until it receives
func (abc *ABC) waitForMatchingBlock(r int, ptr *utils.BlockPointer, largeBlockChan chan *utils.PreBlock) {
	done := false
	for pb := range largeBlockChan {
		h := pb.Hash()
		if done {
			return
		}
		if bytes.Equal(h[:], ptr.BlockHash) {
			// Multicast pre-block
			pbmes := &preBlockMessage{
				sender:   abc.cfg.nodeId,
				preBlock: pb,
			}
			pbm := &utils.Message{
				Sender:  abc.cfg.nodeId,
				Payload: pbmes,
			}
			//log.Printf("Node %d: multicasting matching pre-block", abc.cfg.nodeId)
			abc.multicast(pbm, r)

			// Multicast decryption shares
			decShares := make([]*tcpaillier.DecryptionShare, len(pb.Vec))
			for i, v := range pb.Vec {
				tmp := new(big.Int)
				tmp.SetBytes(v.Message)
				decShare, err := abc.tcs.encSk.PartialDecrypt(tmp)
				if err != nil {
					log.Printf("Node %d: is unable to partially decrypt message[%d]: %s. %s", abc.cfg.nodeId, i, v.Message, err)
					continue
				}
				decShares[i] = decShare
			}
			mes := &pbDecryptionShareMessage{
				sender:    abc.cfg.nodeId,
				decShares: [][]*tcpaillier.DecryptionShare{decShares},
			}
			m := &utils.Message{
				Sender:  abc.cfg.nodeId,
				Payload: mes,
			}
			//log.Printf("Node %d: multicasting decrpytion share", abc.cfg.nodeId)
			abc.multicast(m, r)
		}
		done = true
	}
}

// isWellFormedBlockShare returns whether a block share is well-formed. That is if the signature is
// valid.
func (abc *ABC) isWellFormedBlockShare(bs *utils.BlockShare) bool {
	if bs == nil {
		return false
	}
	err := rsa.VerifyPKCS1v15(abc.tcs.keyMeta.PublicKey, crypto.SHA256, bs.Pointer.BlockHash, bs.Pointer.Sig)
	return err == nil
}

// handleLargeTransaction sends a blockMessage containing encrypted transactions w to the committee.
func (abc *ABC) handleLargeTransaction(r int, w [][]byte) {
	// Merge slice of byte slices to one byte slice
	tx := make([]byte, 0)
	for _, t := range w {
		tx = append(tx, t...)
	}
	//log.Printf("Node %d round %d: proposing %x - %dB", abc.cfg.nodeId, r, tx, len(tx))
	data := new(big.Int)
	data.SetBytes(tx)

	m, err := abc.encryptAndSign(data, "large")
	if err != nil {
		return
	}
	// Only send to committee members
	for i := 0; i < abc.cfg.n; i++ {
		if abc.cfg.committee[i] {
			abc.multicast(m, r, i)
		}
	}
}

// handleSmallTransaction sends a blockMessage containing encrypted transaction tx to node i.
func (abc *ABC) handleSmallTransaction(i, r int, tx []byte) {
	data := new(big.Int)
	data.SetBytes(tx)
	m, err := abc.encryptAndSign(data, "small")
	if err != nil {
		return
	}
	abc.multicast(m, r, i)
}

// encryptAndSign encrypts data, signs the hash of the encrypted value and returns a blockMessage
// wrapped into a Message
func (abc *ABC) encryptAndSign(data *big.Int, status string) (*utils.Message, error) {
	tx := string(data.Bytes())
	// Encrypt transaction
	e, _, err := abc.tcs.encPk.Encrypt(data)
	if err != nil {
		log.Printf("Node %d: failed to encrypt transaction %s", abc.cfg.nodeId, tx)
		return nil, err
	}
	// Sign encryption transaction
	h := sha256.Sum256(e.Bytes())
	pH, err := tcrsa.PrepareDocumentHash(abc.tcs.keyMeta.PublicKey.Size(), crypto.SHA256, h[:])
	if err != nil {
		log.Printf("Node %d: failed to hash transaction %s", abc.cfg.nodeId, tx)
		return nil, err
	}
	sig, err := abc.tcs.sigSk.Sign(pH, crypto.SHA256, abc.tcs.keyMeta)
	if err != nil {
		log.Printf("Node %d: failed to sign transaction %s", abc.cfg.nodeId, tx)
		return nil, err
	}
	mes := &blockMessage{
		sender:  abc.cfg.nodeId,
		status:  status,
		payload: e.Bytes(),
		sig:     sig,
	}
	m := &utils.Message{
		Sender:  abc.cfg.nodeId,
		Payload: mes,
	}
	return m, nil
}

// handleSmallBlockMessage saves incoming blockMessages containing small blocks.
func (abc *ABC) handleSmallBlockMessage(r int, m *blockMessage, b *utils.PreBlock, rdy *bool, mu *sync.Mutex, readyChan chan struct{}) {
	mu.Lock()
	defer mu.Unlock()
	if b.Vec[m.sender] == nil {
		pbMes := &utils.PreBlockMessage{
			Message: m.payload,
			Sig:     m.sig,
		}
		b.Vec[m.sender] = pbMes
		if b.Quality() >= abc.cfg.n-abc.cfg.t && !*rdy {
			*rdy = true
			readyChan <- struct{}{}
		}
	}
}

// handleLargeBlockMessage saves incoming blockMessages containing large blocks.
func (abc *ABC) handleLargeBlockMessage(r int, m *blockMessage, b *utils.PreBlock, rdy *bool, mu *sync.Mutex, readyChan chan struct{}) {
	mu.Lock()
	defer mu.Unlock()
	if b.Vec[m.sender] == nil {
		//log.Printf("Node %d: received from %d: %x", abc.cfg.nodeId, m.sender, m.payload)
		pbMes := &utils.PreBlockMessage{
			Message: m.payload,
			Sig:     m.sig,
		}
		b.Vec[m.sender] = pbMes

		if b.Quality() >= abc.cfg.n-abc.cfg.t && !*rdy {
			//log.Printf("Node %d: has a %d-quality pre-block", abc.cfg.nodeId, b.Quality())
			*rdy = true
			readyChan <- struct{}{}
			h := b.Hash()
			paddedHash, err := tcrsa.PrepareDocumentHash(abc.tcs.keyMeta.PublicKey.Size(), crypto.SHA256, h[:])
			if err != nil {
				log.Printf("Node %d: failed to create a padded hash", abc.cfg.nodeId)
				return
			}
			sig, err := abc.tcs.sigSk.Sign(paddedHash, crypto.SHA256, abc.tcs.keyMeta)
			if err != nil {
				log.Printf("Node %d: failed to sign pre-block hash", abc.cfg.nodeId)
				return
			}
			mes := &committeeMessage{
				sender:   abc.cfg.nodeId,
				preBlock: b,
				hash:     h,
				hashSig:  sig,
				proof:    abc.tcs.proof,
			}
			m := &utils.Message{
				Sender:  abc.cfg.nodeId,
				Payload: mes,
			}

			//log.Printf("Node %d multicasting %d-quality pre-block to committee", abc.cfg.nodeId, b.Quality())
			// Only send to committee members
			for i := 0; i < abc.cfg.n; i++ {
				if abc.cfg.committee[i] {
					abc.multicast(m, r, i)
				}
			}
		}
	}
}

// handlePointerMessage saves a received block pointer, if the node has no current block pointer.
// If the node is in the committee and receives a well-formed block pointer, it multicasts it
func (abc *ABC) handlePointerMessage(r int, m *pointerMessage, ptr **utils.BlockPointer, mu *sync.Mutex, ptrChan chan struct{}) {
	mu.Lock()
	defer mu.Unlock()
	// Only set pointer if there isn't already one.
	if *ptr != nil {
		return
	}
	// If node is in committee check if pointer is well-formed, multicast it
	if abc.cfg.committee[abc.cfg.nodeId] {
		err := rsa.VerifyPKCS1v15(abc.tcs.keyMeta.PublicKey, crypto.SHA256, m.pointer.BlockHash, m.pointer.Sig)
		if err != nil {
			log.Printf("Node %d: received block pointer with invalid signature: %s", abc.cfg.nodeId, err)
			return
		}
		*ptr = m.pointer
		ptrChan <- struct{}{}
		ptrMes := &pointerMessage{
			sender:  abc.cfg.nodeId,
			pointer: *ptr,
		}
		m := &utils.Message{
			Sender:  abc.cfg.nodeId,
			Payload: ptrMes,
		}
		abc.multicast(m, r)
		return
	}
	// If ptr came from committee: if ptr == nil: set ptr
	if abc.cfg.committee[m.sender] {
		*ptr = m.pointer
		ptrChan <- struct{}{}
	}
}

// handleCommitteeMessage saves incoming committeeMessages containing large blocks. If enough
// messages on the same block are received it combines a signature and multicasts a block pointer.
func (abc *ABC) handleCommitteeMessage(r int, m *committeeMessage, ptr **utils.BlockPointer, mesRec map[int]bool, blocksReceived map[[32]byte]map[int]*tcrsa.SigShare, mu *sync.Mutex, ptrChan chan struct{}) {
	mu.Lock()
	defer mu.Unlock()
	// Only if in committee
	if !abc.cfg.committee[abc.cfg.nodeId] {
		return
	}
	// If the committee message is invalid don't do anything
	if !abc.isValidCommitteeMessage(m) {
		return
	}
	// Echo first valid committee messages received by any committee member, but only when the block
	// pointer is nil.
	if !mesRec[m.sender] && ptr == nil {
		mesRec[m.sender] = true
		paddedHash, err := tcrsa.PrepareDocumentHash(abc.tcs.keyMeta.PublicKey.Size(), crypto.SHA256, m.hash[:])
		if err != nil {
			log.Printf("Node %d: failed to hash pre-block", abc.cfg.nodeId)
			return
		}
		hashSig, err := abc.tcs.sigSk.Sign(paddedHash, crypto.SHA256, abc.tcs.keyMeta)
		if err != nil {
			log.Printf("Node %d: failed to sign hash of pre-block", abc.cfg.nodeId)
			return
		}
		mes := &committeeMessage{
			sender:   abc.cfg.nodeId,
			preBlock: m.preBlock,
			hash:     m.hash,
			hashSig:  hashSig,
			proof:    abc.tcs.proof,
		}
		m := &utils.Message{
			Sender:  abc.cfg.nodeId,
			Payload: mes,
		}
		// Only send to committee members
		for i := 0; i < abc.cfg.n; i++ {
			if abc.cfg.committee[i] {
				abc.multicast(m, r, i)
			}
		}
	}
	// Upon receiving tk+1 messages from distinct parties on same block: combine sig
	if blocksReceived[m.hash] == nil {
		blocksReceived[m.hash] = make(map[int]*tcrsa.SigShare)
	}
	blocksReceived[m.hash][m.sender] = m.hashSig
	// TODO: num of block needs to be >= abc.cfg.tk+1. But we need n/2+1 sigshares
	if len(blocksReceived[m.hash]) >= abc.cfg.n/2+1 {
		//log.Printf("Node %d: received enough committee messages on same pre-block. Creating signature", abc.cfg.nodeId)
		// for _, v := range m.preBlock.Vec {
		// 	log.Printf("Node %d: %x", abc.cfg.nodeId, v.Message)
		// }
		var sigShares tcrsa.SigShareList
		for _, s := range blocksReceived[m.hash] {
			sigShares = append(sigShares, s)
		}
		h, err := tcrsa.PrepareDocumentHash(abc.tcs.keyMeta.PublicKey.Size(), crypto.SHA256, m.hash[:])
		if err != nil {
			log.Printf("Node %d: failed to pad block hash", abc.cfg.nodeId)
			return
		}
		signature, err := sigShares.Join(h, abc.tcs.keyMeta)
		if err != nil {
			log.Printf("Node %d: failed to create signature on pre-block hash. %s", abc.cfg.nodeId, err)
		}

		bPtr := utils.NewBlockPointer(m.hash[:], signature)

		*ptr = bPtr
		ptrChan <- struct{}{}
		mes := &pointerMessage{
			sender:  abc.cfg.nodeId,
			pointer: bPtr,
		}
		m := &utils.Message{
			Sender:  abc.cfg.nodeId,
			Payload: mes,
		}
		abc.multicast(m, r)
	}
}

// isValidCommitteeMessage returns whether a message from a committee member is valid. Three
// conditions must hold:
// 1. The signature on the id is valid.
// 2. The signature of the hash is valid.
// 3. The hash matches the hashed pre-block
func (abc *ABC) isValidCommitteeMessage(m *committeeMessage) bool {
	// Condition 1:
	hash := sha256.Sum256([]byte(strconv.Itoa(m.sender)))
	paddedHash, err := tcrsa.PrepareDocumentHash(abc.tcs.keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		log.Printf("Node %d: was unable to hash sender id", abc.cfg.nodeId)
		return false
	}
	if err = m.proof.Verify(paddedHash, abc.tcs.keyMeta); err != nil {
		log.Printf("Node %d: received invalid committee message: invalid id proof", abc.cfg.nodeId)
		return false
	}

	// Condition 2:
	paddedHash, err = tcrsa.PrepareDocumentHash(abc.tcs.keyMeta.PublicKey.Size(), crypto.SHA256, m.hash[:])
	if err != nil {
		log.Printf("Node %d: unable to pad block hash", abc.cfg.nodeId)
		return false
	}
	if err = m.hashSig.Verify(paddedHash, abc.tcs.keyMeta); err != nil {
		log.Printf("Node %d: received invalid committee message: invalid signature on hash: %s", abc.cfg.nodeId, err)
		return false
	}

	// Condition 3:
	if m.preBlock.Hash() != m.hash {
		log.Printf("Node %d: received invalid committee message: invalid block hash", abc.cfg.nodeId)
		return false
	}
	return true
}

// proposeTxs chooses l values v1, ..., vl uniformaly at random (without replacement) from the first
// m values in buf.
func (abc *ABC) proposeTxs(l, m int) [][]byte {
	abc.Lock()
	defer abc.Unlock()
	if m > len(abc.buf) {
		m = len(abc.buf)
	}
	indices := make(map[int]bool)
	result := make([][]byte, 0)
	for j := 0; j < l; j++ {
		i := rand.Intn(m)
		for indices[i] {
			i = rand.Intn(m)
		}
		indices[i] = true
		result = append(result, abc.buf[i])
	}

	return result
}

// FillBuffer appends a slice of transactions to the buffer.
func (abc *ABC) FillBuffer(txs [][]byte) {
	abc.Lock()
	defer abc.Unlock()
	abc.buf = append(abc.buf, txs...)
}

// GetBlocks returns a copy of the blocks.
func (abc *ABC) GetBlocks() map[int]*utils.Block {
	ret := make(map[int]*utils.Block)
	abc.Lock()
	defer abc.Unlock()

	for key, block := range abc.blocks {
		ret[key] = block
	}

	return ret
}
