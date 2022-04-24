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
	Cfg            *ABCConfig                                      // Parameters for protocol
	acss           []*acs.CommonSubset                             // Subset instances
	blas           []*bla.BlockAgreement                           // Blockagreement instances
	tcs            *tcs                                            // Keys for threshold crypto system
	buf            [][]byte                                        // Transaction buffer
	multicast      func(msg *utils.Message, round int, rec ...int) // Function for multicasting messages
	receive        func(round int) *utils.Message                  // Function for receiving messages
	blocks         map[int]*utils.Block                            // Maps round -> block
	latency        map[[32]byte]time.Time                          // TODO: refactor this?
	LatencyTotal   time.Duration
	FinishedRounds int
	sync.Mutex
}

type BlockMessage struct {
	Sender  int
	Status  string          // "large" or "small"
	Payload []byte          // Encrypted data
	Sig     *tcrsa.SigShare // Signature on payload
}

type CommitteeMessage struct {
	Sender   int
	PreBlock *utils.PreBlock
	Hash     [32]byte        // Hash of the pre-block
	HashSig  *tcrsa.SigShare // Signature of the hash
	Proof    *tcrsa.SigShare // Signature of the dealer on the nodeId of the sender
}

type PointerMessage struct {
	Sender  int
	Pointer *utils.BlockPointer
}

type PreBlockMessage struct {
	Sender   int
	PreBlock *utils.PreBlock
}

// PbDecryptionShareMessage contains decryption shares per block of the acs output
type PbDecryptionShareMessage struct {
	Sender    int
	DecShares [][]*tcpaillier.DecryptionShare // One decryption share for every message in the block
}

func NewABC(cfg *ABCConfig, tcs *tcs) *ABC {
	tk := (((1 - cfg.epsilon) * cfg.kappa * cfg.ta) / cfg.n)
	cfg.tk = tk
	receive := func(round int) *utils.Message {
		return cfg.handlerFuncs.ABCreceive(round)
	}
	multicast := func(msg *utils.Message, round int, receiver ...int) {
		if len(receiver) == 1 {
			cfg.handlerFuncs.ABCmulticast(msg, round, receiver[0])
		} else {
			cfg.handlerFuncs.ABCmulticast(msg, round, -1)
		}

	}

	acss := make([]*acs.CommonSubset, 0)
	blas := make([]*bla.BlockAgreement, 0)

	u := &ABC{
		Cfg:            cfg,
		acss:           acss,
		blas:           blas,
		tcs:            tcs,
		buf:            make([][]byte, 0),
		multicast:      multicast,
		receive:        receive,
		blocks:         make(map[int]*utils.Block),
		latency:        make(map[[32]byte]time.Time),
		LatencyTotal:   time.Duration(0),
		FinishedRounds: 0,
	}
	return u
}

func (abc *ABC) Run(maxRound int, roundCfg utils.RoundConfigs, start time.Time) {
	<-time.After(time.Until(start))
	startTime := time.Now()
	log.Printf("Node %d starting", abc.Cfg.NodeId)
	go abc.Cfg.handlerFuncs.Receiver()

	stop := make(chan struct{}, 100)
	var wg sync.WaitGroup
	round := 0
	ticker := time.NewTicker(time.Duration(abc.Cfg.lambda) * time.Millisecond)
	if maxRound > 0 {
		wg.Add(maxRound)
	}
	// Start first round immediately
	go func() {
		abc.acss = append(abc.acss, setupACS(0, abc.Cfg, abc.tcs, roundCfg[0].Ta))
		abc.blas = append(abc.blas, setupBLA(0, abc.Cfg, abc.tcs, roundCfg[0].Ts))
		abc.runProtocol(0, roundCfg[0])
		if maxRound > 0 {
			wg.Done()
		}
	}()
	for {
		select {
		case <-stop:
			wg.Wait()
			log.Printf("Node %d exiting with runtime %d", abc.Cfg.NodeId, time.Since(startTime).Milliseconds())
			ticker.Stop()
			return
		case <-ticker.C:
			abc.Lock()
			round++
			abc.Unlock()
			r := round
			if r >= maxRound && maxRound > 0 {
				stop <- struct{}{}
			} else {
				go func() {
					abc.runProtocol(r, roundCfg[r])
					if maxRound > 0 {
						wg.Done()
					}
				}()
				// setup acs and bla for the next round
				abc.acss = append(abc.acss, setupACS(r, abc.Cfg, abc.tcs, roundCfg[r].Ta))
				abc.blas = append(abc.blas, setupBLA(r, abc.Cfg, abc.tcs, roundCfg[r].Ts))
			}
		}
	}
}

func (abc *ABC) runProtocol(r int, rcfg *utils.RoundConfig) {
	if rcfg.Crashed[abc.Cfg.NodeId] {
		// Crash node for current round
		log.Printf("Node %d crashing in round %d", abc.Cfg.NodeId, r)
		return
	}
	startTotal := time.Now()

	// log.Printf("Node %d: starting round %d\n", abc.Cfg.NodeId, r)
	// Ticker for starting BLA
	blaTicker := time.NewTicker(time.Duration(4*abc.Cfg.delta) * time.Millisecond)

	// Every round needs a unique lock.
	var mu sync.Mutex

	largePb := utils.NewPreBlock(abc.Cfg.n - rcfg.Ta) // large pre-block
	largePb.Size = "large"
	readyLarge := false                               // Set when n-t-quality pre-block is received
	smallPb := utils.NewPreBlock(abc.Cfg.n - rcfg.Ta) // Small pre-pointer
	smallPb.Size = "small"
	readySmall := false                                // Set when n-t-quality pre-block is received
	readyChan := make(chan struct{}, 9999)             // Notify when ready == true
	ptrChan := make(chan struct{}, 9999)               // Notify when ptr != nil
	mesRec := make(map[int]bool)                       // NodeId -> message received
	var ptr *utils.BlockPointer                        // Blockpointer
	largeBlockChan := make(chan *utils.PreBlock, 9999) // Buffer for received large pre-blocks
	pbChan := make(chan *utils.PreBlock, 9999)         // Chan for pre-block that matches ptr from acs
	decChan := make(chan [][]*tcpaillier.DecryptionShare, abc.Cfg.n*99)

	// Listener function that handles incoming messages
	listener := func() {
		// Maps hash(block) -> nodeId -> sigShare
		blocksReceived := make(map[[32]byte]map[int]*tcrsa.SigShare)
		for {
			msg := abc.receive(r)
			log.Printf("Received message from %d", msg.Sender)
			switch m := msg.Payload.(type) {
			case *BlockMessage:
				if m.Status == "large" && abc.Cfg.committee[abc.Cfg.NodeId] {
					abc.handleLargeBlockMessage(r, rcfg.Ta, m, largePb, &readyLarge, &mu)
				} else {
					abc.handleSmallBlockMessage(r, rcfg.Ta, m, smallPb, &readySmall, &mu, readyChan)
				}
			case *PointerMessage:
				abc.handlePointerMessage(r, m, &ptr, &mu, ptrChan)
			case *CommitteeMessage:
				largeBlockChan <- m.PreBlock
				abc.handleCommitteeMessage(r, m, &ptr, mesRec, blocksReceived, &mu, ptrChan)
			case *PbDecryptionShareMessage:
				// log.Printf("Node %d: receiving decryption share. decshares: %d from %d", abc.cfg.nodeId, len(m.DecShares), m.Sender)
				decChan <- m.DecShares
			case *PreBlockMessage:
				//log.Printf("Node %d: receiving pre-block", abc.cfg.nodeId)
				pbChan <- m.PreBlock
			}
		}
	}
	go listener()

	// At time 0 propose transactions:
	go func() {
		// TODO: l should be multiplied by kappa. But then we have splitted transactions?
		l := abc.Cfg.n * abc.Cfg.n
		// abc.Lock()
		// bufLen := len(abc.buf)
		// abc.Unlock()
		v := abc.proposeTxs(l/abc.Cfg.n, l*abc.Cfg.kappa)
		w := abc.proposeTxs(l/abc.Cfg.n, l*abc.Cfg.kappa)

		// Encrypt each v_i in v and send it to node_i
		// log.Printf("Node %d round %d: is sending small blocks to nodes", abc.cfg.nodeId, r)
		for i, tx := range v {
			abc.handleSmallTransaction(i, r, tx)
		}

		// Encrypt w and send it to each committee member
		// log.Printf("Node %d round %d: is sending a large block to the committee", abc.cfg.nodeId, r)
		abc.handleLargeTransaction(r, w)
	}()

	// At time 4 delta, run BLA:
	<-blaTicker.C
	blaTicker.Stop()
	var blaOutput *utils.BlockShare

	mu.Lock()
	if readySmall && ptr != nil {
		// log.Printf("Node %d: starting BLA in round %d", abc.Cfg.NodeId, r)
		bs := utils.NewBlockShare(smallPb, ptr)
		mu.Unlock()
		abc.blas[r].SetInput(bs)
		abc.blas[r].Run()
		// At time 5 delta + 5 kappa delta, get output of BLA and run ACS:
		blaOutput = abc.blas[r].GetValue()
	} else {
		mu.Unlock()
		blaOutput = nil
		// Wait for 5 kappa delta
		t := time.NewTicker(time.Duration(5*abc.Cfg.kappa*abc.Cfg.delta) * time.Millisecond)
		<-t.C
		t.Stop()
	}

	var start time.Time

	if abc.isWellFormedBlockShare(blaOutput) {
		// If blaOutput is well-formed, input it to ACS
		// log.Printf("Node %d round %d: Running ACS with BLA output", abc.Cfg.NodeId, r)
		start = time.Now()
		abc.acss[r].SetInput(blaOutput)
		abc.acss[r].Run()
	} else {
		// Else wait until ready is true and pointer != nil and input that to ACS
		// log.Printf("Node %d round %d: Waiting for blocks", abc.Cfg.NodeId, r)
		<-readyChan
		<-ptrChan
		mu.Lock()
		bs := utils.NewBlockShare(smallPb, ptr)
		mu.Unlock()
		// log.Printf("Node %d round %d: Running ACS after failed BLA", abc.Cfg.NodeId, r)
		start = time.Now()
		abc.acss[r].SetInput(bs)
		go abc.acss[r].Run()
	}

	acsOutput := abc.acss[r].GetValue()
	acsTime := time.Since(start)
	var block *utils.Block
	// log.Printf("Node %d round %d: received output from ACS. len: %d", abc.Cfg.NodeId, r, len(acsOutput))
	if len(acsOutput) == 1 {
		// BLA was successfull and we got one large block as result
		if abc.Cfg.committee[abc.Cfg.NodeId] {
			abc.waitForMatchingBlock(r, acsOutput[0].Pointer, largeBlockChan)
		}
		for pb := range pbChan {
			h := pb.Hash()
			if bytes.Equal(acsOutput[0].Pointer.BlockHash, h[:]) {
				// We know the block is a large pre-block
				block = abc.constructBlock(r, []*utils.PreBlock{pb}, decChan)
			}
			if block != nil {
				break
			}
		}
	} else {
		if abc.Cfg.committee[abc.Cfg.NodeId] {
			abc.sendDecryptionShares(r, acsOutput)
		}
		preBlocks := make([]*utils.PreBlock, len(acsOutput))
		for i, bs := range acsOutput {
			preBlocks[i] = bs.Block
		}
		block = abc.constructBlock(r, preBlocks, decChan)
	}

	//abc.setBlock(r, block)
	count, uniqueTxs, latency := abc.setBlock(r, block)
	abc.Lock()
	abc.LatencyTotal += latency
	abc.FinishedRounds++
	abc.Unlock()
	runTimeTotal := time.Since(startTotal)
	proto := "bla"
	if len(acsOutput) != 1 {
		proto = "acs"
	}
	log.Printf("Node %d finished round %d with %s. txs: %d unique_txs: %d latency: %d t_acs: %d t_total: %d", abc.Cfg.NodeId, r, proto, count, uniqueTxs, latency.Milliseconds(), acsTime.Milliseconds(), runTimeTotal.Milliseconds())

}

// SetBlock removes all transactions from the buffer that are in the block and sets the block of
// the current round. Note: duplicate transactions in the buffer won't get removed, but there
// shouldn't be duplicates anyway. Returns the amount of transactions in the block.
func (abc *ABC) setBlock(r int, block *utils.Block) (int, int, time.Duration) {
	// Removes an element at index i
	remove := func(arr [][]byte, i int) [][]byte {
		arr[i] = arr[len(arr)-1]
		// Set last element to nil, so that the garbage collector can clean up properly
		arr[len(arr)-1] = nil
		return arr[:len(arr)-1]
	}

	abc.Lock()
	removedTxs := 0
	latency := time.Duration(0)
	for _, tx := range block.Txs {
		for i, bufTx := range abc.buf {
			if bytes.Equal(tx, bufTx) {
				//log.Printf("Node %d removing from buf: %s", abc.cfg.nodeId, tx)
				h := sha256.Sum256(tx)
				latency += time.Since(abc.latency[h])
				removedTxs++
				abc.buf = remove(abc.buf, i)
			}
		}
	}
	abc.blocks[r] = block
	abc.Unlock()

	// TODO: division by 0. What to do when there are no new transactions?
	if removedTxs == 0 {
		return len(block.Txs), removedTxs, latency
	} else {
		return len(block.Txs), removedTxs, latency / time.Duration(removedTxs)
	}
}

func (abc *ABC) constructBlock(r int, b []*utils.PreBlock, decChan chan [][]*tcpaillier.DecryptionShare) *utils.Block {
	//log.Printf("Node %d: constructing block.", abc.cfg.nodeId)
	txs := make([][]byte, 0)

	// Get number of total transactions.
	txsCount := 0
	for _, block := range b {
		txsCount += block.Quality()
	}
	// bl := b[0]
	// for i, v := range bl.Vec {
	// 	log.Printf("Node %d: %d - %x", abc.cfg.nodeId, i, v.Message)
	// }
	decCounter := 0
	bytesCounter := 0
	if len(b) == 1 {
		// Decrypt large block
		pb := b[0]
		decshares := make([][][]*tcpaillier.DecryptionShare, len(pb.Vec))
		for i := range decshares {
			decshares[i] = make([][]*tcpaillier.DecryptionShare, abc.Cfg.n)
		}

		for s := range decChan {
			for node, messageShares := range s {
				for message, share := range messageShares {
					if decshares[node][message] == nil {
						decshares[node][message] = make([]*tcpaillier.DecryptionShare, 0)
					}
					decshares[node][message] = append(decshares[node][message], share)
					if len(decshares[node][message]) >= len(abc.Cfg.committee)/2+1 {
						dec, err := abc.tcs.encPk.CombineShares(decshares[node][message]...)
						if err != nil {
							log.Printf("Node %d: failed to decrypt ciphertext. %s", abc.Cfg.NodeId, err)
							continue
						}
						txs = append(txs, dec.Bytes())
						//log.Printf("Node %d: %d - %s", abc.cfg.nodeId, j, dec.Bytes())
						bytesCounter += len(dec.Bytes())
						decCounter++
						if decCounter == txsCount*len(messageShares) {
							goto Done
						}
					}
				}
			}
		}
	} else {
		// Decrypt small blocks
		decshares := make([][][]*tcpaillier.DecryptionShare, len(b))
		for i := range decshares {
			decshares[i] = make([][]*tcpaillier.DecryptionShare, abc.Cfg.n)
		}

		for s := range decChan {
			for i, shares := range s {
				for j, share := range shares {
					if share != nil {
						decshares[i][j] = append(decshares[i][j], share)
					}
					if len(decshares[i][j]) >= len(abc.Cfg.committee)/2+1 {
						dec, err := abc.tcs.encPk.CombineShares(decshares[i][j]...)
						if err != nil {
							log.Printf("Node %d: failed to decrypt ciphertext. %s", abc.Cfg.NodeId, err)
							continue
						}
						txs = append(txs, dec.Bytes())
						//log.Printf("Node %d: %d - %s", abc.cfg.nodeId, j, dec.Bytes())
						bytesCounter += len(dec.Bytes())
						decCounter++
						if decCounter == txsCount {
							goto Done
						}
					}
				}
			}
		}
	}

Done:
	//log.Printf("Node %d: done constructing block. Total of %d bytes", abc.cfg.nodeId, bytesCounter)
	block := &utils.Block{
		Txs:      txs,
		TxsCount: bytesCounter / abc.Cfg.txSize,
	}
	// for _, tx := range txs {
	// 	log.Printf("Node %d round %d: final txs: %s - %dB", abc.cfg.nodeId, r, tx, len(tx))
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
				log.Printf("Node %d round %d: got nil in blockvec", abc.Cfg.NodeId, r)
				continue
			}
			tmp := new(big.Int)
			tmp.SetBytes(v.Message)
			decShare, err := abc.tcs.committeeKeys.encSk.PartialDecrypt(tmp)
			if err != nil {
				log.Printf("Node %d: is unable to partially decrypt message[%d]: %s. %s", abc.Cfg.NodeId, j, v.Message, err)
				continue
			}
			decShares[i][j] = decShare
		}
	}

	mes := &PbDecryptionShareMessage{
		Sender:    abc.Cfg.NodeId,
		DecShares: decShares,
	}
	m := &utils.Message{
		Sender:  abc.Cfg.NodeId,
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
			pbmes := &PreBlockMessage{
				Sender:   abc.Cfg.NodeId,
				PreBlock: pb,
			}
			pbm := &utils.Message{
				Sender:  abc.Cfg.NodeId,
				Payload: pbmes,
			}
			//log.Printf("Node %d: multicasting matching pre-block", abc.cfg.nodeId)
			abc.multicast(pbm, r)

			// Multicast decryption shares
			if pb.Size == "large" {
				decShares := make([][]*tcpaillier.DecryptionShare, len(pb.Vec))
				bitlen := abc.tcs.encPk.N.BitLen()
				enclen := bitlen / 4
				for node, v := range pb.Vec {
					decShares[node] = make([]*tcpaillier.DecryptionShare, 0)
					// Split Messages
					for i := 0; i < len(v.Message); i += enclen {
						end := i + enclen
						if end > len(v.Message) {
							end = len(v.Message)
						}
						tmp := new(big.Int)
						tmp.SetBytes(v.Message[i:end])
						decShare, err := abc.tcs.committeeKeys.encSk.PartialDecrypt(tmp)
						if err != nil {
							log.Printf("Node %d: is unable to partially decrypt message[%d]: %s. %s", abc.Cfg.NodeId, i, v.Message, err)
							continue
						}
						decShares[node] = append(decShares[node], decShare)
					}
				}
				mes := &PbDecryptionShareMessage{
					Sender:    abc.Cfg.NodeId,
					DecShares: decShares,
				}
				m := &utils.Message{
					Sender:  abc.Cfg.NodeId,
					Payload: mes,
				}
				abc.multicast(m, r)
			} else {
				decShares := make([]*tcpaillier.DecryptionShare, len(pb.Vec))
				for i, v := range pb.Vec {
					tmp := new(big.Int)
					tmp.SetBytes(v.Message)
					decShare, err := abc.tcs.committeeKeys.encSk.PartialDecrypt(tmp)
					if err != nil {
						log.Printf("Node %d: is unable to partially decrypt message[%d]: %s. %s", abc.Cfg.NodeId, i, v.Message, err)
						continue
					}
					decShares[i] = decShare
				}
				mes := &PbDecryptionShareMessage{
					Sender:    abc.Cfg.NodeId,
					DecShares: [][]*tcpaillier.DecryptionShare{decShares},
				}
				m := &utils.Message{
					Sender:  abc.Cfg.NodeId,
					Payload: mes,
				}
				//log.Printf("Node %d: multicasting decrpytion share", abc.cfg.nodeId)
				abc.multicast(m, r)
			}
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
	err := rsa.VerifyPKCS1v15(abc.tcs.keyMetaC.PublicKey, crypto.SHA256, bs.Pointer.BlockHash, bs.Pointer.Sig)
	return err == nil
}

// handleLargeTransaction sends a blockMessage containing encrypted transactions w to the committee.
func (abc *ABC) handleLargeTransaction(r int, w [][]byte) {
	// Encrypt one by one and then merge
	tx := make([]byte, 0)
	for _, t := range w {
		data := new(big.Int)
		data.SetBytes(t)
		d, _, err := abc.tcs.encPk.Encrypt(data)
		if err != nil {
			log.Printf("Node %d round %d failed to encrypt tx %x", abc.Cfg.NodeId, r, t)
			return
		}
		// In case encryption output is corrupted repeat
		for len(d.Bytes()) != abc.tcs.encPk.N.BitLen()/4 {
			data := new(big.Int)
			data.SetBytes(t)
			d, _, _ = abc.tcs.encPk.Encrypt(data)
		}

		tx = append(tx, d.Bytes()...)

	}

	// Sign resulting slice of encrypted transactions
	h := sha256.Sum256(tx)
	pH, err := tcrsa.PrepareDocumentHash(abc.tcs.keyMeta.PublicKey.Size(), crypto.SHA256, h[:])
	if err != nil {
		log.Printf("Node %d: failed to hash transaction %s", abc.Cfg.NodeId, tx)
		return
	}
	sig, err := abc.tcs.sigSk.Sign(pH, crypto.SHA256, abc.tcs.keyMeta)
	if err != nil {
		log.Printf("Node %d: failed to sign transaction %s", abc.Cfg.NodeId, tx)
		return
	}

	mes := &BlockMessage{
		Sender:  abc.Cfg.NodeId,
		Status:  "large",
		Payload: tx,
		Sig:     sig,
	}
	m := &utils.Message{
		Sender:  abc.Cfg.NodeId,
		Payload: mes,
	}
	// log.Printf("Node %d sending large block. Size: %d", abc.cfg.nodeId, len(tx))
	// Only send to committee members
	for i := 0; i < abc.Cfg.n; i++ {
		if abc.Cfg.committee[i] {
			abc.multicast(m, r, i)
		}
	}
}

// handleSmallTransaction sends a blockMessage containing encrypted transaction tx to node i.
func (abc *ABC) handleSmallTransaction(i, r int, tx []byte) {
	data := new(big.Int)
	data.SetBytes(tx)
	m, err := abc.encryptAndSign(r, data, "small")
	if err != nil {
		log.Printf("Node %d round %d: encryptAndSign failed: %s", abc.Cfg.NodeId, r, err)
		return
	}
	abc.multicast(m, r, i)
}

// encryptAndSign encrypts data, signs the hash of the encrypted value and returns a blockMessage
// wrapped into a Message
func (abc *ABC) encryptAndSign(r int, data *big.Int, status string) (*utils.Message, error) {
	tx := string(data.Bytes())
	// Encrypt transaction
	e, _, err := abc.tcs.encPk.Encrypt(data)
	if err != nil {
		log.Printf("Node %d: failed to encrypt transaction %s", abc.Cfg.NodeId, tx)
		return nil, err
	}
	// Sign encryption transaction
	h := sha256.Sum256(e.Bytes())
	pH, err := tcrsa.PrepareDocumentHash(abc.tcs.keyMeta.PublicKey.Size(), crypto.SHA256, h[:])
	if err != nil {
		log.Printf("Node %d: failed to hash transaction %s", abc.Cfg.NodeId, tx)
		return nil, err
	}
	sig, err := abc.tcs.sigSk.Sign(pH, crypto.SHA256, abc.tcs.keyMeta)
	if err != nil {
		log.Printf("Node %d: failed to sign transaction %s", abc.Cfg.NodeId, tx)
		return nil, err
	}
	mes := &BlockMessage{
		Sender:  abc.Cfg.NodeId,
		Status:  status,
		Payload: e.Bytes(),
		Sig:     sig,
	}
	m := &utils.Message{
		Sender:  abc.Cfg.NodeId,
		Payload: mes,
	}
	// log.Printf("Tx before enc: %d. Tx after enc: %d", len(data.Bytes()), len(e.Bytes()))
	return m, nil
}

// handleSmallBlockMessage saves incoming blockMessages containing small blocks.
func (abc *ABC) handleSmallBlockMessage(r, ta int, m *BlockMessage, b *utils.PreBlock, rdy *bool, mu *sync.Mutex, readyChan chan struct{}) {
	mu.Lock()
	defer mu.Unlock()
	if b.Vec[m.Sender] == nil {
		pbMes := &utils.PreBlockMessage{
			Message: m.Payload,
			Sig:     m.Sig,
		}
		b.AddMessage(m.Sender, pbMes)

		if b.Quality() >= abc.Cfg.n-ta && !*rdy {
			*rdy = true
			readyChan <- struct{}{}
		}
	}
}

// handleLargeBlockMessage saves incoming blockMessages containing large blocks.
func (abc *ABC) handleLargeBlockMessage(r, ta int, m *BlockMessage, b *utils.PreBlock, rdy *bool, mu *sync.Mutex) {
	mu.Lock()
	defer mu.Unlock()
	if b.Vec[m.Sender] == nil {
		pbMes := &utils.PreBlockMessage{
			Message: m.Payload,
			Sig:     m.Sig,
		}
		b.Vec[m.Sender] = pbMes

		if b.Quality() >= abc.Cfg.n-ta && !*rdy {
			//log.Printf("Node %d: has a %d-quality pre-block", abc.cfg.nodeId, b.Quality())
			*rdy = true
			h := b.Hash()
			paddedHash, err := tcrsa.PrepareDocumentHash(abc.tcs.keyMetaC.PublicKey.Size(), crypto.SHA256, h[:])
			if err != nil {
				log.Printf("Node %d: failed to create a padded hash", abc.Cfg.NodeId)
				return
			}
			sig, err := abc.tcs.committeeKeys.sigSk.Sign(paddedHash, crypto.SHA256, abc.tcs.keyMetaC)
			if err != nil {
				log.Printf("Node %d: failed to sign pre-block hash", abc.Cfg.NodeId)
				return
			}
			mes := &CommitteeMessage{
				Sender:   abc.Cfg.NodeId,
				PreBlock: b,
				Hash:     h,
				HashSig:  sig,
				Proof:    abc.tcs.proof,
			}
			m := &utils.Message{
				Sender:  abc.Cfg.NodeId,
				Payload: mes,
			}

			//log.Printf("Node %d multicasting %d-quality pre-block to committee", abc.cfg.nodeId, b.Quality())
			// Only send to committee members
			for i := 0; i < abc.Cfg.n; i++ {
				if abc.Cfg.committee[i] {
					abc.multicast(m, r, i)
				}
			}
		}
	}
}

// handlePointerMessage saves a received block pointer, if the node has no current block pointer.
// If the node is in the committee and receives a well-formed block pointer, it multicasts it
func (abc *ABC) handlePointerMessage(r int, m *PointerMessage, ptr **utils.BlockPointer, mu *sync.Mutex, ptrChan chan struct{}) {
	mu.Lock()
	defer mu.Unlock()
	// Only set pointer if there isn't already one.
	if *ptr != nil {
		return
	}
	// If node is in committee check if pointer is well-formed, multicast it
	if abc.Cfg.committee[abc.Cfg.NodeId] {
		err := rsa.VerifyPKCS1v15(abc.tcs.keyMetaC.PublicKey, crypto.SHA256, m.Pointer.BlockHash, m.Pointer.Sig)
		if err != nil {
			log.Printf("Node %d: received block pointer with invalid signature: %s", abc.Cfg.NodeId, err)
			return
		}
		*ptr = m.Pointer
		ptrChan <- struct{}{}
		ptrMes := &PointerMessage{
			Sender:  abc.Cfg.NodeId,
			Pointer: *ptr,
		}
		m := &utils.Message{
			Sender:  abc.Cfg.NodeId,
			Payload: ptrMes,
		}
		abc.multicast(m, r)
		return
	}
	// If ptr came from committee: if ptr == nil: set ptr
	if abc.Cfg.committee[m.Sender] {
		*ptr = m.Pointer
		ptrChan <- struct{}{}
	}
}

// handleCommitteeMessage saves incoming committeeMessages containing large blocks. If enough
// messages on the same block are received it combines a signature and multicasts a block pointer.
func (abc *ABC) handleCommitteeMessage(r int, m *CommitteeMessage, ptr **utils.BlockPointer, mesRec map[int]bool, blocksReceived map[[32]byte]map[int]*tcrsa.SigShare, mu *sync.Mutex, ptrChan chan struct{}) {
	mu.Lock()
	defer mu.Unlock()
	// Only if in committee
	if !abc.Cfg.committee[abc.Cfg.NodeId] {
		return
	}
	// If the committee message is invalid don't do anything
	if !abc.isValidCommitteeMessage(m) {
		return
	}
	// Echo first valid committee messages received by any committee member, but only when the block
	// pointer is nil.
	if !mesRec[m.Sender] && ptr == nil {
		mesRec[m.Sender] = true
		paddedHash, err := tcrsa.PrepareDocumentHash(abc.tcs.keyMetaC.PublicKey.Size(), crypto.SHA256, m.Hash[:])
		if err != nil {
			log.Printf("Node %d: failed to hash pre-block", abc.Cfg.NodeId)
			return
		}
		hashSig, err := abc.tcs.committeeKeys.sigSk.Sign(paddedHash, crypto.SHA256, abc.tcs.keyMeta)
		if err != nil {
			log.Printf("Node %d: failed to sign hash of pre-block", abc.Cfg.NodeId)
			return
		}
		mes := &CommitteeMessage{
			Sender:   abc.Cfg.NodeId,
			PreBlock: m.PreBlock,
			Hash:     m.Hash,
			HashSig:  hashSig,
			Proof:    abc.tcs.proof,
		}
		m := &utils.Message{
			Sender:  abc.Cfg.NodeId,
			Payload: mes,
		}
		// Only send to committee members
		for i := 0; i < abc.Cfg.n; i++ {
			if abc.Cfg.committee[i] {
				abc.multicast(m, r, i)
			}
		}
	}
	// Upon receiving tk+1 messages from distinct parties on same block: combine sig
	if blocksReceived[m.Hash] == nil {
		blocksReceived[m.Hash] = make(map[int]*tcrsa.SigShare)
	}
	blocksReceived[m.Hash][m.Sender] = m.HashSig
	// TODO: set to tk+1
	if len(blocksReceived[m.Hash]) >= (len(abc.Cfg.committee)/2 + 1) {
		var sigShares tcrsa.SigShareList
		for _, s := range blocksReceived[m.Hash] {
			sigShares = append(sigShares, s)
		}
		h, err := tcrsa.PrepareDocumentHash(abc.tcs.keyMetaC.PublicKey.Size(), crypto.SHA256, m.Hash[:])
		if err != nil {
			log.Printf("Node %d: failed to pad block hash", abc.Cfg.NodeId)
			return
		}
		signature, err := sigShares.Join(h, abc.tcs.keyMetaC)
		if err != nil {
			log.Printf("Node %d round %d: failed to create signature on pre-block hash. %s", abc.Cfg.NodeId, r, err)
			return
		}
		//log.Printf("Node %d round %d: received enough committee messages on same pre-block. Creating signature", abc.cfg.nodeId, r)

		bPtr := utils.NewBlockPointer(m.Hash[:], signature)

		*ptr = bPtr
		ptrChan <- struct{}{}
		mes := &PointerMessage{
			Sender:  abc.Cfg.NodeId,
			Pointer: bPtr,
		}
		m := &utils.Message{
			Sender:  abc.Cfg.NodeId,
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
func (abc *ABC) isValidCommitteeMessage(m *CommitteeMessage) bool {
	// TODO: fix
	if m == nil || m.HashSig == nil || m.Proof == nil || m.PreBlock == nil {
		log.Printf("Received corrupted committee message")
		return false
	}
	// Condition 1:
	hash := sha256.Sum256([]byte(strconv.Itoa(m.Sender)))
	paddedHash, err := tcrsa.PrepareDocumentHash(abc.tcs.keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		log.Printf("Node %d: was unable to hash sender id", abc.Cfg.NodeId)
		return false
	}
	if err = m.Proof.Verify(paddedHash, abc.tcs.keyMeta); err != nil {
		log.Printf("Node %d: received invalid committee message: invalid id proof", abc.Cfg.NodeId)
		return false
	}

	// Condition 2:
	// Use committee exclusive pki
	paddedHash, err = tcrsa.PrepareDocumentHash(abc.tcs.keyMetaC.PublicKey.Size(), crypto.SHA256, m.Hash[:])
	if err != nil {
		log.Printf("Node %d: unable to pad block hash", abc.Cfg.NodeId)
		return false
	}
	if err = m.HashSig.Verify(paddedHash, abc.tcs.keyMetaC); err != nil {
		log.Printf("Node %d: received invalid committee message: invalid signature on hash: %s", abc.Cfg.NodeId, err)
		return false
	}

	// Condition 3:
	if m.PreBlock.Hash() != m.Hash {
		log.Printf("Node %d: received invalid committee message: invalid block hash", abc.Cfg.NodeId)
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
	for _, tx := range txs {
		h := sha256.Sum256(tx)
		abc.latency[h] = time.Now()
	}
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
