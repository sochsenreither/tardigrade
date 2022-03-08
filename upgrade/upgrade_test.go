package upgrade

import (
	"crypto"
	"crypto/sha256"
	"fmt"

	// "io/ioutil"
	// "log"
	// "os"
	"time"

	"math/rand"
	"strconv"
	"sync"
	"testing"

	"github.com/niclabs/tcpaillier"
	"github.com/niclabs/tcrsa"
	aba "github.com/sochsenreither/upgrade/binaryagreement"
	bla "github.com/sochsenreither/upgrade/blockagreement"
	rbc "github.com/sochsenreither/upgrade/broadcast"
	acs "github.com/sochsenreither/upgrade/commonsubset"
	utils "github.com/sochsenreither/upgrade/utils"
)

type testConfig struct {
	n         int                    // Number of nodes
	ta        int                    // Number of maximum faulty nodes (asynch)
	ts        int                    // Number of maximum faulty nodes (synch)
	kappa     int                    // Security parameter
	delta     int                    // Round timer
	epsilon   int                    //
	lambda    int                    // spacing paramter
	committee map[int]bool           // List of committee members
	txSize    int                    // Transaction size in bytes
	sigKeys   tcrsa.KeyShareList     // List of keyShares of the signature scheme
	keyMeta   *tcrsa.KeyMeta         // keyMeta of the signature scheme
	pk        tcpaillier.PubKey      // public key of the encryption scheme
	signedIDs []*tcrsa.SigShare      // List of signed node ids by the dealer
	keyMetaC  *tcrsa.KeyMeta         // KeyMeta for committee members
	sigKeysC  []*tcrsa.KeyShare      // Signings keys for committee members
	encKeysC  []*tcpaillier.KeyShare // Private encryption keys for committee members
}

// func TestMain(m *testing.M) {
// 	log.SetOutput(ioutil.Discard)
// 	os.Exit(m.Run())
// }

func simpleTestInstance(n int) *ABC {
	buf := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		buf[i] = []byte(strconv.Itoa(i))
	}
	committee := make(map[int]bool)
	committee[0] = true
	cfg := &UpgradeConfig{
		n:         1,
		nodeId:    0,
		t:         0,
		tk:        0,
		kappa:     0,
		lambda:    200,
		committee: committee,
	}
	u := &ABC{
		cfg: cfg,
		acs: nil,
		bla: nil,
		tcs: nil,
		buf: buf,
	}
	return u
}

func TestProposeTxs(t *testing.T) {
	u := simpleTestInstance(1)

	r := u.proposeTxs(3, 10)
	if len(r) != 3 {
		t.Errorf("Expected %d elements, got %d", 3, len(r))
	}
	r = u.proposeTxs(10, 10)
	if len(r) != 10 {
		t.Errorf("Expected %d elements, got %d", 10, len(r))
	}
}

func TestSimpleTest(t *testing.T) {
	// Note: Increase keysize of pk enc when increasing number of nodes or tx size
	n := 5
	delta := 30
	lambda := 400
	txSize := 4
	kappa := 2
	cfg := setupConfig(n, 0, 0, kappa, delta, 0, lambda, txSize)

	maxRounds := 15
	abcs := setupSimulation(cfg, maxRounds)

	fmt.Println("Setup done, starting simulation...")
	var wg sync.WaitGroup
	wg.Add(cfg.n - cfg.ta)
	start := time.Now()
	for i := 0; i < cfg.n-cfg.ta; i++ {
		//fmt.Println(i, len(abcs[i].acs), len(abcs[i].bla))
		i := i
		go func() {
			defer wg.Done()
			abcs[i].Run(maxRounds)
		}()
	}
	wg.Wait()
	executionTime := time.Since(start)
	fmt.Println("Execution time:", executionTime)

	txsCount := 0
	// Check if every node has the same chain of blocks.
	// Check for every round
	for j := 0; j < maxRounds; j++ {
		var prevHash [32]byte
		// Check every node.
		for i := 0; i < cfg.n-cfg.ta; i++ {
			out := abcs[i].GetBlocks()[j].Hash()
			if i == 0 {
				prevHash = out
				continue
			}
			if out != prevHash {
				t.Errorf("Different output blocks")
			}
		}
		txsCount += abcs[0].GetBlocks()[j].TxsCount
	}

	// TODO: count unique transactions
	fmt.Println("Total transactions:", txsCount)
	fmt.Println("Transactions per second:", float64(txsCount)/float64(executionTime/time.Millisecond)*1000)
}

// Sets up a simulation with k rounds. So every ABC instance has n ACS and BLA instances.
func setupSimulation(cfg *testConfig, k int) []*ABC {
	// Get n*k instances of BLAs
	start := time.Now()
	blas := make([][]*bla.BlockAgreement, k)
	for i := 0; i < k; i++ {
		blas[i] = setupBLA(cfg)
	}
	fmt.Println("BLA setup took", time.Since(start))

	// Get n*k instances of ACSs
	start = time.Now()
	acss := make([][]*acs.CommonSubset, k)
	for i := 0; i < k; i++ {
		acss[i] = setupACS(cfg)
	}
	fmt.Println("ACS setup took", time.Since(start))

	// Get n instances of ABC
	start = time.Now()
	abcs := setupABC(cfg, acss, blas)
	fmt.Println("ABC setup took", time.Since(start))

	// Create buffers for every node with random transactions
	start = time.Now()
	bufsize := cfg.n * k * 20
	bufs := make([][][]byte, cfg.n)
	for i := 0; i < cfg.n; i++ {
		bufs[i] = make([][]byte, bufsize)
		for j := 0; j < bufsize; j++ {
			token := make([]byte, cfg.txSize)
			rand.Read(token)
			bufs[i][j] = token
			//bufs[i][j] = []byte(strconv.Itoa(i))
		}
		abcs[i].FillBuffer(bufs[i])
	}
	fmt.Println("Creating random buffers took", time.Since(start))
	return abcs
}

func setupConfig(n, ta, ts, kappa, delta, epsilon, lambda int, txSize int) *testConfig {
	committee := make(map[int]bool)
	for i := 0; i < kappa; i++ {
		committee[i] = true
	}


	start := time.Now()
	sigKeys, keyMeta, pk, sigKeysC, keyMetaC, encKeysC := setupKeys(n, committee)
	signedIds := make([]*tcrsa.SigShare, n)
	// Dealer signs node ids (dealer is node 0 in this case)
	for i := 0; i < n; i++ {
		hash := sha256.Sum256([]byte(strconv.Itoa(i)))
		paddedHash, _ := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
		sig, err := sigKeys[0].Sign(paddedHash, crypto.SHA256, keyMeta)
		if err != nil {
			panic(err)
		}
		signedIds[i] = sig
	}
	fmt.Println("Key setup took", time.Since(start))
	cfg := &testConfig{
		n:         n,
		ta:        ta,
		ts:        ts,
		kappa:     kappa,
		delta:     delta,
		epsilon:   epsilon,
		lambda:    lambda,
		committee: committee,
		sigKeys:   sigKeys,
		keyMeta:   keyMeta,
		pk:        *pk,
		signedIDs: signedIds,
		keyMetaC:  keyMetaC,
		sigKeysC:  sigKeysC,
		encKeysC:  encKeysC,
		txSize:    txSize,
	}
	return cfg
}

func setupKeys(n int, committee map[int]bool) (tcrsa.KeyShareList, *tcrsa.KeyMeta, *tcpaillier.PubKey, tcrsa.KeyShareList, *tcrsa.KeyMeta, []*tcpaillier.KeyShare) {
	// Setup signature scheme
	keyShares, keyMeta, err := tcrsa.NewKey(512, uint16(n/2+1), uint16(n), nil)
	if err != nil {
		panic(err)
	}

	k := len(committee)
	keySharesC, keyMetaC, err := tcrsa.NewKey(512, uint16(k/2+1), uint16(k), nil)
	if err != nil {
		panic(err)
	}

	// Setup encryption scheme
	shares, pk, err := tcpaillier.NewKey(512, 1, uint8(k), uint8(k/2+1))
	if err != nil {
		panic(err)
	}

	return keyShares, keyMeta, pk, keySharesC, keyMetaC, shares
}

// setupBLA returns a slice of blockagreement instances
func setupBLA(cfg *testConfig) []*bla.BlockAgreement {
	blas := make([]*bla.BlockAgreement, cfg.n)
	var mu sync.Mutex
	nodeChans := make(map[int][]chan *utils.Message)

	multicast := func(id, round int, msg *utils.Message, params ...int) {
		go func() {
			var chans []chan *utils.Message
			mu.Lock()
			if nodeChans[round] == nil {
				nodeChans[round] = make([]chan *utils.Message, cfg.n)
				for i := 0; i < cfg.n; i++ {
					nodeChans[round][i] = make(chan *utils.Message, 99999*cfg.n)
				}
			}
			// Set channels to send to to different variable in order to prevent data/lock races
			chans = append(chans, nodeChans[round]...)
			mu.Unlock()
			if len(params) == 1 {
				//fmt.Printf("%d -> %d %T\n", msg.Sender, params[0], msg.Payload)
				chans[params[0]] <- msg
			} else {
				for i := 0; i < cfg.n; i++ {
					chans[i] <- msg
				}
			}
		}()
	}

	receive := func(id, round int) chan *utils.Message {
		mu.Lock()
		if nodeChans[round] == nil {
			nodeChans[round] = make([]chan *utils.Message, cfg.n)
			for i := 0; i < cfg.n; i++ {
				nodeChans[round][i] = make(chan *utils.Message, 99999*cfg.n)
			}
		}
		ch := nodeChans[round][id]
		mu.Unlock()
		return ch
	}

	leader := func(round, n int) int {
		return (round + 1) % n
	}

	for i := 0; i < cfg.n-cfg.ts; i++ {
		blas[i] = bla.NewBlockAgreement(cfg.n, i, cfg.ts, cfg.kappa, nil, cfg.sigKeys[i], cfg.keyMeta, leader, cfg.delta, multicast, receive)
	}
	return blas
}

// Returns one instance of acs per node
func setupABC(cfg *testConfig, acss [][]*acs.CommonSubset, blas [][]*bla.BlockAgreement) []*ABC {
	abcs := make([]*ABC, cfg.n)
	nodeChans := make(map[int][]chan *utils.Message)
	var mu sync.Mutex

	multicast := func(msg *utils.Message, params ...int) {
		// First parameter = round, second parameter = receiver
		go func() {
			var chans []chan *utils.Message
			mu.Lock()
			round := params[0]
			if nodeChans[round] == nil {
				nodeChans[round] = make([]chan *utils.Message, cfg.n)
				for i := 0; i < cfg.n; i++ {
					nodeChans[round][i] = make(chan *utils.Message, 99999*cfg.n)
				}
			}
			// Set channels to send to to different variable in order to prevent data/lock races
			chans = append(chans, nodeChans[round]...)
			mu.Unlock()
			if len(params) == 2 {
				chans[params[1]] <- msg
			} else {
				for i := 0; i < cfg.n; i++ {
					chans[i] <- msg
				}
			}
		}()
	}
	receive := func(id, round int) *utils.Message {
		mu.Lock()
		if nodeChans[round] == nil {
			nodeChans[round] = make([]chan *utils.Message, cfg.n)
			for i := 0; i < cfg.n; i++ {
				nodeChans[round][i] = make(chan *utils.Message, 99999*cfg.n)
			}
		}
		ch := nodeChans[round][id]
		mu.Unlock()
		val := <-ch
		return val
	}

	for i := 0; i < cfg.n; i++ {
		committeeKeys := &committeeKeys{}
		if cfg.committee[i] {
			committeeKeys.sigSk = cfg.sigKeysC[i]
			committeeKeys.encSk = *cfg.encKeysC[i]
		}
		tcs := &tcs{
			keyMeta:       cfg.keyMeta,
			keyMetaC:      cfg.keyMetaC,
			proof:         cfg.signedIDs[i],
			sigSk:         cfg.sigKeys[i],
			encPk:         cfg.pk,
			committeeKeys: committeeKeys,
		}
		ucfg := &UpgradeConfig{
			n:         cfg.n,
			nodeId:    i,
			t:         cfg.ta,
			kappa:     cfg.kappa,
			delta:     cfg.delta,
			lambda:    cfg.lambda,
			committee: cfg.committee,
			txSize:    cfg.txSize,
		}
		a := make([]*acs.CommonSubset, len(acss))
		for j, acs := range acss {
			a[j] = acs[i]
		}
		b := make([]*bla.BlockAgreement, len(blas))
		for j, bla := range blas {
			b[j] = bla[i]
		}
		abcs[i] = NewABC(ucfg, a, b, tcs, multicast, receive)
	}

	return abcs
}

// Returns one instance of acs per node
func setupACS(cfg *testConfig) []*acs.CommonSubset {
	// Setup common coin
	requestChannel := make(chan *aba.CoinRequest, 9999)
	coin := aba.NewCommonCoin(cfg.n, cfg.keyMeta, requestChannel)
	go coin.Run()

	rbcs := setupRbc(cfg)
	abas := setupAba(cfg, coin)

	acss := make([]*acs.CommonSubset, cfg.n)
	nodeChans := make(map[int][]chan *utils.Message) // round -> chans
	var mu sync.Mutex

	multicast := func(id, round int, msg *utils.Message) {
		go func() {
			var chans []chan *utils.Message
			mu.Lock()
			if nodeChans[round] == nil {
				nodeChans[round] = make([]chan *utils.Message, cfg.n)
				for i := 0; i < cfg.n; i++ {
					nodeChans[round][i] = make(chan *utils.Message, 99999*cfg.n)
				}
			}
			// Set channels to send to to different variable in order to prevent data/lock races
			chans = append(chans, nodeChans[round]...)
			mu.Unlock()
			for i := 0; i < cfg.n; i++ {
				chans[i] <- msg
			}
		}()
	}

	receive := func(id, round int) *utils.Message {
		mu.Lock()
		if nodeChans[round] == nil {
			nodeChans[round] = make([]chan *utils.Message, cfg.n)
			for i := 0; i < cfg.n; i++ {
				nodeChans[round][i] = make(chan *utils.Message, 99999*cfg.n)
			}
		}
		ch := nodeChans[round][id]
		mu.Unlock()
		val := <-ch
		return val
	}

	for i := 0; i < cfg.n; i++ {
		tc := &acs.ThresholdCrypto{
			Sk:       cfg.sigKeys[i],
			KeyMeta:  cfg.keyMeta,
			SigShare: cfg.signedIDs[i],
			KeyMetaC: cfg.keyMetaC,
		}
		if cfg.committee[i] {
			tc.SkC = cfg.sigKeysC[i]
		}
		acscfg := &acs.ACSConfig{
			N:       cfg.n,
			NodeId:  i,
			T:       cfg.ta,
			Kappa:   1,
			Epsilon: 0,
			Round:   0,
		}
		acss[i] = acs.NewACS(acscfg, cfg.committee, nil, rbcs[i], abas[i], tc, multicast, receive)
	}

	return acss
}

// Returns n instances of aba per node
func setupAba(cfg *testConfig, coin *aba.CommonCoin) map[int][]*aba.BinaryAgreement {
	abas := make(map[int][]*aba.BinaryAgreement)
	nodeChans := make(map[int]map[int][]chan *aba.AbaMessage) // round -> instance -> chans
	var mu sync.Mutex

	multicast := func(id, instance, round int, msg *aba.AbaMessage) {
		go func() {
			var chans []chan *aba.AbaMessage
			mu.Lock()
			if nodeChans[round] == nil {
				nodeChans[round] = make(map[int][]chan *aba.AbaMessage)
			}
			if len(nodeChans[round][instance]) != cfg.n {
				nodeChans[round][instance] = make([]chan *aba.AbaMessage, cfg.n)
				for i := 0; i < cfg.n; i++ {
					nodeChans[round][instance][i] = make(chan *aba.AbaMessage, 99999*cfg.n)
				}
			}
			// Set channels to send to to different variable in order to prevent data/lock races
			chans = append(chans, nodeChans[round][instance]...)
			mu.Unlock()
			for i := 0; i < len(chans); i++ {
				chans[i] <- msg
			}
		}()
	}
	receive := func(id, instance, round int) *aba.AbaMessage {
		// If channels for round or instance don't exist create them first
		mu.Lock()
		if nodeChans[round] == nil {
			nodeChans[round] = make(map[int][]chan *aba.AbaMessage)
		}
		if len(nodeChans[round][instance]) != cfg.n {
			nodeChans[round][instance] = make([]chan *aba.AbaMessage, cfg.n)
			for k := 0; k < cfg.n; k++ {
				nodeChans[round][instance][k] = make(chan *aba.AbaMessage, 99999*cfg.n)
			}
		}
		// Set receive channel to separate variable in order to prevent data/lock races
		ch := nodeChans[round][instance][id]
		mu.Unlock()
		val := <-ch
		return val
	}

	for i := 0; i < cfg.n; i++ {
		i := i
		thresholdCrypto := &aba.ThresholdCrypto{
			KeyShare: cfg.sigKeys[i],
			KeyMeta:  cfg.keyMeta,
		}
		for j := 0; j < cfg.n; j++ {
			abas[i] = append(abas[i], aba.NewBinaryAgreement(cfg.n, i, cfg.ta, 0, j, coin, thresholdCrypto, multicast, receive))
		}
	}

	return abas
}

// Returns n instances of rbc per node
func setupRbc(cfg *testConfig) map[int][]*rbc.ReliableBroadcast {
	nodeChans := make(map[int]map[int][]chan *utils.Message) // maps round -> instance -> chans
	broadcasts := make(map[int][]*rbc.ReliableBroadcast)
	var mu sync.Mutex

	multicast := func(id, instance, round int, msg *utils.Message) {
		go func() {
			var chans []chan *utils.Message
			// If channels for round or instance don't exist create them first
			mu.Lock()
			if nodeChans[round] == nil {
				nodeChans[round] = make(map[int][]chan *utils.Message)
			}
			if len(nodeChans[round][instance]) != cfg.n {
				nodeChans[round][instance] = make([]chan *utils.Message, cfg.n)
				for i := 0; i < cfg.n; i++ {
					nodeChans[round][instance][i] = make(chan *utils.Message, 99999*cfg.n)
				}
			}
			// Set channels to send to to different variable in order to prevent data/lock races
			chans = append(chans, nodeChans[round][instance]...)
			mu.Unlock()

			switch msg.Payload.(type) {
			case *rbc.SMessage:
				for i, ch := range chans {
					if cfg.committee[i] {
						ch <- msg
					}
				}
			default:
				for _, ch := range chans {
					ch <- msg
				}
			}
		}()
	}
	receive := func(id, instance, round int) *utils.Message {
		// If channels for round or instance don't exist create them first
		mu.Lock()
		if nodeChans[round] == nil {
			nodeChans[round] = make(map[int][]chan *utils.Message)
		}
		if len(nodeChans[round][instance]) != cfg.n {
			nodeChans[round][instance] = make([]chan *utils.Message, cfg.n)
			for k := 0; k < cfg.n; k++ {
				nodeChans[round][instance][k] = make(chan *utils.Message, 99999*cfg.n)
			}
		}
		// Set receive channel to separate variable in order to prevent data/lock races
		ch := nodeChans[round][instance][id]
		mu.Unlock()
		val := <-ch
		return val
	}

	for i := 0; i < cfg.n; i++ {
		signature := &rbc.Signature{
			SigShare: cfg.signedIDs[i],
			KeyMeta:  cfg.keyMeta,
		}
		for j := 0; j < cfg.n; j++ {
			config := &rbc.ReliableBroadcastConfig{
				N:        cfg.n,
				NodeId:   i,
				T:        cfg.ta,
				Kappa:    1,
				Epsilon:  cfg.epsilon,
				SenderId: j,
				Round:    0,
			}
			broadcasts[i] = append(broadcasts[i], rbc.NewReliableBroadcast(config, cfg.committee, signature, multicast, receive))
		}
	}

	return broadcasts
}
