package tardigrade

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
	aba "github.com/sochsenreither/tardigrade/binaryagreement"
	"github.com/sochsenreither/tardigrade/utils"
)

type testConfig struct {
	n          int                    // Number of nodes
	ta         int                    // Number of maximum faulty nodes (asynch)
	ts         int                    // Number of maximum faulty nodes (synch)
	kappa      int                    // Security parameter
	delta      int                    // Round timer
	epsilon    int                    //
	lambda     int                    // spacing paramter
	committee  map[int]bool           // List of committee members
	txSize     int                    // Transaction size in bytes
	sigKeys    tcrsa.KeyShareList     // List of keyShares of the signature scheme
	keyMeta    *tcrsa.KeyMeta         // keyMeta of the signature scheme
	pk         tcpaillier.PubKey      // public key of the encryption scheme
	proofs     []*tcrsa.SigShare      // List of signed node ids by the dealer
	keyMetaC   *tcrsa.KeyMeta         // KeyMeta for committee members
	sigKeysC   []*tcrsa.KeyShare      // Signings keys for committee members
	encKeysC   []*tcpaillier.KeyShare // Private encryption keys for committee members
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
	cfg := &ABCConfig{
		n:         1,
		NodeId:    0,
		ta:        0,
		tk:        0,
		kappa:     0,
		lambda:    200,
		committee: committee,
	}
	u := &ABC{
		Cfg: cfg,
		acss: nil,
		blas: nil,
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
	delta := 1
	lambda := 10
	txSize := 8
	kappa := 2
	cfg := setupConfig(n, 0, 0, kappa, delta, 0, lambda, txSize)

	maxRounds := 5
	abcs := setupSimulation(cfg)

	fmt.Println("Setup done, starting simulation...")
	var wg sync.WaitGroup
	wg.Add(cfg.n - cfg.ta)
	cfgs := make(map[int]*utils.RoundConfig)
	hCfg := &utils.RoundConfig{
		Ta: 0,
		Ts: 0,
		Crashed: map[int]bool{},
	}
	for i := 0; i < maxRounds; i++ {
		cfgs[i] = hCfg
	}
	start := time.Now()
	for i := 0; i < cfg.n-cfg.ta; i++ {
		//fmt.Println(i, len(abcs[i].acs), len(abcs[i].bla))
		i := i
		go func() {
			defer wg.Done()
			abcs[i].Run(maxRounds, cfgs, time.Now())
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

	fmt.Println("Total transactions:", txsCount)
	fmt.Println("Transactions per second:", float64(txsCount)/float64(executionTime/time.Millisecond)*1000)
}

func setupSimulation(cfg *testConfig) []*ABC {
	// Create common coin
	req := make(chan *utils.CoinRequest, 9999)
	coin := aba.NewLocalCommonCoin(cfg.n, cfg.keyMeta, req)
	go coin.Run()

	// Create communication channels and handlers
	nodeChans := make(map[int]chan *utils.HandlerMessage)
	var handlers []*utils.LocalHandler
	for i := 0; i < cfg.n; i++ {
		nodeChans[i] = make(chan *utils.HandlerMessage, 9999)
	}

	// Create leader function
	leaderFunc := func(r, n int) int {
		return r % n
	}

	abcs := make([]*ABC, cfg.n)
	for i := 0; i < cfg.n; i++ {
		handlers = append(handlers, utils.NewLocalHandler(nodeChans, coin.RequestChan, i, cfg.n, cfg.kappa))
		tcs := &tcs{
			keyMeta:       cfg.keyMeta,
			keyMetaC:      cfg.keyMetaC,
			proof:         cfg.proofs[i],
			sigSk:         cfg.sigKeys[i],
			encPk:         cfg.pk,
			committeeKeys: nil,
		}
		if cfg.committee[i] {
			committeeKeys := &committeeKeys{
				sigSk: cfg.sigKeysC[i],
				encSk: cfg.encKeysC[i],
			}
			tcs.committeeKeys = committeeKeys
		}
		c := &ABCConfig{
			n:          cfg.n,
			NodeId:     i,
			ta:         cfg.ta,
			ts:         cfg.ts,
			tk:         -1,
			kappa:      cfg.kappa,
			delta:      cfg.delta,
			lambda:     cfg.lambda,
			epsilon:    cfg.epsilon,
			committee:  cfg.committee,
			txSize:     cfg.txSize,
			leaderFunc: leaderFunc,
			handlerFuncs:    handlers[i].Funcs,
		}
		abcs[i] = NewABC(c, tcs)
	}

	// Create buffers for every node with random transactions
	fmt.Println("Filling buffers..")
	bufsize := cfg.n * 1200
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
	fmt.Println("Finished filling buffers")
	return abcs
}

func setupConfig(n, ta, ts, kappa, delta, epsilon, lambda int, txSize int) *testConfig {
	fmt.Println("Starting key setup..")
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
		proofs:    signedIds,
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
