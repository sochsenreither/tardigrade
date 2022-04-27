package tardigrade

import (
	"sync"

	"github.com/niclabs/tcpaillier"
	"github.com/niclabs/tcrsa"
	aba "github.com/sochsenreither/tardigrade/binaryagreement"
	bla "github.com/sochsenreither/tardigrade/blockagreement"
	rbc "github.com/sochsenreither/tardigrade/broadcast"
	acs "github.com/sochsenreither/tardigrade/commonsubset"
	utils "github.com/sochsenreither/tardigrade/utils"
)

type tcs struct {
	keyMeta       *tcrsa.KeyMeta    // KeyMeta containig pks for verifying
	keyMetaC      *tcrsa.KeyMeta    // KeyMeta containig pks for verifying committee signatures
	proof         *tcrsa.SigShare   // Signature on the node index signed by the dealer
	sigSk         *tcrsa.KeyShare   // Private signing key
	encPk         tcpaillier.PubKey // Public encryption key
	committeeKeys *committeeKeys
	sync.Mutex
}

// These keys are only used for signing committee messages and creating decryption shares
type committeeKeys struct {
	sigSk *tcrsa.KeyShare      // Private signing key
	encSk *tcpaillier.KeyShare // Private encryption key
}

func NewTcs(keyShare *tcrsa.KeyShare, keyMeta, keyMetaCommittee *tcrsa.KeyMeta, pk *tcpaillier.PubKey, proof *tcrsa.SigShare, keyShareCommitte *tcrsa.KeyShare, decryptionShare *tcpaillier.KeyShare) *tcs {
	tcs := &tcs{
		keyMeta:  keyMeta,
		keyMetaC: keyMetaCommittee,
		proof:    proof,
		sigSk:    keyShare,
		encPk:    *pk,
	}
	if keyShareCommitte != nil && decryptionShare != nil {
		tcs.committeeKeys = &committeeKeys{
			sigSk: keyShareCommitte,
			encSk: decryptionShare,
		}
	}
	return tcs
}


type ABCConfig struct {
	n            int                 // Number of nodes
	NodeId       int                 // Id of node
	ta           int                 // Number of maximum faulty nodes (async)
	ts           int                 // Number of maximum faulty nodes (sync)
	tk           int                 // Threshold for distinct committee messages
	kappa        int                 // Security parameter
	delta        int                 // Round timer
	lambda       int                 // spacing paramter
	epsilon      int                 //
	committee    map[int]bool        // List of committee members
	txSize       int                 // Transaction size in bytes
	leaderFunc   func(r, n int) int  // Function for electing a leader
	handlerFuncs *utils.HandlerFuncs // Communication handler
}

func NewABCConfig(n, nodeId, ta, ts, kappa, delta, lambda, epsilon, txSize int, committee map[int]bool, leaderFunc func(r, n int) int, handlerFuncs *utils.HandlerFuncs) *ABCConfig {
	return &ABCConfig{
		n:            n,
		NodeId:       nodeId,
		ta:           ta,
		ts:           ts,
		kappa:        kappa,
		delta:        delta,
		lambda:       lambda,
		epsilon:      epsilon,
		committee:    committee,
		txSize:       txSize,
		leaderFunc:   leaderFunc,
		handlerFuncs: handlerFuncs,
	}
}

func setupBLA(UROUND int, cfg *ABCConfig, tcs *tcs, ts int) *bla.BlockAgreement {
	return bla.NewBlockAgreement(UROUND, cfg.n, cfg.NodeId, ts, cfg.kappa, nil, tcs.sigSk, tcs.keyMeta, cfg.leaderFunc, cfg.delta, cfg.handlerFuncs)
}

func setupACS(UROUND int, cfg *ABCConfig, tcs *tcs, ta int) *acs.CommonSubset {
	rbcs := setupRBC(UROUND, cfg, tcs, ta)
	abas := setupABA(UROUND, cfg, tcs, ta)
	config := &acs.ACSConfig{
		N:       cfg.n,
		NodeId:  cfg.NodeId,
		T:       ta,
		Kappa:   cfg.kappa,
		Epsilon: cfg.epsilon,
		UROUND:  UROUND,
	}
	t := &acs.ThresholdCrypto{
		Sk:       tcs.sigSk,
		KeyMeta:  tcs.keyMeta,
		Proof:    tcs.proof,
		KeyMetaC: tcs.keyMetaC,
		SkC:      nil,
	}
	if cfg.committee[cfg.NodeId] {
		t.SkC = tcs.committeeKeys.sigSk
	}
	a := acs.NewACS(config, cfg.committee, nil, rbcs, abas, t, cfg.handlerFuncs)
	return a
}

// Returns n instances of rbc
func setupRBC(UROUND int, cfg *ABCConfig, tcs *tcs, ta int) []*rbc.ReliableBroadcast {
	rbcs := make([]*rbc.ReliableBroadcast, cfg.n)
	sig := &rbc.Signature{
		Proof:   tcs.proof,
		KeyMeta: tcs.keyMeta,
	}
	for i := 0; i < cfg.n; i++ {
		config := &rbc.ReliableBroadcastConfig{
			UROUND:   UROUND,
			N:        cfg.n,
			NodeId:   cfg.NodeId,
			T:        ta,
			Kappa:    cfg.kappa,
			Epsilon:  cfg.epsilon,
			SenderId: i,
			Instance: i,
		}
		rbcs[i] = rbc.NewReliableBroadcast(config, cfg.committee, sig, cfg.handlerFuncs)
	}
	return rbcs
}

// Returns n instances of aba
func setupABA(UROUND int, cfg *ABCConfig, tcs *tcs, ta int) []*aba.BinaryAgreement {
	tc := &aba.ThresholdCrypto{
		KeyShare: tcs.sigSk,
		KeyMeta:  tcs.keyMeta,
	}
	abas := make([]*aba.BinaryAgreement, cfg.n)
	for i := 0; i < cfg.n; i++ {
		abas[i] = aba.NewBinaryAgreement(UROUND, cfg.n, cfg.NodeId, ta, -1, i, tc, cfg.handlerFuncs)
	}
	return abas
}
