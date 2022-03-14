package upgrade

import (
	aba "github.com/sochsenreither/upgrade/binaryagreement"
	bla "github.com/sochsenreither/upgrade/blockagreement"
	rbc "github.com/sochsenreither/upgrade/broadcast"
	acs "github.com/sochsenreither/upgrade/commonsubset"
)

func setupBLA(UROUND int, cfg *ABCConfig, tcs *tcs) *bla.BlockAgreement {
	return bla.NewBlockAgreement(UROUND, cfg.n, cfg.nodeId, cfg.ts, cfg.kappa, nil, tcs.sigSk, tcs.keyMeta, cfg.leaderFunc, cfg.delta, cfg.handler)
}

func setupACS(UROUND int, cfg *ABCConfig, tcs *tcs) *acs.CommonSubset {
	rbcs := setupRBC(UROUND, cfg, tcs)
	abas := setupABA(UROUND, cfg, tcs)
	config := &acs.ACSConfig{
		N: cfg.n,
		NodeId: cfg.nodeId,
		T: cfg.ta,
		Kappa: cfg.kappa,
		Epsilon: cfg.epsilon,
		UROUND: UROUND,
	}
	t := &acs.ThresholdCrypto{
		Sk: tcs.sigSk,
		KeyMeta: tcs.keyMeta,
		Proof: tcs.proof,
		KeyMetaC: tcs.keyMetaC,
		SkC: nil,
	}
	if cfg.committee[cfg.nodeId] {
		t.SkC = tcs.committeeKeys.sigSk
	}
	a := acs.NewACS(config, cfg.committee, nil, rbcs, abas, t, cfg.handler)
	return a
}

// Returns n instances of rbc
func setupRBC(UROUND int, cfg *ABCConfig, tcs *tcs) []*rbc.ReliableBroadcast {
	rbcs := make([]*rbc.ReliableBroadcast, cfg.n)
	sig := &rbc.Signature{
		Proof: tcs.proof,
		KeyMeta: tcs.keyMeta,
	}
	for i := 0; i < cfg.n; i++ {
		config := &rbc.ReliableBroadcastConfig{
			UROUND: UROUND,
			N: cfg.n,
			NodeId: cfg.nodeId,
			T: cfg.ta,
			Kappa: cfg.kappa,
			Epsilon: cfg.epsilon,
			SenderId: i,
			Instance: i,
		}
		rbcs[i] = rbc.NewReliableBroadcast(config, cfg.committee, sig, cfg.handler)
	}
	return rbcs
}

// Returns n instances of aba
func setupABA(UROUND int, cfg *ABCConfig, tcs *tcs) []*aba.BinaryAgreement {
	tc := &aba.ThresholdCrypto{
		KeyShare: tcs.sigSk,
		KeyMeta:  tcs.keyMeta,
	}
	abas := make([]*aba.BinaryAgreement, cfg.n)
	for i := 0; i < cfg.n; i++ {
		abas[i] = aba.NewBinaryAgreement(UROUND, cfg.n, cfg.nodeId, cfg.ta, -1, i, cfg.coin, tc, cfg.handler)
	}
	return abas
}
