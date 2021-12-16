package blockagreement

import (
	"log"
	"time"
)

type BlockAgreement struct {
	n                       int                 // Number of nodes
	nodeId                  int                 // Id of node
	t                       int                 // Number of maximum faulty nodes
	round                   int                 // Round number
	kappa                   int                 // Security parameter
	nodeChans               []chan *message     // Communication channels of all nodes
	preBlock                *PreBlock           // Input pre-block of the node
	commits                 []*commitMessage    // List of commit messages received from GC
	thresholdCrypto         *thresholdCrypto    // Struct containing the secret key and key meta
	leaderChan              chan *leaderRequest // Channel for calling Leader(r)
	out                     chan *PreBlock      // Output channel
	gradedConsensusProtocol *gradedConsensus    // Underlying sub-protocol
	tickerChan              chan int            // Timer for synchronizing
	delta                   time.Duration       // Round time
}

func NewBlockAgreement(n, nodeId, t, kappa int, nodeChans []chan *message, preBlock *PreBlock, thresholdCrypto *thresholdCrypto, leaderChan chan *leaderRequest, out chan *PreBlock, delta time.Duration, tickerChan chan int) *BlockAgreement {
	killConsensus := make(chan struct{}, 10)
	gradedConsensusOut := make(chan *gradedConsensusResult, 1)
	vote := &vote{
		round:    0,
		preBlock: preBlock,
		commits:  nil,
	}
	gradedConsensus := NewGradedConsensus(n, nodeId, t, 0, nodeChans, tickerChan, vote, killConsensus, thresholdCrypto, leaderChan, gradedConsensusOut)

	blockAgreement := &BlockAgreement{
		n:                       n,
		nodeId:                  nodeId,
		t:                       t,
		round:                   0,
		kappa:                   kappa,
		nodeChans:               nodeChans,
		preBlock:                preBlock,
		thresholdCrypto:         thresholdCrypto,
		leaderChan:              leaderChan,
		out:                     out,
		gradedConsensusProtocol: gradedConsensus,
		tickerChan:              tickerChan,
		delta:                   delta,
	}

	return blockAgreement
}

func (ba *BlockAgreement) run() {
	// Clean up communication channel
	ba.nodeChans[ba.nodeId] = make(chan *message, 1000)

	for ba.round < ba.kappa {
		// At time 5r:
		// Run GC and denote output.
		log.Println(ba.nodeId, "------ running GC round", ba.round, "------")
		ba.updateVotes()
		ba.gradedConsensusProtocol.run()
		res := <-ba.gradedConsensusProtocol.out
		if res.grade > 0 {
			ba.preBlock = res.preBlock
			ba.commits = res.commits
		}
		if res.grade == 2 {
			log.Println(ba.nodeId, "got grade 2, outputting pre-block")
			ba.out <- res.preBlock
		}

		// At time 5(r+1):
		// If grade received from GC is 2 output the corresponding block. Set r = r+1.
		ba.incrementRound()
		for len(ba.nodeChans[ba.nodeId]) > 0 {
			<-ba.nodeChans[ba.nodeId]
		}
		// Wait one tick because GC finishes in 4 Ticks TODO: fix this?
		<-ba.tickerChan
	}
	log.Println(ba.nodeId, "terminating")
}

// Updates the votes for running the underlying protocols
func (ba *BlockAgreement) updateVotes() {
	// Update vote in GC
	ba.gradedConsensusProtocol.vote.round = ba.round
	ba.gradedConsensusProtocol.vote.preBlock = ba.preBlock
	ba.gradedConsensusProtocol.vote.commits = ba.commits

	// Update vote for propose
	ba.gradedConsensusProtocol.proposeProtocol.vote.round = ba.round
	ba.gradedConsensusProtocol.proposeProtocol.vote.preBlock = ba.preBlock
	ba.gradedConsensusProtocol.proposeProtocol.vote.commits = ba.commits
}

func (ba *BlockAgreement) incrementRound() {
	ba.round++
	ba.gradedConsensusProtocol.round++
	ba.gradedConsensusProtocol.proposeProtocol.round++
}
