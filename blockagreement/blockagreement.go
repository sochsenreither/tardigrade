package blockagreement

import (

	// "log"
	"time"

	"github.com/niclabs/tcrsa"
	"github.com/sochsenreither/upgrade/utils"
)

type BlockAgreement struct {
	UROUND                  int
	n                       int                    // Number of nodes
	nodeId                  int                    // Id of node
	t                       int                    // Number of maximum faulty nodes
	round                   int                    // Round number of BA, not the top protocol
	kappa                   int                    // Security parameter
	blockShare              *utils.BlockShare      // Input pre-block of the node
	commits                 []*commitMessage       // List of commit messages received from GC
	thresholdCrypto         *thresholdCrypto       // Struct containing the secret key and key meta
	out                     chan *utils.BlockShare // Output channel
	gradedConsensusProtocol *gradedConsensus       // Underlying protocol
	tickerChan              chan int               // Timer for synchronizing
	delta                   int                    // Round timer
	ticker                  func()                 // Ticker function that ticks every delta milliseconds
}

func NewBlockAgreement(UROUND, n, nodeId, t, kappa int, blockShare *utils.BlockShare, keyShare *tcrsa.KeyShare, keyMeta *tcrsa.KeyMeta, leaderFunc func(round, n int) int, delta int, handler *utils.Handler) *BlockAgreement {
	multicast := func(msg *utils.Message, round int, receiver ...int) {
		if len(receiver) == 1 {
			handler.Funcs.BLAmulticast(msg, UROUND, round, receiver[0])
		} else {
			handler.Funcs.BLAmulticast(msg, UROUND, round, -1)
		}
	}
	c := make(chan *utils.Message, 99999)
	receive := func(id, round int) chan *utils.Message {
		go func() {
			for {
				val := handler.Funcs.BLAreceive(UROUND, round)
				c <- val
			}
		}()
		return c
	}
	tcs := &thresholdCrypto{
		keyShare: keyShare,
		keyMeta:  keyMeta,
	}
	tickerChan := make(chan int, 99999)
	ticker := func() {

		t := time.NewTicker(time.Duration(delta * int(time.Millisecond)))
		c := 1

		for range t.C {
			// log.Printf("Node %d at tick %d", nodeId, c)
			tickerChan <- c % 6
			c++
			if c == 7*kappa {
				// log.Printf("Node %d ticker terminating", nodeId)
				return
			}
		}
	}
	out := make(chan *utils.BlockShare, n*9999)
	vote := &vote{
		round:      0,
		blockShare: blockShare,
		commits:    nil,
	}
	gradedConsensus := NewGradedConsensus(n, nodeId, t, 0, tickerChan, vote, tcs, leaderFunc, multicast, receive)

	blockAgreement := &BlockAgreement{
		n:                       n,
		nodeId:                  nodeId,
		t:                       t,
		round:                   0,
		kappa:                   kappa,
		blockShare:              blockShare,
		thresholdCrypto:         tcs,
		out:                     out,
		gradedConsensusProtocol: gradedConsensus,
		tickerChan:              tickerChan,
		delta:                   delta,
		ticker:                  ticker,
	}

	return blockAgreement
}

func (ba *BlockAgreement) Run() {
	go ba.ticker()

	for ba.round < ba.kappa {
		// At time 5r:
		// Run GC and denote output.
		// log.Println(ba.nodeId, "------ running GC round", ba.round, "------")
		ba.updateVotes()
		ba.gradedConsensusProtocol.run()
		// TODO: may be blocking forever?
		res := ba.gradedConsensusProtocol.GetValue()
		if res.grade > 0 {
			ba.blockShare = res.blockShare
			ba.commits = res.commits
		}
		if res.grade == 2 {
			// log.Println(ba.nodeId, "got grade 2, outputting block share")
			ba.out <- res.blockShare
		}

		// At time 5(r+1):
		// If grade received from GC is 2 output the corresponding block. Set r = r+1.
		ba.incrementRound()

		// Wait one tick because GC finishes in 4 Ticks TODO: fix this?
		<-ba.tickerChan
	}
	// log.Println(ba.nodeId, "terminating")
}

// Updates the votes for running the underlying protocols
func (ba *BlockAgreement) updateVotes() {
	// Update vote in GC
	ba.gradedConsensusProtocol.vote.round = ba.round
	ba.gradedConsensusProtocol.vote.blockShare = ba.blockShare
	ba.gradedConsensusProtocol.vote.commits = ba.commits

	// Update vote for propose
	ba.gradedConsensusProtocol.proposeProtocol.vote.round = ba.round
	ba.gradedConsensusProtocol.proposeProtocol.vote.blockShare = ba.blockShare
	ba.gradedConsensusProtocol.proposeProtocol.vote.commits = ba.commits
}

func (ba *BlockAgreement) incrementRound() {
	ba.round++
	ba.gradedConsensusProtocol.round++
	ba.gradedConsensusProtocol.proposeProtocol.round++
}

// GetValue returns the output of the protocol. This shouldn't be called before the protocol had time to run
func (ba *BlockAgreement) GetValue() *utils.BlockShare {
	if len(ba.out) == 0 {
		return nil
	}
	return <-ba.out
}

// SetInput sets the input
func (ba *BlockAgreement) SetInput(bs *utils.BlockShare) {
	vote := &vote{
		round:      0,
		blockShare: bs,
		commits:    nil,
	}
	ba.blockShare = bs
	// This also sets the vote for the propose protocol
	ba.gradedConsensusProtocol.SetInput(vote)
}
