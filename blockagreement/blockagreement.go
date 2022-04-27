package blockagreement

import (
	// "log"
	"sync"
	"time"

	"github.com/niclabs/tcrsa"
	"github.com/sochsenreither/tardigrade/utils"
)

type BlockAgreement struct {
	UROUND                  int
	n                       int                    // Number of nodes
	nodeId                  int                    // Id of node
	t                       int                    // Number of maximum faulty nodes
	round                   int                    // Round number of BA, not the top protocol
	kappa                   int                    // Security parameter
	blockShare              *utils.BlockShare      // Input pre-block of the node
	commits                 []*CommitMessage       // List of commit messages received from GC
	thresholdCrypto         *thresholdCrypto       // Struct containing the secret key and key meta
	out                     chan *utils.BlockShare // Output channel
	gradedConsensusProtocol *gradedConsensus       // Underlying protocol
	tickerChan              chan int               // Timer for synchronizing
	delta                   int                    // Round timer
	ticker                  func()                 // Ticker function that ticks every delta milliseconds
	notifyChans             map[int]chan *NotifyMessage
	commitChans             map[int]chan *CommitMessage
	voteChans               map[int]chan *VoteMessage
	proposeChans            map[int]chan *ProposeMessage
	receive                 func(UROUND, round int) *utils.Message
	sync.Mutex
}

func NewBlockAgreement(UROUND, n, nodeId, t, kappa int, blockShare *utils.BlockShare, keyShare *tcrsa.KeyShare, keyMeta *tcrsa.KeyMeta, leaderFunc func(round, n int) int, delta int, handlerFuncs *utils.HandlerFuncs) *BlockAgreement {
	multicast := func(msg *utils.Message, round int, receiver ...int) {
		if len(receiver) == 1 {
			handlerFuncs.BLAmulticast(msg, UROUND, round, receiver[0])
		} else {
			handlerFuncs.BLAmulticast(msg, UROUND, round, -1)
		}
	}
	notifyChans := make(map[int]chan *NotifyMessage)
	commitChans := make(map[int]chan *CommitMessage)
	voteChans := make(map[int]chan *VoteMessage)
	proposeChans := make(map[int]chan *ProposeMessage)
	for i := 0; i < kappa; i++ {
		notifyChans[i] = make(chan *NotifyMessage, n*kappa)
		commitChans[i] = make(chan *CommitMessage, n*kappa)
		voteChans[i] = make(chan *VoteMessage, n*kappa)
		proposeChans[i] = make(chan *ProposeMessage, n*kappa)
	}

	tcs := &thresholdCrypto{
		KeyShare: keyShare,
		KeyMeta:  keyMeta,
	}
	tickerChan := make(chan int, 999)
	ticker := func() {

		t := time.NewTicker(time.Duration(delta * int(time.Millisecond)))
		c := 1

		for range t.C {
			//log.Printf("Node %d at tick %d", nodeId, c)
			tickerChan <- c % 6
			c++
			if c == 7*kappa {
				// log.Printf("Node %d ticker terminating", nodeId)
				return
			}
		}
	}
	out := make(chan *utils.BlockShare, n*9)
	vote := &Vote{
		Round:      0,
		BlockShare: blockShare,
		Commits:    nil,
	}
	gradedConsensus := NewGradedConsensus(n, nodeId, t, 0, tickerChan, vote, tcs, leaderFunc, multicast, notifyChans, commitChans, voteChans, proposeChans)

	blockAgreement := &BlockAgreement{
		UROUND:                  UROUND,
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
		notifyChans:             notifyChans,
		commitChans:             commitChans,
		voteChans:               voteChans,
		proposeChans:            proposeChans,
		receive:                 handlerFuncs.BLAreceive,
	}

	return blockAgreement
}

func (ba *BlockAgreement) Run() {
	go ba.ticker()
	listener := func(r int) {
		for {
			m := ba.receive(ba.UROUND, r)
			// log.Printf("Node %d receiving mes %T in round %d", ba.nodeId, m.Payload, r)
			switch mes := m.Payload.(type) {
			case *NotifyMessage:
				ba.notifyChans[r] <- mes
			case *CommitMessage:
				ba.commitChans[r] <- mes
			case *VoteMessage:
				ba.voteChans[r] <- mes
			case *ProposeMessage:
				ba.proposeChans[r] <- mes
			}
		}
	}

	for ba.round < ba.kappa {
		go listener(ba.round)
		// At time 5r:
		// Run GC and denote output.
		// log.Println(ba.nodeId, "------ running GC round", ba.round, "------")
		ba.updateVotes()
		ba.gradedConsensusProtocol.run()
		res := ba.gradedConsensusProtocol.GetValue()
		if res.Grade > 0 {
			ba.blockShare = res.BlockShare
			ba.commits = res.Commits
		}
		if res.Grade == 2 {
			// log.Println(ba.nodeId, "got grade 2, outputting block share")
			ba.out <- res.BlockShare
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
	ba.gradedConsensusProtocol.vote.Round = ba.round
	ba.gradedConsensusProtocol.vote.BlockShare = ba.blockShare
	ba.gradedConsensusProtocol.vote.Commits = ba.commits

	// Update vote for propose
	ba.gradedConsensusProtocol.proposeProtocol.vote.Round = ba.round
	ba.gradedConsensusProtocol.proposeProtocol.vote.BlockShare = ba.blockShare
	ba.gradedConsensusProtocol.proposeProtocol.vote.Commits = ba.commits
}

func (ba *BlockAgreement) incrementRound() {
	ba.Lock()
	defer ba.Unlock()
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
	vote := &Vote{
		Round:      0,
		BlockShare: bs,
		Commits:    nil,
	}
	ba.blockShare = bs
	// This also sets the vote for the propose protocol
	ba.gradedConsensusProtocol.SetInput(vote)
}
