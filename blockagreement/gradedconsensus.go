package blockagreement

import (
	"crypto"
	"log"

	"github.com/niclabs/tcrsa"
	"github.com/sochsenreither/upgrade/utils"
)

type gradedConsensus struct {
	n               int                                     // Number of nodes
	nodeId          int                                     // Id of node
	t               int                                     // Number of maximum faulty nodes
	proposerId      int                                     // Proposer id
	round           int                                     // Round number
	vote            *Vote                                   // Input vote of the node
	thresholdCrypto *thresholdCrypto                        // Struct containing the secret key and key meta
	out             chan *GradedConsensusResult             // Output channel
	proposeProtocol *proposeProtocol                        // Underlying sub-protocol
	multicast       func(msg *utils.Message, params ...int) // Function for multicasting messages
	leader          func() int                              // Function to determin the leader
	notifyChans     map[int]chan *NotifyMessage
	commitChans     map[int]chan *CommitMessage
}

// Returns a new graded consensus protocol instance
func NewGradedConsensus(n, nodeId, t, round int, tickerChan chan int, vote *Vote, thresthresholdCrypto *thresholdCrypto, leaderFunc func(round, n int) int, multicastFunc func(msg *utils.Message, round int, receiver ...int), notifyChans map[int]chan *NotifyMessage, commitChans map[int]chan *CommitMessage, voteChans map[int]chan *VoteMessage, proposeChans map[int]chan *ProposeMessage) *gradedConsensus {
	out := make(chan *GradedConsensusResult, 100)
	propose := NewProposeProtocol(n, nodeId, t, -1, round, tickerChan, vote, thresthresholdCrypto, multicastFunc, voteChans, proposeChans)

	gc := &gradedConsensus{
		n:               n,
		nodeId:          nodeId,
		t:               t,
		proposerId:      -1,
		round:           round,
		vote:            vote,
		thresholdCrypto: thresthresholdCrypto,
		out:             out,
		proposeProtocol: propose,
		notifyChans:     notifyChans,
		commitChans:     commitChans,
	}

	multicast := func(msg *utils.Message, params ...int) {
		multicastFunc(msg, gc.round, params...)
	}

	leader := func() int {
		return leaderFunc(gc.round, n)
	}

	gc.multicast = multicast
	gc.leader = leader

	return gc
}

func (gc *gradedConsensus) run() {
	commits := make(map[int]*CommitMessage)
	notifySent := make(chan bool, 1)

	// At time 0:
	// Call leader and run the propose protocol
	leader := gc.leader()
	gc.proposerId = leader
	gc.proposeProtocol.proposerId = leader

	// Update vote before running
	gc.proposeProtocol.run()

	// At time 3:
	proposeOut := gc.proposeProtocol.GetValue()
	// multicast received output (if any)
	if proposeOut != nil {
		// log.Println("--GC--", gc.nodeId, "received output from propose and multicasts it:", proposeOut.Hash())
		gc.multicastCommitMessage(proposeOut)
	}

	// Handle incoming commit messages. If this methode returns the node is now at time 4
	gc.handleCommitMessages(commits)

	// At time 4:
	// Find a subset of commits and listen to incoming notifys (if not already terminated)
	gc.findSubset(commits, notifySent)

	// If a notify was sent the node can terminate
	canTerminate := <-notifySent
	if canTerminate {
		<-gc.proposeProtocol.tickerChan
		return
	}
	// Until time 5:
	// If a valid notify has been received output and terminate
	for {
		select {
		case gc.proposeProtocol.time = <-gc.proposeProtocol.tickerChan:
			// Time 5:
			// If no notify was received output grade 0 and terminate.
			result := &GradedConsensusResult{
				BlockShare: nil,
				Commits:    nil,
				Grade:      0,
			}
			// log.Println("--GC--", gc.nodeId, "didn't receive any notify")
			gc.out <- result
			return
		case m := <-gc.notifyChans[gc.round]:
			result := &GradedConsensusResult{
				BlockShare: nil,
				Commits:    nil,
				Grade:      0,
			}
			if gc.isValidNotify(m) {
				result.BlockShare = m.BlockShare
				result.Commits = m.Commits
				result.Grade = 1
			}
			// log.Println("--GC--", gc.nodeId, "received notify and terminates. Grade:", result.grade)
			gc.out <- result
			return

		}
	}
}

// Creates a commit message and multicasts it
func (gc *gradedConsensus) multicastCommitMessage(bs *utils.BlockShare) {
	commitMes, err := gc.newSignedCommitMessage(bs)
	if err != nil {
		return
	}

	message := &utils.Message{
		Sender:  gc.nodeId,
		Payload: commitMes,
	}

	//log.Println("--GC--", gc.nodeId, "multicasts commit")
	gc.multicast(message)
}

// Handles incoming commit messages
func (gc *gradedConsensus) handleCommitMessages(commits map[int]*CommitMessage) {
	for {
		select {
		case gc.proposeProtocol.time = <-gc.proposeProtocol.tickerChan:
			//log.Printf("Node %d received %d commit messages", gc.nodeId, len(commits))
			return
		case m := <-gc.commitChans[gc.round]:
			//log.Printf("Node %d received commit message from %d", gc.nodeId, m.Sender)
			// Upon receiving the first valid commit message from a node add it to list of commits
			if gc.verifyCommitMessage(m) && m.BlockShare.Block.Quality() >= gc.t+1 {
				sender := m.Sender
				//log.Println("--GC--", gc.nodeId, "received valid commit from", sender)
				if commits[sender] == nil {
					commits[sender] = m
				}
			} else {
				log.Printf("Node %d received invalid commit from %d", gc.nodeId, m.Sender)
			}
		}
	}
}

// Find a subset in a set of commit messages on the same pre-block B', such that:
// 1. The size of that subset is greater or equal to t+1
// 2. For each commit c_j in that subset: r_j >= r
// Check for valid signature is not necessary, since that already happened in handleCommitMessages.
func (gc *gradedConsensus) findSubset(commits map[int]*CommitMessage, notifySent chan bool) {
	if len(commits) < gc.t+1 {
		// There can't be a subset of size >= t+1
		notifySent <- false
		return
	}

	type helper struct {
		blockShare     *utils.BlockShare
		commitMessages []*CommitMessage
	}

	// Create a map with the hashes of pre-blocks as key. Every honest node should commit the same
	// pre-block, but in case of corrupted nodes we need to choose the pre-block with at least t+1
	// occurences.
	subsets := make(map[[32]byte]*helper)
	for _, commit := range commits {
		hash := commit.BlockShare.Hash()
		if subsets[hash] == nil {
			// Found a new pre-block
			commitMessages := make([]*CommitMessage, 0)
			commitMessages = append(commitMessages, commit)
			subsets[hash] = &helper{
				blockShare:     commit.BlockShare,
				commitMessages: commitMessages,
			}
		} else {
			subsets[hash].commitMessages = append(subsets[hash].commitMessages, commit)
		}
	}

	// Choose the subset with length >= t+1. There can only be one of such a subset.
	for _, subset := range subsets {
		if len(subset.commitMessages) >= gc.t+1 {
			// If we found that subset multicast notify, output a grade and give a signal to terminate
			notify := &NotifyMessage{
				Sender:     gc.nodeId,
				Round:      gc.round,
				BlockShare: subset.blockShare,
				Commits:    subset.commitMessages,
			}

			message := &utils.Message{
				Sender:  gc.nodeId,
				Payload: notify,
			}

			// log.Println("--GC--", gc.nodeId, "multicasting notify and terminating. Grade: 2")
			gc.multicast(message)

			result := &GradedConsensusResult{
				BlockShare: subset.blockShare,
				Commits:    subset.commitMessages,
				Grade:      2,
			}
			gc.out <- result
			notifySent <- true
			return
		}
	}

	// Something went wrong. TODO: is there a possible scenario where this can fail?
	notifySent <- false
}

// Returns if a notify message (notify, r, B, C) is valid. Following conditions need to hold:
// 1. The B is a (n-t)-quality pre-block.
// 2. C is a set of valid commit messages, such that:
// 2.1 All commit messages carry the same pre-block.
// 2.2 C contains commit messages from at least t+1 distinct nodes.
// 2.3 For every commit message the round number of that commit is greater or equal to r.
// TODO: verify signature?
func (gc *gradedConsensus) isValidNotify(notify *NotifyMessage) bool {
	// 1:
	if notify.BlockShare.Block.Quality() < gc.n-gc.t {
		// log.Println("--GC--", gc.nodeId, "received a notify that doesn't contain a valid pre-block")
		return false
	}
	// 2:
	// Sets to keep track of distinct nodes and distinct pre-blocks
	distinctNodes := make(map[int]struct{})
	distinctPreBlocks := make(map[[32]byte]struct{})
	for _, commit := range notify.Commits {
		// 2.3:
		if commit.Round < gc.round {
			// log.Println("--GC--", gc.nodeId, "received a notify that contains a commit message with a roudn number smaller than the current round")
			return false
		}
		distinctNodes[commit.Sender] = struct{}{}
		distinctPreBlocks[commit.BlockShare.Hash()] = struct{}{}
	}
	// 2.1:
	if len(distinctPreBlocks) > 1 {
		// log.Println("--GC--", gc.nodeId, "received a notify with more than one pre-block in the commits set")
		return false
	}
	// 2.2:
	if len(distinctNodes) < gc.t+1 {
		// log.Println("--GC--", gc.nodeId, "received a notify with commit messages from less than t+1 distinct nodes")
		return false
	}

	return true
}

// Returns a new signed commitMessage
func (gc *gradedConsensus) newSignedCommitMessage(bs *utils.BlockShare) (*CommitMessage, error) {
	// Create a new commitMessage
	commitMes := &CommitMessage{
		Sender:     gc.nodeId,
		Round:      gc.round,
		BlockShare: bs,
		Sig:        nil,
	}

	// Create a hash of the sender, round and blockshare
	hash := commitMes.HashWithoutSig()
	hashPadded, err := tcrsa.PrepareDocumentHash(gc.thresholdCrypto.KeyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		// log.Println("--GC--", gc.nodeId, "was unanble to hash commitMessage:", err)
		return nil, err
	}

	// Sign the hash
	sigShare, err := gc.thresholdCrypto.KeyShare.Sign(hashPadded, crypto.SHA256, gc.thresholdCrypto.KeyMeta)
	if err != nil {
		// log.Println("--GC--", gc.nodeId, "was unable to sign commitMessage:", err)
		return nil, err
	}
	commitMes.Sig = sigShare

	return commitMes, nil
}

// Verifys a given commitMessage
func (gc *gradedConsensus) verifyCommitMessage(cm *CommitMessage) bool {
	hash := cm.HashWithoutSig()
	hashPadded, err := tcrsa.PrepareDocumentHash(gc.thresholdCrypto.KeyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		// log.Println("--GC--", gc.nodeId, "was unanble to hash commitMessage while verifying:", err)
		return false
	}
	if err = cm.Sig.Verify(hashPadded, gc.thresholdCrypto.KeyMeta); err != nil {
		// log.Println("--GC--", gc.nodeId, "received invalid commitMessage signature from", cm.sender)
		return false
	}
	return true
}

// GetValue returns the output of the protocol (blocking)
func (gc *gradedConsensus) GetValue() *GradedConsensusResult {
	return <-gc.out
}

// SetInput sets the input
func (gc *gradedConsensus) SetInput(vote *Vote) {
	gc.proposeProtocol.SetInput(vote)
	gc.vote = vote
}
