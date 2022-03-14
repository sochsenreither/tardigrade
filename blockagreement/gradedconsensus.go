package blockagreement

import (
	"crypto"
	//"log"

	"github.com/niclabs/tcrsa"
	"github.com/sochsenreither/upgrade/utils"
)

type gradedConsensus struct {
	n               int                                     // Number of nodes
	nodeId          int                                     // Id of node
	t               int                                     // Number of maximum faulty nodes
	proposerId      int                                     // Proposer id
	round           int                                     // Round number
	vote            *vote                                   // Input vote of the node
	thresholdCrypto *thresholdCrypto                        // Struct containing the secret key and key meta
	out             chan *gradedConsensusResult             // Output channel
	proposeProtocol *proposeProtocol                        // Underlying sub-protocol
	multicast       func(msg *utils.Message, params ...int) // Function for multicasting messages
	receive         func() chan *utils.Message              // Blocking function for receiving messages
	leader          func() int                     // Function to determin the leader
}

// Returns a new graded consensus protocol instance
func NewGradedConsensus(n, nodeId, t, round int, tickerChan chan int, vote *vote, thresthresholdCrypto *thresholdCrypto, leaderFunc func(round, n int) int, multicastFunc func(msg *utils.Message, round int, receiver ...int), receiveFunc func(nodeId, round int) chan *utils.Message) *gradedConsensus {
	out := make(chan *gradedConsensusResult, 100)
	propose := NewProposeProtocol(n, nodeId, t, -1, round, tickerChan, vote, thresthresholdCrypto, multicastFunc, receiveFunc)

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
	}

	multicast := func(msg *utils.Message, params ...int) {
		multicastFunc(msg, gc.round ,params...)
	}
	receive := func() chan *utils.Message {
		return receiveFunc(nodeId, gc.round)
	}
	leader := func() int {
		return leaderFunc(gc.round, n)
	}

	gc.multicast = multicast
	gc.receive = receive
	gc.leader = leader

	return gc
}

func (gc *gradedConsensus) run() {
	commits := make(map[int]*commitMessage)
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
		// log.Println("--GC--", gc.nodeId, "received output from propose and multicasts it")
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
			result := &gradedConsensusResult{
				blockShare: nil,
				commits:    nil,
				grade:      0,
			}
			// log.Println("--GC--", gc.nodeId, "didn't receive any notify")
			gc.out <- result
			return
		case message := <-gc.receive():
			switch m := message.Payload.(type) {
			case *notifyMessage:
				result := &gradedConsensusResult{
					blockShare: nil,
					commits:    nil,
					grade:      0,
				}
				if gc.isValidNotify(m) {
					result.blockShare = m.blockShare
					result.commits = m.commits
					result.grade = 1
				}
				// log.Println("--GC--", gc.nodeId, "received notify and terminates. Grade:", result.grade)
				gc.out <- result
				return
			}
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

	// log.Println("--GC--", gc.nodeId, "multicasts commit")
	gc.multicast(message)
}

// Handles incoming commit messages
func (gc *gradedConsensus) handleCommitMessages(commits map[int]*commitMessage) {
	for {
		select {
		case gc.proposeProtocol.time = <-gc.proposeProtocol.tickerChan:
			return
		case message := <-gc.receive():
			switch m := message.Payload.(type) {
			case *commitMessage:
				// Upon receiving the first valid commit message from a node add it to list of commits
				if gc.verifyCommitMessage(m) && m.blockShare.Block.Quality() >= gc.t+1 {
					sender := m.sender
					// log.Println("--GC--", gc.nodeId, "received commit from", sender)
					if commits[sender] == nil {
						commits[sender] = m
					}
				}
			}
		}
	}
}

// Find a subset in a set of commit messages on the same pre-block B', such that:
// 1. The size of that subset is greater or equal to t+1
// 2. For each commit c_j in that subset: r_j >= r
// Check for valid signature is not necessary, since that already happened in handleCommitMessages.
func (gc *gradedConsensus) findSubset(commits map[int]*commitMessage, notifySent chan bool) {
	if len(commits) < gc.t+1 {
		// There can't be a subset of size >= t+1
		notifySent <- false
		return
	}

	type helper struct {
		blockShare     *utils.BlockShare
		commitMessages []*commitMessage
	}

	// Create a map with the hashes of pre-blocks as key. Every honest node should commit the same
	// pre-block, but in case of corrupted nodes we need to choose the pre-block with at least t+1
	// occurences.
	subsets := make(map[[32]byte]*helper)
	for _, commit := range commits {
		hash := commit.blockShare.Hash()
		if subsets[hash] == nil {
			// Found a new pre-block
			commitMessages := make([]*commitMessage, 0)
			commitMessages = append(commitMessages, commit)
			subsets[hash] = &helper{
				blockShare:     commit.blockShare,
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
			notify := &notifyMessage{
				sender:     gc.nodeId,
				round:      gc.round,
				blockShare: subset.blockShare,
				commits:    subset.commitMessages,
			}

			message := &utils.Message{
				Sender:  gc.nodeId,
				Payload: notify,
			}

			// log.Println("--GC--", gc.nodeId, "multicasting notify and terminating. Grade: 2")
			gc.multicast(message)

			result := &gradedConsensusResult{
				blockShare: subset.blockShare,
				commits:    subset.commitMessages,
				grade:      2,
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
func (gc *gradedConsensus) isValidNotify(notify *notifyMessage) bool {
	// 1:
	if notify.blockShare.Block.Quality() < gc.n-gc.t {
		// log.Println("--GC--", gc.nodeId, "received a notify that doesn't contain a valid pre-block")
		return false
	}
	// 2:
	// Sets to keep track of distinct nodes and distinct pre-blocks
	distinctNodes := make(map[int]struct{})
	distinctPreBlocks := make(map[[32]byte]struct{})
	for _, commit := range notify.commits {
		// 2.3:
		if commit.round < gc.round {
			// log.Println("--GC--", gc.nodeId, "received a notify that contains a commit message with a roudn number smaller than the current round")
			return false
		}
		distinctNodes[commit.sender] = struct{}{}
		distinctPreBlocks[commit.blockShare.Hash()] = struct{}{}
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
func (gc *gradedConsensus) newSignedCommitMessage(bs *utils.BlockShare) (*commitMessage, error) {
	// Create a new commitMessage
	commitMes := &commitMessage{
		sender:     gc.nodeId,
		round:      gc.round,
		blockShare: bs,
		sig:        nil,
	}

	// Create a hash of the sender, round and blockshare
	hash := commitMes.HashWithoutSig()
	hashPadded, err := tcrsa.PrepareDocumentHash(gc.thresholdCrypto.keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		// log.Println("--GC--", gc.nodeId, "was unanble to hash commitMessage:", err)
		return nil, err
	}

	// Sign the hash
	sigShare, err := gc.thresholdCrypto.keyShare.Sign(hashPadded, crypto.SHA256, gc.thresholdCrypto.keyMeta)
	if err != nil {
		// log.Println("--GC--", gc.nodeId, "was unable to sign commitMessage:", err)
		return nil, err
	}
	commitMes.sig = sigShare

	return commitMes, nil
}

// Verifys a given commitMessage
func (gc *gradedConsensus) verifyCommitMessage(cm *commitMessage) bool {
	hash := cm.HashWithoutSig()
	hashPadded, err := tcrsa.PrepareDocumentHash(gc.thresholdCrypto.keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		// log.Println("--GC--", gc.nodeId, "was unanble to hash commitMessage while verifying:", err)
		return false
	}
	if err = cm.sig.Verify(hashPadded, gc.thresholdCrypto.keyMeta); err != nil {
		// log.Println("--GC--", gc.nodeId, "received invalid commitMessage signature from", cm.sender)
		return false
	}
	return true
}

// GetValue returns the output of the protocol (blocking)
func (gc *gradedConsensus) GetValue() *gradedConsensusResult {
	return <-gc.out
}

// SetInput sets the input
func (gc *gradedConsensus) SetInput(vote *vote) {
	gc.proposeProtocol.SetInput(vote)
	gc.vote = vote
}
