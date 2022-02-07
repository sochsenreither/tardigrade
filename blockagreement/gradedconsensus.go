package blockagreement

import (
	"fmt"
	"log"

	"github.com/niclabs/tcrsa"
	"github.com/sochsenreither/upgrade/utils"
)

type gradedConsensus struct {
	n               int                         // Number of nodes
	nodeId          int                         // Id of node
	t               int                         // Number of maximum faulty nodes
	proposerId      int                         // Proposer id
	round           int                         // Round number
	nodeChans       []chan *utils.Message             // Communication channels of all nodes
	vote            *vote                       // Input vote of the node
	killConsensus   chan struct{}               // Termination channel
	thresholdCrypto *thresholdCrypto            // Struct containing the secret key and key meta
	leaderChan      chan *leaderRequest         // Channel for calling Leader(r)
	out             chan *gradedConsensusResult // Output channel
	proposeProtocol *proposeProtocol            // Underlying sub-protocol
}

type leaderRequest struct {
	round  int
	answer chan *leaderAnswer // Channel for receiving an answer from the leader
}

type leaderAnswer struct {
	round  int
	leader int
}

type gradedConsensusResult struct {
	preBlock *utils.PreBlock
	commits  []*commitMessage
	grade    int
}

type commitMessage struct {
	sender   int
	round    int
	preBlock *utils.PreBlock
	sig      *tcrsa.SigShare
}

type notifyMessage struct {
	sender   int
	round    int
	preBlock *utils.PreBlock
	commits  []*commitMessage
}

// Returns a new graded consensus protocol instance
func NewGradedConsensus(n, nodeId, t, round int, nodeChans []chan *utils.Message, tickerChan chan int, vote *vote, killConsensus chan struct{}, thresthresholdCrypto *thresholdCrypto, leaderChan chan *leaderRequest, out chan *gradedConsensusResult) *gradedConsensus {
	proposeOut := make(chan *utils.PreBlock, 10)
	killPropose := make(chan struct{}, 10)
	propose := NewProposeProtocol(n, nodeId, t, -1, round, nodeChans, tickerChan, vote, proposeOut, killPropose, thresthresholdCrypto)

	gradedConsensus := &gradedConsensus{
		n:               n,
		nodeId:          nodeId,
		t:               t,
		proposerId:      -1,
		round:           round,
		nodeChans:       nodeChans,
		vote:            vote,
		killConsensus:   killConsensus,
		thresholdCrypto: thresthresholdCrypto,
		leaderChan:      leaderChan,
		out:             out,
		proposeProtocol: propose,
	}

	return gradedConsensus
}

func (gc *gradedConsensus) run() {
	commits := make(map[int]*commitMessage)
	answer := make(chan *leaderAnswer)
	notifySent := make(chan bool, 1)

	// At time 0:
	// Call leader and run the propose protocol
	gc.leaderChan <- &leaderRequest{
		round:  gc.round,
		answer: answer,
	}
	leaderResponse := <-answer
	gc.proposerId = leaderResponse.leader
	gc.proposeProtocol.proposerId = leaderResponse.leader

	// Update vote before running
	gc.proposeProtocol.run()

	// At time 3:
	proposeOut := <-gc.proposeProtocol.out
	// multicast received output (if any)
	if proposeOut != nil {
		log.Println(gc.nodeId, "received output from propose and multicasts it")
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
		case <-gc.killConsensus:
			gc.proposeProtocol.killPropose <- struct{}{}
			gc.killConsensus <- struct{}{}
			log.Println(gc.nodeId, "received kill signal.. terminating")
			return
		case gc.proposeProtocol.time = <-gc.proposeProtocol.tickerChan:
			// Time 5:
			// If no notify was received output grade 0 and terminate.
			result := &gradedConsensusResult{
				preBlock: nil,
				commits:  nil,
				grade:    0,
			}
			log.Println(gc.nodeId, "didn't receive any notify")
			gc.out <- result
			return
		case message := <-gc.nodeChans[gc.nodeId]:
			switch m := message.Payload.(type) {
			case *notifyMessage:
				result := &gradedConsensusResult{
					preBlock: nil,
					commits:  nil,
					grade:    0,
				}
				if gc.isValidNotify(m) {
					result.preBlock = m.preBlock
					result.commits = m.commits
					result.grade = 1
				}
				log.Println(gc.nodeId, "received notify and terminates. Grade:", result.grade)
				gc.out <- result
				return
			}
		}
	}
}

// Creates a commit message and multicasts it
func (gc *gradedConsensus) multicastCommitMessage(pre *utils.PreBlock) {
	commitMes := &commitMessage{
		sender:   gc.nodeId,
		round:    gc.round,
		preBlock: pre,
		sig:      nil,
	}
	str := fmt.Sprintf("%p", commitMes)
	sig, err := gc.proposeProtocol.sign(str)
	if err != nil {
		log.Println(gc.nodeId, "failed to sign commit message")
	}
	commitMes.sig = sig

	message := &utils.Message{
		Sender:  gc.nodeId,
		Payload: commitMes,
	}

	log.Println(gc.nodeId, "multicasts commit")
	gc.multicast(message)
}

// Sends a given message to all nodes
func (gc *gradedConsensus) multicast(message *utils.Message) {
	for _, node := range gc.nodeChans {
		node <- message
	}
}

// Handles incoming commit messages
func (gc *gradedConsensus) handleCommitMessages(commits map[int]*commitMessage) {
	for {
		select {
		case <-gc.killConsensus:
			gc.proposeProtocol.killPropose <- struct{}{}
			gc.killConsensus <- struct{}{}
			log.Println(gc.nodeId, "received kill signal.. terminating")
			return
		case gc.proposeProtocol.time = <-gc.proposeProtocol.tickerChan:
			return
		case message := <-gc.nodeChans[gc.nodeId]:
			switch m := message.Payload.(type) {
			case *commitMessage:
				// Upon receiving the first valid commit message from a node add it to list of commits
				// TODO: valid commit in own function
				str := fmt.Sprintf("%p", m)
				if gc.proposeProtocol.verify(str, m.sig) && m.preBlock.Quality() >= gc.t+1 {
					sender := m.sender
					log.Println(gc.nodeId, "received commit from", sender)
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
		preBlock       *utils.PreBlock
		commitMessages []*commitMessage
	}

	// Create a map with the hashes of pre-blocks as key. Every honest node should commit the same
	// pre-block, but in case of corrupted nodes we need to choose the pre-block with at least t+1
	// occurences.
	subsets := make(map[[32]byte]*helper)
	for _, commit := range commits {
		hash := commit.preBlock.Hash()
		if subsets[hash] == nil {
			// Found a new pre-block
			commitMessages := make([]*commitMessage, 0)
			commitMessages = append(commitMessages, commit)
			subsets[hash] = &helper{
				preBlock:       commit.preBlock,
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
				sender:   gc.nodeId,
				round:    gc.round,
				preBlock: subset.preBlock,
				commits:  subset.commitMessages,
			}

			message := &utils.Message{
				Sender:  gc.nodeId,
				Payload: notify,
			}

			log.Println(gc.nodeId, "multicasting notify and terminating. Grade: 2")
			gc.multicast(message)

			result := &gradedConsensusResult{
				preBlock: subset.preBlock,
				commits:  subset.commitMessages,
				grade:    2,
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
	if notify.preBlock.Quality() < gc.n-gc.t {
		log.Println(gc.nodeId, "received a notify that doesn't contain a valid pre-block")
		return false
	}
	// 2:
	// Sets to keep track of distinct nodes and distinct pre-blocks
	distinctNodes := make(map[int]struct{})
	distinctPreBlocks := make(map[[32]byte]struct{})
	for _, commit := range notify.commits {
		// 2.3:
		if commit.round < gc.round {
			log.Println(gc.nodeId, "received a notify that contains a commit message with a roudn number smaller than the current round")
			return false
		}
		distinctNodes[commit.sender] = struct{}{}
		distinctPreBlocks[commit.preBlock.Hash()] = struct{}{}
	}
	// 2.1:
	if len(distinctPreBlocks) > 1 {
		log.Println(gc.nodeId, "received a notify with more than one pre-block in the commits set")
		return false
	}
	// 2.2:
	if len(distinctNodes) < gc.t+1 {
		log.Println(gc.nodeId, "received a notify with commit messages from less than t+1 distinct nodes")
		return false
	}

	return true
}
