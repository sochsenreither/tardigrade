package blockagreement

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/niclabs/tcrsa"
)

// TODO:
// change signature of pointer to signature of real value

type proposeProtocol struct {
	n               int              // Number of nodes
	nodeId          int              // Id of node
	t               int              // Number of maximum faulty nodes
	proposerId      int              // Proposer id
	round           int              // Round number
	time            int              // Current time
	nodeChans       []chan *message  // Communication channels of all nodes
	tickerChan      chan int         // Ticker
	vote            *vote            // Vote of the current node
	out             chan *PreBlock   // Output channel
	killPropose     chan struct{}    // Termination channel
	thresholdCrypto *thresholdCrypto // Struct containing the secret key and key meta
}

type thresholdCrypto struct {
	keyShare *tcrsa.KeyShare
	keyMeta  *tcrsa.KeyMeta
}

type message struct {
	sender  int
	payload interface{}
}

type voteMessage struct {
	sender int
	vote   *vote
	sig    *tcrsa.SigShare
}

type proposeMessage struct {
	sender       int
	vote         *vote
	voteMessages map[int]*voteMessage
	sig          *tcrsa.SigShare
}

type vote struct {
	round    int
	preBlock *PreBlock
	commits  []*commitMessage
}

// Returns a new propose protocol instance
func NewProposeProtocol(n, nodeId, t, proposerId, round int, nodeChans []chan *message, ticker chan int, vote *vote, out chan *PreBlock, killPropose chan struct{}, thresthresholdCrypto *thresholdCrypto) *proposeProtocol {
	p := &proposeProtocol{
		n:               n,
		nodeId:          nodeId,
		t:               t,
		proposerId:      proposerId,
		round:           round,
		nodeChans:       nodeChans,
		time:            0,
		tickerChan:      ticker,
		vote:            vote,
		out:             out,
		killPropose:     killPropose,
		thresholdCrypto: thresthresholdCrypto,
	}
	return p
}

func (p *proposeProtocol) run() {
	// Keep track of received votes
	votes := make(map[int]*voteMessage)
	// At time 0:
	// All parties send their votes to the proposer.
	p.sendVotes()
	// Proposer denotes all received votes and at time 1 finds the maxVote and proposes it to every node.
	if p.nodeId == p.proposerId {
		p.handleVotes(votes)
		p.propose(votes)
	}

	for {
		select {
		case <-p.killPropose:
			p.killPropose <- struct{}{}
			log.Println(p.nodeId, "received kill signal.. terminating")
			return
		case p.time = <-p.tickerChan:
			if p.time == 2 {
				// All parties receive propose messages from the proposer. If they are valid they multicast them, otherwise output bottom.
				p.handleProposals()
				return
			}
			if p.time > 2 {
				return
			}
		}
	}
}

// Sends vote to the proposer of the protocol.
func (p *proposeProtocol) sendVotes() {
	// Create a new vote message
	voteMes := &voteMessage{
		sender: p.nodeId,
		sig:    nil,
		vote:   p.vote,
	}
	// Creates a string literal of the vote message pointer for signing
	str := fmt.Sprintf("%p", voteMes)
	sig, err := p.sign(str)
	if err != nil {
		log.Println(p.nodeId, "failed to sign vote message")
	}
	voteMes.sig = sig

	// Wrap the vote message into a protocol message
	message := &message{
		sender:  p.nodeId,
		payload: voteMes,
	}

	log.Println(p.nodeId, "Sending vote to proposer")
	p.nodeChans[p.proposerId] <- message
}

// Save received votes in votes.
func (p *proposeProtocol) handleVotes(votes map[int]*voteMessage) {
	for {
		select {
		case <-p.killPropose:
			p.killPropose <- struct{}{}
			log.Println(p.nodeId, "received kill signal while waiting for votes.. terminating")
			return
		case <-p.tickerChan:
			return
		case vote := <-p.nodeChans[p.nodeId]:
			switch v := vote.payload.(type) {
			case *voteMessage:
				// If the signature is invalid or the pre-block is invalid discard the message
				str := fmt.Sprintf("%p", v)
				if p.verify(str, v.sig) && p.isValidPreBlock(v.vote.preBlock) {
					log.Println("Proposer received valid vote from", vote.sender)
					if votes[v.sender] == nil {
						votes[v.sender] = v
					}
				} else {
					log.Println("Proposer received invalid signature or invalid pre-block")
				}
			default:
				log.Printf("Expected vote from %d, got %T", vote.sender, v)
			}
		}
	}
}

// Proposer finds maxVote and multicasts it.
func (p *proposeProtocol) propose(votes map[int]*voteMessage) {
	if len(votes) >= p.t+1 {
		log.Printf("Proposer received %d votes, needed %d", len(votes), p.t+1)
		maxVote := findMaxVote(votes)
		proposal := &proposeMessage{
			sender:       p.nodeId,
			sig:          nil,
			vote:         maxVote,
			voteMessages: votes,
		}
		// Creates a string literal of the propose message pointer for signing
		str := fmt.Sprintf("%p", proposal)
		sig, err := p.sign(str)
		if err != nil {
			log.Println(p.nodeId, "failed to sign propose message")
		}
		proposal.sig = sig

		message := &message{
			sender:  p.nodeId,
			payload: proposal,
		}

		// Multicast propose to every node.
		log.Println("Proposer is sending maxVote to nodes")
		p.multicast(message)
	} else {
		log.Printf("Proposer didn't receive enough votes, received %d, needed %d", len(votes), p.t+1)
	}
}

// If received propose message is valid multicast it and listen for other forwarded proposals.
func (p *proposeProtocol) handleProposals() {
	var proposals []*proposeMessage
	var leaderProposal *proposeMessage
	received := false
	for {
		select {
		case <-p.killPropose:
			p.killPropose <- struct{}{}
			log.Println(p.nodeId, "received kill signal while waiting for proposal.. terminating")
			return
		case msg := <-p.nodeChans[p.nodeId]:
			switch proposal := msg.payload.(type) {
			case *proposeMessage:
				if proposal.sender == p.proposerId {
					// Received proposal is from the proposer
					// If the current node already received a message from the proposer ignore the next one (which will be a multicast forward)
					if !received {
						if p.isValidProposal(proposal) {
							// Multicast proposal
							leaderProposal = proposal
							received = true
							log.Println(p.nodeId, "multicasting proposal")
							mes := &message{
								sender:  p.nodeId,
								payload: proposal,
							}
							p.multicast(mes)
						} else {
							// If the proposal is invalid output nil
							log.Println(p.nodeId, "received invalid proposal from proposer")
							p.out <- nil
							return
						}
					}
				} else {
					// Received proposal is a forwarded proposal. Save it and check if every received proposal is exactly the same before terminating.
					log.Println(p.nodeId, "received forwarded proposal from", msg.sender)
					proposals = append(proposals, proposal)
				}
			default:
				log.Printf("%d received wrong message type from %d, %T", p.nodeId, msg.sender, proposal)
			}
		case <-p.tickerChan:
			// This is time 3 and therefore the last tick. Output either nil or a pre-block.
			if leaderProposal == nil {
				// Node didn't receive a proposal of the proposer. Therefore it outputs nil.
				log.Println(p.nodeId, "didn't receive a proposal of the proposer")
				p.out <- nil
				return
			} else {
				// Node received a proposal of the proposer. Check if every other received forwarded proposal matches the proposal of the proposer.
				for _, proposal := range proposals {
					if !proposalsAreEqual(proposal, leaderProposal) {
						log.Println(p.nodeId, "found a proposer different from the propose of the proposer")
						p.out <- nil
						return
					}
				}
				log.Println(p.nodeId, "is outputting a pre-block")
				p.out <- leaderProposal.vote.preBlock
				return
			}
		}
	}
}

// Send message to every node
func (p *proposeProtocol) multicast(message *message) {
	for _, node := range p.nodeChans {
		node <- message
	}
}

// Checks if two proposals are equal
func proposalsAreEqual(p1, p2 *proposeMessage) bool {
	// TODO: implement this
	return true
}

// Finds vote (r*, B*, C*) such that r* >= round number of all votes in V (breaking ties by lowest party index).
func findMaxVote(votes map[int]*voteMessage) (maxVote *vote) {
	var index int
	for i, v := range votes {
		if maxVote == nil || v.vote.round > maxVote.round || (v.vote.round == maxVote.round && i < index) {
			index, maxVote = i, v.vote
		}
	}
	return maxVote
}

// Checks if a proposal is valid. Following conditions need to hold:
// 1. The signatures on the propose message and on each Vote in V are valid,
// 2. B is a valid pre-block,
// 3. there is a round r vote for B in V,
// 4. |V| contains at least t+1 votes,
// 5. r is >= to the round number of all votes in V.
func (p *proposeProtocol) isValidProposal(proposal *proposeMessage) bool {
	// 1:
	// Check signature of propose message
	str := fmt.Sprintf("%p", proposal)
	if !p.verify(str, proposal.sig) {
		log.Println(p.nodeId, "received invalid proposal signature")
		return false
	}
	// Check signature of every vote in V
	for _, vote := range proposal.voteMessages {
		str := fmt.Sprintf("%p", vote)
		if !p.verify(str, vote.sig) {
			log.Println(p.nodeId, "found invalid vote signature, vote:", vote)
			return false
		}
	}
	// 2:
	if !p.isValidPreBlock(proposal.vote.preBlock) {
		log.Println(p.nodeId, "received invalid pre-block in proposal")
		return false
	}
	// 3:
	if p.round == 0 {
		if proposal.vote.round != 0 || len(proposal.vote.commits) != 0 {
			log.Println(p.nodeId, "received proposal with invalid round r vote")
			return false
		}
	} else {
		if len(proposal.vote.commits) < p.t+1 {
			log.Println(p.nodeId, "received proposal that doesn't have enough commit messages")
			return false
		}
		// TODO: check signature?
		for _, c := range proposal.vote.commits {
			if c.round > proposal.vote.round {
				return false
			}
		}
	}
	// 4:
	if len(proposal.voteMessages) < p.t+1 {
		log.Println(p.nodeId, "received proposal that doesn't have enough votes")
		return false
	}
	// 5:
	round := proposal.vote.round
	for _, vote := range proposal.voteMessages {
		if round < vote.vote.round {
			log.Println(p.nodeId, "found a round number greater than the round number of the vote in the proposal")
			return false
		}
	}
	return true
}

// Determines if a pre-block is valid
// TODO: correct way to check?
func (p *proposeProtocol) isValidPreBlock(pre *PreBlock) bool {
	if pre.Quality() < (p.n - p.t) {
		return false
	}
	for i, mes := range pre.Vec {
		// If the index is invalid the pre-block is invalid. Signatures should be correct at this point (they get checked by parties before inputting their pre-block to the protocol)
		// TODO: check signature?
		if i != int(mes.Sig.Id-1) {
			return false
		}
	}
	return true
}

// Signs a given string and returns a signature share
func (p *proposeProtocol) sign(s string) (sigShare *tcrsa.SigShare, err error) {
	hash, err := p.hash(s)
	if err != nil {
		log.Println(p.nodeId, "was unanble to hash vote:", err)
		return nil, err
	}

	// Sign the hash
	sigShare, err = p.thresholdCrypto.keyShare.Sign(hash, crypto.SHA256, p.thresholdCrypto.keyMeta)
	if err != nil {
		log.Println(p.nodeId, "was unable to sign vote:", err)
		return nil, err
	}

	return sigShare, nil
}

// Verifys if a given signature is valid
func (p *proposeProtocol) verify(s string, sig *tcrsa.SigShare) bool {
	hash, err := p.hash(s)
	if err != nil {
		log.Println(p.nodeId, "was unable to hash vote while verifying:", err)
		return false
	}
	// TODO: Verify is really slow, takes about 1ms
	if err = sig.Verify(hash, p.thresholdCrypto.keyMeta); err != nil {
		log.Println(p.nodeId, "received invalid vote signature")
		return false
	}
	return true
}

// Hashes a given string
func (p *proposeProtocol) hash(s string) (hash []byte, err error) {
	voteHash := sha256.Sum256([]byte(s))
	hash, err = tcrsa.PrepareDocumentHash(p.thresholdCrypto.keyMeta.PublicKey.Size(), crypto.SHA256, voteHash[:])
	if err != nil {
		log.Println(p.nodeId, "was unanble to hash vote:", err)
		return nil, err
	}
	return hash, nil
}
