package blockagreement

import (
	"crypto"
	"crypto/sha256"
	"log"

	"github.com/niclabs/tcrsa"
	"github.com/sochsenreither/upgrade/utils"
)

type proposeProtocol struct {
	n               int                    // Number of nodes
	nodeId          int                    // Id of node
	t               int                    // Number of maximum faulty nodes
	proposerId      int                    // Proposer id
	round           int                    // Round number
	time            int                    // Current time
	nodeChans       []chan *utils.Message  // Communication channels of all nodes
	tickerChan      chan int               // Ticker
	vote            *vote                  // Vote of the current node
	out             chan *utils.BlockShare // Output channel
	killPropose     chan struct{}          // Termination channel
	thresholdCrypto *thresholdCrypto       // Struct containing the secret key and key meta
}

// Returns a new propose protocol instance
func NewProposeProtocol(n, nodeId, t, proposerId, round int, nodeChans []chan *utils.Message, ticker chan int, vote *vote, out chan *utils.BlockShare, killPropose chan struct{}, thresthresholdCrypto *thresholdCrypto) *proposeProtocol {
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
	voteMes, err := p.newSignedVoteMessage()
	if err != nil {
		log.Println(p.nodeId, "was unable to create vote message")
	}

	// Wrap the vote message into a protocol message
	message := &utils.Message{
		Sender:  p.nodeId,
		Payload: voteMes,
	}

	log.Println(p.nodeId, "Sending vote to proposer")
	p.nodeChans[p.proposerId] <- message
}

// Save received votes in map votes.
func (p *proposeProtocol) handleVotes(votes map[int]*voteMessage) {
	for {
		select {
		case <-p.killPropose:
			p.killPropose <- struct{}{}
			log.Println(p.nodeId, "received kill signal while waiting for votes.. terminating")
			return
		case <-p.tickerChan:
			return
		case voteMes := <-p.nodeChans[p.nodeId]:
			switch v := voteMes.Payload.(type) {
			case *voteMessage:
				// If the signature is invalid or the pre-block is invalid discard the message
				if p.verifyVoteMessage(v) && p.isValidBlockShare(v.vote.blockShare) {
					log.Println("Proposer received valid vote from", voteMes.Sender)
					if votes[v.sender] == nil {
						votes[v.sender] = v
					}
				} else {
					log.Println("Proposer received invalid signature or invalid pre-block")
				}
			default:
				log.Printf("Expected vote from %d, got %T", voteMes.Sender, v)
			}
		}
	}
}

// Proposer finds maxVote and multicasts it.
func (p *proposeProtocol) propose(votes map[int]*voteMessage) {
	if len(votes) >= p.t+1 {
		log.Printf("Proposer received %d votes, needed %d", len(votes), p.t+1)
		// Get maxVote
		maxVote := findMaxVote(votes)

		// Create new proposeMessage
		proposal, err := p.newSignedProposeMessage(maxVote, votes)
		if err != nil {
			log.Println(p.nodeId, "was unable to create propose message")
		}

		// Wrap proposeMessage
		message := &utils.Message{
			Sender:  p.nodeId,
			Payload: proposal,
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
			switch proposal := msg.Payload.(type) {
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
							mes := &utils.Message{
								Sender:  p.nodeId,
								Payload: proposal,
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
					log.Println(p.nodeId, "received forwarded proposal from", msg.Sender)
					proposals = append(proposals, proposal)
				}
			default:
				log.Printf("%d received wrong message type from %d, %T", p.nodeId, msg.Sender, proposal)
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
				log.Println(p.nodeId, "is outputting a block share")
				p.out <- leaderProposal.vote.blockShare
				return
			}
		}
	}
}

// Send message to every node
func (p *proposeProtocol) multicast(message *utils.Message) {
	for _, node := range p.nodeChans {
		node <- message
	}
}

// Checks if two proposals are equal
func proposalsAreEqual(p1, p2 *proposeMessage) bool {
	return p1.Hash() == p2.Hash()
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
	if !p.verifyProposeMessage(proposal) {
		return false
	}
	// Check signature of every vote in V
	for _, voteMessage := range proposal.voteMessages {
		if !p.verifyVoteMessage(voteMessage) {
			log.Println(p.nodeId, "found invalid vote signature, vote:", voteMessage)
			return false
		}
	}
	// 2:
	if !p.isValidBlockShare(proposal.vote.blockShare) {
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
func (p *proposeProtocol) isValidBlockShare(bs *utils.BlockShare) bool {
	if bs.Block.Quality() < (p.n - p.t) {
		return false
	}
	for i, mes := range bs.Block.Vec {
		// If the index is invalid the pre-block is invalid.
		if i != int(mes.Sig.Id-1) {
			return false
		}
		// If the signature is invalid, the pre-block is invalid
		h := sha256.Sum256(mes.Message)
		hash, _ := tcrsa.PrepareDocumentHash(p.thresholdCrypto.keyMeta.PublicKey.Size(), crypto.SHA256, h[:])
		if err := mes.Sig.Verify(hash, p.thresholdCrypto.keyMeta); err != nil {
			log.Println("Signature for message index", i, "in pre-block couldn't be verified.", err)
			return false
		}
	}

	// TODO: check for valid block pointer
	return true
}

// Returns a new signed voteMessage
func (p *proposeProtocol) newSignedVoteMessage() (*voteMessage, error) {
	// Create a new voteMessage
	voteMes := &voteMessage{
		sender: p.nodeId,
		sig:    nil,
		vote:   p.vote,
	}

	// Create a hash of the sender and vote
	hash := voteMes.HashWithoutSig()
	hashPadded, err := tcrsa.PrepareDocumentHash(p.thresholdCrypto.keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		log.Println(p.nodeId, "was unanble to hash vote:", err)
		return nil, err
	}

	// Sign the hash
	sigShare, err := p.thresholdCrypto.keyShare.Sign(hashPadded, crypto.SHA256, p.thresholdCrypto.keyMeta)
	if err != nil {
		log.Println(p.nodeId, "was unable to sign vote:", err)
		return nil, err
	}
	voteMes.sig = sigShare

	return voteMes, nil
}

// Returns a new signed proposeMessage
func (p *proposeProtocol) newSignedProposeMessage(vote *vote,votes map[int]*voteMessage) (*proposeMessage, error) {
	// Create new proposeMessage
	proposeMes := &proposeMessage{
		sender:       p.nodeId,
		vote:         vote,
		voteMessages: votes,
		sig:          nil,
	}

	// Create a hash of the sender, vote and voteMessages
	hash := proposeMes.HashWithoutSig()
	hashPadded, err := tcrsa.PrepareDocumentHash(p.thresholdCrypto.keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		log.Println(p.nodeId, "was unanble to hash proposal:", err)
		return nil, err
	}

	// Sign the hash
	sigShare, err := p.thresholdCrypto.keyShare.Sign(hashPadded, crypto.SHA256, p.thresholdCrypto.keyMeta)
	if err != nil {
		log.Println(p.nodeId, "was unable to sign proposal:", err)
		return nil, err
	}
	proposeMes.sig = sigShare

	return proposeMes, nil
}

// Verifys a given voteMessage
func (p *proposeProtocol) verifyVoteMessage(vm *voteMessage) bool {
	hash := vm.HashWithoutSig()
	hashPadded, err := tcrsa.PrepareDocumentHash(p.thresholdCrypto.keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		log.Println(p.nodeId, "was unable to hash vote while verifying:", err)
		return false
	}
	if err = vm.sig.Verify(hashPadded, p.thresholdCrypto.keyMeta); err != nil {
		log.Println(p.nodeId, "received invalid vote signature from", vm.sender)
		return false
	}
	return true
}

// Verifys a given proposeMessage
func (p *proposeProtocol) verifyProposeMessage(pm *proposeMessage) bool {
	hash := pm.HashWithoutSig()
	hashPadded, err := tcrsa.PrepareDocumentHash(p.thresholdCrypto.keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		log.Println(p.nodeId, "was unanble to hash proposal while verifying:", err)
		return false
	}
	if err = pm.sig.Verify(hashPadded, p.thresholdCrypto.keyMeta); err != nil {
		log.Println(p.nodeId, "received invalid proposal signature from", pm.sender)
		return false
	}
	return true
}
