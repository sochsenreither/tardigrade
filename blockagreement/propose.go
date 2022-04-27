package blockagreement

import (
	"crypto"
	"crypto/sha256"

	"github.com/niclabs/tcrsa"
	"github.com/sochsenreither/tardigrade/utils"
)

type proposeProtocol struct {
	n               int                                     // Number of nodes
	nodeId          int                                     // Id of node
	t               int                                     // Number of maximum faulty nodes
	proposerId      int                                     // Proposer id
	round           int                                     // Round number
	time            int                                     // Current time
	tickerChan      chan int                                // Ticker
	vote            *Vote                                   // Vote of the current node
	out             chan *utils.BlockShare                  // Output channel
	thresholdCrypto *thresholdCrypto                        // Struct containing the secret key and key meta
	multicast       func(msg *utils.Message, params ...int) // Function for multicasting messages
	voteChans       map[int]chan *VoteMessage
	proposeChans    map[int]chan *ProposeMessage
}

// Returns a new propose protocol instance
func NewProposeProtocol(n, nodeId, t, proposerId, round int, ticker chan int, vote *Vote, thresthresholdCrypto *thresholdCrypto, multicastFunc func(msg *utils.Message, round int, receiver ...int), voteChans map[int]chan *VoteMessage, proposeChans map[int]chan *ProposeMessage) *proposeProtocol {
	out := make(chan *utils.BlockShare, n)
	p := &proposeProtocol{
		n:               n,
		nodeId:          nodeId,
		t:               t,
		proposerId:      proposerId,
		round:           round,
		time:            0,
		tickerChan:      ticker,
		vote:            vote,
		out:             out,
		thresholdCrypto: thresthresholdCrypto,
		voteChans:       voteChans,
		proposeChans:    proposeChans,
	}

	multicast := func(msg *utils.Message, params ...int) {
		multicastFunc(msg, p.round, params...)
	}

	p.multicast = multicast

	return p
}

func (p proposeProtocol) run() {
	// Keep track of received votes
	votes := make(map[int]*VoteMessage)
	// At time 0:
	// All parties send their votes to the proposer.
	p.sendVotes()
	// Proposer denotes all received votes and at time 1 finds the maxVote and proposes it to every node.
	if p.nodeId == p.proposerId {
		p.handleVotes(votes)
		p.propose(votes)
	}

	for {
		p.time = <-p.tickerChan
		if p.time == 2 {
			// All parties receive propose messages from the proposer. If they are valid multicast
			// them, otherwise output bottom.
			p.handleProposals()
			return
		}
		if p.time > 2 {
			return
		}
	}
}

// Sends vote to the proposer of the protocol.
func (p *proposeProtocol) sendVotes() {
	voteMes, err := p.newSignedVoteMessage()
	if err != nil {
		// log.Println("--P--", p.nodeId, "was unable to create vote message")
	}

	// Wrap the vote message into a protocol message
	message := &utils.Message{
		Sender:  p.nodeId,
		Payload: voteMes,
	}

	//log.Println("--P--", p.nodeId, "Sending vote to proposer")
	p.multicast(message, p.proposerId)
}

// Save received votes in map votes.
func (p *proposeProtocol) handleVotes(votes map[int]*VoteMessage) {
	for {
		select {
		case <-p.tickerChan:
			return
		case v := <-p.voteChans[p.round]:
			// If the signature is invalid or the pre-block is invalid discard the message
			if p.verifyVoteMessage(v) && p.isValidBlockShare(v.Vote.BlockShare) {
				// log.Println("--P--", "Proposer received valid vote from", voteMes.Sender)
				if votes[v.Sender] == nil {
					votes[v.Sender] = v
				}
			} else {
				// log.Println("--P--", "Proposer received invalid signature or invalid pre-block")
			}

		}
	}
}

// Proposer finds maxVote and multicasts it.
func (p *proposeProtocol) propose(votes map[int]*VoteMessage) {
	if len(votes) >= p.t+1 {
		// log.Printf("Proposer received %d votes, needed %d", len(votes), p.t+1)
		// Get maxVote
		maxVote := findMaxVote(votes)

		// Create new proposeMessage
		proposal, err := p.newSignedProposeMessage(maxVote, votes)
		if err != nil {
			// log.Println("--P--", p.nodeId, "was unable to create propose message")
		}

		// Wrap proposeMessage
		message := &utils.Message{
			Sender:  p.nodeId,
			Payload: proposal,
		}

		// Multicast propose to every node.
		//log.Println("--P--", "Proposer is sending maxVote to nodes")
		p.multicast(message)
	} else {
		// log.Printf("Proposer didn't receive enough votes, received %d, needed %d", len(votes), p.t+1)
	}
}

// If received propose message is valid multicast it and listen for other forwarded proposals.
func (p *proposeProtocol) handleProposals() {
	var proposals []*ProposeMessage
	var leaderProposal *ProposeMessage
	received := false
	for {
		select {
		case proposal := <-p.proposeChans[p.round]:
			if proposal.Sender == p.proposerId {
				// TODO: This happens only when using tcp. Why?
				if proposal.Sig == nil {
					continue
				}
				//log.Println("Node", p.nodeId,"got prop from",msg.Sender, proposal)
				// Received proposal is from the proposer
				// If the current node already received a message from the proposer ignore the next one (which will be a multicast forward)
				if !received {
					if p.isValidProposal(proposal) {
						// Multicast proposal
						leaderProposal = proposal
						received = true
						// log.Println("--P--", p.nodeId, "multicasting proposal")
						mes := &utils.Message{
							Sender:  p.nodeId,
							Payload: proposal,
						}
						p.multicast(mes)
					} else {
						// If the proposal is invalid output nil
						// log.Println("--P--", p.nodeId, "received invalid proposal from proposer")
						p.out <- nil
						return
					}
				}
			} else {
				// Received proposal is a forwarded proposal. Save it and check if every received proposal is exactly the same before terminating.
				// log.Println("--P--", p.nodeId, "received forwarded proposal from", msg.Sender)
				proposals = append(proposals, proposal)
			}
		case <-p.tickerChan:
			// This is time 3 and therefore the last tick. Output either nil or a pre-block.
			if leaderProposal == nil {
				// Node didn't receive a proposal of the proposer. Therefore it outputs nil.
				// log.Println("--P--", p.nodeId, "didn't receive a proposal of the proposer")
				p.out <- nil
				return
			} else {
				// Node received a proposal of the proposer. Check if every other received forwarded proposal matches the proposal of the proposer.
				for _, proposal := range proposals {
					if !proposalsAreEqual(proposal, leaderProposal) {
						// log.Println("--P--", p.nodeId, "found a proposer different from the propose of the proposer")
						p.out <- nil
						return
					}
				}
				// log.Println("--P--", p.nodeId, "is outputting a block share")
				p.out <- leaderProposal.Vote.BlockShare
				return
			}
		}
	}
}

// Checks if two proposals are equal
func proposalsAreEqual(p1, p2 *ProposeMessage) bool {
	return p1.Hash() == p2.Hash()
}

// Finds vote (r*, B*, C*) such that r* >= round number of all votes in V (breaking ties by lowest party index).
func findMaxVote(votes map[int]*VoteMessage) (maxVote *Vote) {
	var index int
	for i, v := range votes {
		if maxVote == nil || v.Vote.Round > maxVote.Round || (v.Vote.Round == maxVote.Round && i < index) {
			index, maxVote = i, v.Vote
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
func (p *proposeProtocol) isValidProposal(proposal *ProposeMessage) bool {
	if proposal.Vote == nil {
		panic("Prop vote nil")
	}
	if proposal.Sig == nil {
		panic("Prop sig nil")
	}
	// 1:
	// Check signature of propose message
	if !p.verifyProposeMessage(proposal) {
		return false
	}
	// Check signature of every vote in V
	for _, voteMessage := range proposal.VoteMessages {
		if !p.verifyVoteMessage(voteMessage) {
			// log.Println("--P--", p.nodeId, "found invalid vote signature, vote:", voteMessage)
			return false
		}
	}
	// 2:
	if !p.isValidBlockShare(proposal.Vote.BlockShare) {
		// log.Println("--P--", p.nodeId, "received invalid pre-block in proposal")
		return false
	}
	// 3:
	if p.round == 0 {
		if proposal.Vote.Round != 0 || len(proposal.Vote.Commits) != 0 {
			// log.Println("--P--", p.nodeId, "received proposal with invalid round r vote")
			return false
		}
	} else {
		if len(proposal.Vote.Commits) < p.t+1 {
			// log.Println("--P--", p.nodeId, "received proposal that doesn't have enough commit messages")
			return false
		}
		// TODO: check signature?
		for _, c := range proposal.Vote.Commits {
			if c.Round > proposal.Vote.Round {
				return false
			}
		}
	}
	// 4:
	if len(proposal.VoteMessages) < p.t+1 {
		// log.Println("--P--", p.nodeId, "received proposal that doesn't have enough votes")
		return false
	}
	// 5:
	round := proposal.Vote.Round
	for _, vote := range proposal.VoteMessages {
		if round < vote.Vote.Round {
			// log.Println("--P--", p.nodeId, "found a round number greater than the round number of the vote in the proposal")
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
		hash, _ := tcrsa.PrepareDocumentHash(p.thresholdCrypto.KeyMeta.PublicKey.Size(), crypto.SHA256, h[:])
		if err := mes.Sig.Verify(hash, p.thresholdCrypto.KeyMeta); err != nil {
			// log.Println("--P--", "Signature for message index", i, "in pre-block couldn't be verified.", err)
			return false
		}
	}

	// TODO: check for valid block pointer
	return true
}

// Returns a new signed voteMessage
func (p *proposeProtocol) newSignedVoteMessage() (*VoteMessage, error) {
	// Create a new voteMessage
	voteMes := &VoteMessage{
		Sender: p.nodeId,
		Sig:    nil,
		Vote:   p.vote,
	}

	// Create a hash of the sender and vote
	hash := voteMes.HashWithoutSig()
	hashPadded, err := tcrsa.PrepareDocumentHash(p.thresholdCrypto.KeyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		// log.Println("--P--", p.nodeId, "was unanble to hash vote:", err)
		return nil, err
	}

	// Sign the hash
	sigShare, err := p.thresholdCrypto.KeyShare.Sign(hashPadded, crypto.SHA256, p.thresholdCrypto.KeyMeta)
	if err != nil {
		// log.Println("--P--", p.nodeId, "was unable to sign vote:", err)
		return nil, err
	}
	voteMes.Sig = sigShare

	return voteMes, nil
}

// Returns a new signed proposeMessage
func (p *proposeProtocol) newSignedProposeMessage(vote *Vote, votes map[int]*VoteMessage) (*ProposeMessage, error) {
	// Create new proposeMessage
	proposeMes := &ProposeMessage{
		Sender:       p.nodeId,
		Vote:         vote,
		VoteMessages: votes,
		Sig:          nil,
	}

	// Create a hash of the sender, vote and voteMessages
	hash := proposeMes.HashWithoutSig()
	hashPadded, err := tcrsa.PrepareDocumentHash(p.thresholdCrypto.KeyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		// log.Println("--P--", p.nodeId, "was unanble to hash proposal:", err)
		return nil, err
	}

	// Sign the hash
	sigShare, err := p.thresholdCrypto.KeyShare.Sign(hashPadded, crypto.SHA256, p.thresholdCrypto.KeyMeta)
	if err != nil {
		// log.Println("--P--", p.nodeId, "was unable to sign proposal:", err)
		return nil, err
	}
	proposeMes.Sig = sigShare

	return proposeMes, nil
}

// Verifys a given voteMessage
func (p *proposeProtocol) verifyVoteMessage(vm *VoteMessage) bool {
	hash := vm.HashWithoutSig()
	hashPadded, err := tcrsa.PrepareDocumentHash(p.thresholdCrypto.KeyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		// log.Println("--P--", p.nodeId, "was unable to hash vote while verifying:", err)
		return false
	}
	if err = vm.Sig.Verify(hashPadded, p.thresholdCrypto.KeyMeta); err != nil {
		// log.Println("--P--", p.nodeId, "received invalid vote signature from", vm.sender)
		return false
	}
	return true
}

// Verifys a given proposeMessage
func (p *proposeProtocol) verifyProposeMessage(pm *ProposeMessage) bool {
	hash := pm.HashWithoutSig()
	hashPadded, err := tcrsa.PrepareDocumentHash(p.thresholdCrypto.KeyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
	if err != nil {
		// log.Println("--P--", p.nodeId, "was unanble to hash proposal while verifying:", err)
		return false
	}
	if err = pm.Sig.Verify(hashPadded, p.thresholdCrypto.KeyMeta); err != nil {
		// log.Println("--P--", p.nodeId, "received invalid proposal signature from", pm.sender)
		return false
	}
	return true
}

// GetValue returns the output of the protocol (blocking)
func (p *proposeProtocol) GetValue() *utils.BlockShare {
	return <-p.out
}

// SetInput sets the input
func (p *proposeProtocol) SetInput(vote *Vote) {
	p.vote = vote
}
