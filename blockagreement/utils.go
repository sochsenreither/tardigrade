package blockagreement

import (
	"crypto/sha256"
	"sort"
	"strconv"

	"github.com/niclabs/tcrsa"
	"github.com/sochsenreither/upgrade/utils"
)

type thresholdCrypto struct {
	KeyShare *tcrsa.KeyShare
	KeyMeta  *tcrsa.KeyMeta
}

type voteMessage struct {
	Sender int
	Vote   *vote
	Sig    *tcrsa.SigShare // Signature on sender and vote
}

type proposeMessage struct {
	Sender       int
	Vote         *vote
	VoteMessages map[int]*voteMessage // nodeId -> voteMessage
	Sig          *tcrsa.SigShare      // Signature on sender, vote and voteMessages
}
type vote struct {
	Round      int
	BlockShare *utils.BlockShare
	Commits    []*commitMessage
}

// Hash returns a sha256 hash over all fields of the struct vote
func (v *vote) Hash() [32]byte {
	roundHash := sha256.Sum256([]byte(strconv.Itoa(v.Round)))
	blockShareHash := v.BlockShare.Hash()
	commitsHash := make([]byte, 0)
	for _, c := range v.Commits {
		h := c.Hash()
		commitsHash = append(commitsHash, h[:]...)
	}
	l := make([]byte, 0)
	l = append(l, roundHash[:]...)
	l = append(l, blockShareHash[:]...)
	l = append(l, commitsHash...)
	return sha256.Sum256(l)
}

// Hash returns a sha256 hash over all the fields of the struct vote
func (vm *voteMessage) Hash() [32]byte {
	h := vm.HashWithoutSig()
	sigHash := sha256.Sum256(vm.Sig.Xi)
	l := make([]byte, 0)
	l = append(l, h[:]...)
	l = append(l, sigHash[:]...)
	return sha256.Sum256(l)
}

// HashWithoutSig returns a sha256 hash over sender and vote
func (vm *voteMessage) HashWithoutSig() [32]byte {
	senderHash := sha256.Sum256([]byte(strconv.Itoa(vm.Sender)))
	voteHash := vm.Vote.Hash()
	h := make([]byte, 0)
	h = append(h, senderHash[:]...)
	h = append(h, voteHash[:]...)
	hash := sha256.Sum256(h)
	return hash
}

// Hash returns a sha256 hash over all the fields of the struct proposeMessage
func (pm *proposeMessage) Hash() [32]byte {
	h := pm.HashWithoutSig()
	s := sha256.Sum256(pm.Sig.Xi)
	l := make([]byte, 0)
	l = append(l, h[:]...)
	l = append(l, s[:]...)
	hash := sha256.Sum256(l)
	return hash
}

// HashWithoutSig returns a sha256 hash over sender, vote and voteMessages
func (pm *proposeMessage) HashWithoutSig() [32]byte {
	senderHash := sha256.Sum256([]byte(strconv.Itoa(pm.Sender)))
	voteHash := pm.Vote.Hash()
	vh := make([]byte, 0)
	// We need to iterate in a deterministic manner over the map
	// First collect all keys the iterate over the map with the sorted keys
	keys := make([]int, len(pm.VoteMessages))
	for k := range pm.VoteMessages {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		if pm.VoteMessages[k] == nil {
			// TODO: bug? why can there be a vote == nil in here?
			continue
		}
		h := pm.VoteMessages[k].Hash()
		vh = append(vh, h[:]...)
	}
	l := make([]byte, 0)
	l = append(l, senderHash[:]...)
	l = append(l, voteHash[:]...)
	l = append(l, vh...)
	hash := sha256.Sum256(l)
	return hash
}

type gradedConsensusResult struct {
	blockShare *utils.BlockShare
	commits    []*commitMessage // List of same commitMessages from different nodes
	grade      int
}

type notifyMessage struct {
	sender     int
	round      int
	blockShare *utils.BlockShare
	commits    []*commitMessage // List of same commitMessages from different nodes
}

type commitMessage struct {
	sender     int
	round      int
	blockShare *utils.BlockShare
	sig        *tcrsa.SigShare
}

// Hash returns a sha256 hash over all the fields of struct commitMessage
func (c *commitMessage) Hash() [32]byte {
	h := c.HashWithoutSig()
	s := sha256.Sum256(c.sig.Xi)
	l := make([]byte, 0)
	l = append(l, h[:]...)
	l = append(l, s[:]...)
	return sha256.Sum256(l)
}

// HashWithoutSig returns a sha256 hash over sender, round and blockShare
func (c *commitMessage) HashWithoutSig() [32]byte {
	s := sha256.Sum256([]byte(strconv.Itoa(c.sender)))
	r := sha256.Sum256([]byte(strconv.Itoa(c.round)))
	bs := c.blockShare.Hash()
	l := make([]byte, 0)
	l = append(l, bs[:]...)
	l = append(l, s[:]...)
	l = append(l, r[:]...)
	return sha256.Sum256(l)
}
