package binaryagreement

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"log"
	"strconv"

	"github.com/niclabs/tcrsa"
)

type CommonCoin struct {
	n              int               // Number of nodes
	keyMeta        *tcrsa.KeyMeta    // PKI
	requestChannel chan *coinRequest // Channel to receive requests
}

type coinRequest struct {
	sender int
	round  int
	sig    *tcrsa.SigShare
	answer chan byte
}

func NewCommonCoin(n int, keyMeta *tcrsa.KeyMeta, requestChannel chan *coinRequest) *CommonCoin {
	coin := &CommonCoin{
		n:              n,
		keyMeta:        keyMeta,
		requestChannel: requestChannel,
	}
	return coin
}

func (cc *CommonCoin) run() {
	// Maps from round -> nodeId
	received := make(map[int]map[int]*coinRequest)
	alreadySent := make(map[int]bool)
	coinVals := make(map[int]byte)

	for request := range cc.requestChannel {
		sender := request.sender
		round := request.round

		// Create a new map the first time a request from a new round comes in
		if received[round] == nil {
			received[round] = make(map[int]*coinRequest)
		}

		// Check if a request was already made by a node
		if received[round][sender] != nil {
			log.Println("Already received coin request from", sender, "in round", round)
			continue
		}
		log.Println("Common coin received request for round", round, "from", sender)
		received[round][sender] = request

		// Hash the round number
		h := sha256.Sum256([]byte(strconv.Itoa(round)))
		hash, err := tcrsa.PrepareDocumentHash(cc.keyMeta.PublicKey.Size(), crypto.SHA256, h[:])
		if err != nil {
			log.Println("Common coin failed to create hash for round", round, err)
		}

		// Verify if the received signature share is valid
		if err := request.sig.Verify(hash, cc.keyMeta); err != nil {
			log.Print("Common coin couldn't verify signature share from node", sender)
			continue
		}

		// If enough signature shares were received for a given round combine them to a certificate
		if len(received[round]) >= cc.n/2+1 {
			if alreadySent[round] {
				// If the coin was already created and multicasted and someone asks for the value at a later time, send the value only to this person
				request.answer <- coinVals[round]
			} else {
				// Create the coin value and send it to everyone
				log.Println("Creating certificate in round", round)
				var sigShares tcrsa.SigShareList
				for _, req := range received[round] {
					sigShares = append(sigShares, req.sig)
				}
				certificate, err := sigShares.Join(hash, cc.keyMeta)
				if err != nil {
					log.Println("Common coin failed to create a certificate for round", round)
					continue
				}
				err = rsa.VerifyPKCS1v15(cc.keyMeta.PublicKey, crypto.SHA256, h[:], certificate)
				if err != nil {
					log.Println("Common coin failed to verfiy created certificate for round", round)
				}

				// Compute the hash of the certificate, take the least significant bit and use that as coin.
				certHash := sha256.Sum256(certificate)
				lsb := certHash[len(certHash)-1] & 0x01

				for _, req := range received[round] {
					req.answer <- lsb
				}
				alreadySent[round] = true
				coinVals[round] = lsb
			}
		}
	}
}
