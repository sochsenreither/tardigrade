package main

import (
	"encoding/gob"
	"fmt"
	"os"
	"strconv"

	aba "github.com/sochsenreither/upgrade/binaryagreement"
	bla "github.com/sochsenreither/upgrade/blockagreement"
	rbc "github.com/sochsenreither/upgrade/broadcast"
	acs "github.com/sochsenreither/upgrade/commonsubset"
	abc "github.com/sochsenreither/upgrade/upgrade"

	"github.com/sochsenreither/upgrade/simulation"
)

func main() {
	args := os.Args
	if len(args) != 2 {
		fmt.Printf("Please provide a node id.\n")
		os.Exit(1)
	}
	arg, err := strconv.Atoi(args[1])
	if err != nil {
		panic(err)
	}

	// Register datatypes that will be used as interface{} in utils.Message
	gob.Register(&aba.AbaMessage{})

	gob.Register(&bla.ProposeMessage{})
	gob.Register(&bla.Vote{})
	gob.Register(&bla.VoteMessage{})
	gob.Register(&bla.GradedConsensusResult{})
	gob.Register(&bla.NotifyMessage{})
	gob.Register(&bla.CommitMessage{})

	gob.Register(&rbc.BMessage{})
	gob.Register(&rbc.CMessage{})
	gob.Register(&rbc.SMessage{})

	gob.Register(&acs.AcsCommitteeMessage{})
	gob.Register(&acs.AcsSignatureMessage{})

	gob.Register(&abc.BlockMessage{})
	gob.Register(&abc.CommitteeMessage{})
	gob.Register(&abc.PointerMessage{})
	gob.Register(&abc.PreBlockMessage{})
	gob.Register(&abc.PbDecryptionShareMessage{})

	//simulation.NewSimulationConfig(3, 0, 100, 2500, 2, 8)
	//simulation.RunNode(arg, 3, 0, 200, 1500, 2, 8)
	_ = arg
	simulation.RunNetwork()
}
