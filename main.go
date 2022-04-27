package main

import (
	"encoding/gob"
	"fmt"

	"log"
	"os"

	"strconv"
	"time"

	aba "github.com/sochsenreither/tardigrade/binaryagreement"
	bla "github.com/sochsenreither/tardigrade/blockagreement"
	rbc "github.com/sochsenreither/tardigrade/broadcast"
	acs "github.com/sochsenreither/tardigrade/commonsubset"
	abc "github.com/sochsenreither/tardigrade/tardigrade"
	"github.com/sochsenreither/tardigrade/utils"

	"github.com/sochsenreither/tardigrade/simulation"
)

func main() {
	args := os.Args
	if len(args) != 5 {
		fmt.Printf("Arg 1: Start time at provided Second. Arg 2: Starting id. Arg 3: Ending id.\n")
		os.Exit(1)
	}
	startTime, err := strconv.Atoi(args[1])
	if err != nil {
		panic(err)
	}
	arg1, err := strconv.Atoi(args[2])
	if err != nil {
		panic(err)
	}
	arg2, err := strconv.Atoi(args[3])
	if err != nil {
		panic(err)
	}
	delta, err := strconv.Atoi(args[4])
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

	// Delete old log
	n := 4
	lambda := 400
	kappa := 2
	txSize := 8
	// Runtime is 60s
	rounds := 60_000 / lambda
	if kappa > n {
		kappa = n
	}
	filename := fmt.Sprintf("simulation/logs/.log%s-%s_%d", args[2], args[3], lambda)
	os.Remove(filename)

	// Write logs to file
	if arg1 == arg2 && arg1 == -1 {
		filename = "simulation/logs/.log-coin"
	}
	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)
	log.SetFlags(log.Lmicroseconds)

	log.Printf("Parameters: nodes: %d delta: %d lambda: %d kappa: %d txSize: %d rounds: %d", n, delta, lambda, kappa, txSize, rounds)
	fmt.Printf("Parameters: nodes: %d delta: %d lambda: %d kappa: %d txSize: %d rounds: %d", n, delta, lambda, kappa, txSize, rounds)

	_ = arg1
	_ = arg2

	t := time.Now()
	if startTime < 0 {
		startTime = t.Second()
	}

	cfg := utils.CrashCfg(n, 0, rounds, true)

	start := time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), startTime, 0, t.Location())
	simulation.RunNodes(arg1, arg2, n, 0, delta, lambda, kappa, txSize, start, cfg)
}
