package main

import (
	"encoding/gob"
	"fmt"

	"log"
	"os"

	"strconv"
	"time"

	aba "github.com/sochsenreither/upgrade/binaryagreement"
	bla "github.com/sochsenreither/upgrade/blockagreement"
	rbc "github.com/sochsenreither/upgrade/broadcast"
	acs "github.com/sochsenreither/upgrade/commonsubset"
	abc "github.com/sochsenreither/upgrade/upgrade"
	"github.com/sochsenreither/upgrade/utils"

	"github.com/sochsenreither/upgrade/simulation"
)

func main() {
	args := os.Args
	if len(args) != 4 {
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
	filename := fmt.Sprintf("simulation/logs/.log%s-%s", args[2], args[3])
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

	//simulation.RunNodes(arg1, arg2, 3, 0, 6, 500, 2, 8)
	_ = arg1
	_ = arg2

	t := time.Now()
	if startTime < 0 {
		startTime = t.Second()
	}
	start := time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), startTime, 0, t.Location())
	simulation.RunNode(arg1, 3, 1, 1, 100, 3, 8, start, syncNoCrash())

	//simulation.KeySetup(8, 4)
	//simulation.RunNetwork()
}

func syncNoCrash() *utils.SimulationConfig {
	// No crash and a synchronous network

	rounds := 500
	rcfgs := make(utils.RoundConfigs)
	syncCfg := &utils.RoundConfig{
		Ta: 0,
		Ts: 0,
		Crashed: map[int]bool{
		},
		Async: false,
	}
	for i := 0; i < rounds; i++ {
		rcfgs[i] = syncCfg
	}

	return &utils.SimulationConfig{
		Rounds:    rounds,
		RoundCfgs: rcfgs,
	}
}

func asyncOneCrash() *utils.SimulationConfig {
	// One node crashed, network switches between sync and async
	rounds := 500
	rcfgs := make(utils.RoundConfigs)
	asyncCfg := &utils.RoundConfig{
		Ta: 1,
		Ts: 1,
		Crashed: map[int]bool{
			3: true,
		},
		Async: true,
	}
	syncCfg := &utils.RoundConfig{
		Ta: 1,
		Ts: 1,
		Crashed: map[int]bool{
			3: true,
		},
		Async: false,
	}

	for i := 0; i < 50; i++ {
		rcfgs[i] = syncCfg
	}
	for i := 50; i < 100; i++ {
		rcfgs[i] = asyncCfg
	}
	for i := 100; i < 150; i++ {
		rcfgs[i] = syncCfg
	}
	for i := 150; i < 200; i++ {
		rcfgs[i] = asyncCfg
	}
	for i := 200; i < 250; i++ {
		rcfgs[i] = syncCfg
	}
	for i := 300; i < 350; i++ {
		rcfgs[i] = asyncCfg
	}
	for i := 400; i < 450; i++ {
		rcfgs[i] = syncCfg
	}
	for i := 450; i < rounds; i++ {
		rcfgs[i] = asyncCfg
	}

	return &utils.SimulationConfig{
		Rounds:    rounds,
		RoundCfgs: rcfgs,
	}
}