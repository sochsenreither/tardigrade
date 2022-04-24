package utils

type RoundConfig struct {
	Ta      int
	Ts      int
	Crashed map[int]bool // NodeId -> crashed
	Async   bool
}

type RoundConfigs map[int]*RoundConfig

type SimulationConfig struct {
	Rounds    int
	RoundCfgs RoundConfigs
}

func makeCrashedMap(n, t int) map[int]bool {
	crashed := make(map[int]bool)
	for i := n-t; i < n; i++ {
		crashed[i] = true
	}
	return crashed
}

func SyncNoCrashes(rounds int) *SimulationConfig {
	rcfgs := make(RoundConfigs)
	syncCfg := &RoundConfig{
		Ta:      0,
		Ts:      0,
		Crashed: map[int]bool{},
		Async:   false,
	}

	for i := 0; i < rounds; i++ {
		rcfgs[i] = syncCfg
	}

	return &SimulationConfig{
		Rounds:    rounds,
		RoundCfgs: rcfgs,
	}
}

func CrashCfg(n, t, rounds int, async bool) *SimulationConfig {
	rcfgs := make(RoundConfigs)
	Cfg := &RoundConfig{
		Ta: t,
		Ts: t,
		Crashed: makeCrashedMap(n, t),
		Async: async,
	}

	for i := 0; i < rounds; i++ {
		rcfgs[i] = Cfg
	}

	return &SimulationConfig{
		Rounds:    rounds,
		RoundCfgs: rcfgs,
	}
}

func CrashesChangingNetworkCfg(n, t, rounds int) *SimulationConfig {
	rcfgs := make(RoundConfigs)
	sCfg := &RoundConfig{
		Ta: t,
		Ts: t,
		Crashed: makeCrashedMap(n, t),
		Async: false,
	}
	aCfg := &RoundConfig{
		Ta: t,
		Ts: t,
		Crashed: makeCrashedMap(n, t),
		Async: true,
	}

	sync := true
	ctr := 0
	steps := rounds / 5

	for i := 0; i < rounds; i++ {
		if ctr == steps {
			sync = !sync
			ctr = 0
		}
		ctr += 1
		if sync {
			rcfgs[i] = sCfg
		} else {
			rcfgs[i] = aCfg
		}
	}

	return &SimulationConfig{
		Rounds:    rounds,
		RoundCfgs: rcfgs,
	}
}

func CrashingContinuously(n, t, rounds int) *SimulationConfig {
	rcfgs := make(RoundConfigs)

	steps := rounds/t
	faults := 1
	ctr := 0

	for i := 0; i < rounds; i++ {
		if ctr == steps {
			faults += 1
			ctr = 0
		}
		ctr += 1
		rcfgs[i] = &RoundConfig{
			Ta: faults,
			Ts: faults,
			Crashed: makeCrashedMap(n, faults),
			Async: true,
		}
	}

	return &SimulationConfig{
		Rounds: rounds,
		RoundCfgs: rcfgs,
	}
}