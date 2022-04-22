package utils

type RoundConfig struct {
	Ta      int
	Ts      int
	Crashed map[int]bool // NodeId -> crashed
	Async bool
}

type RoundConfigs map[int]*RoundConfig

type SimulationConfig struct {
	Rounds int
	RoundCfgs RoundConfigs
}