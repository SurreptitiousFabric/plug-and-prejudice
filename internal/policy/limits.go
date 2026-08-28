package policy

import "time"

const (
	MemoryMaxBytes  int64 = 256 << 20
	MemorySwapBytes int64 = 0
	TasksMax              = 64
	CPUQuotaPercent       = 100
	OpenFilesMax          = 256
	WallTime              = 30 * time.Second
	ScopeRuntime          = 35 * time.Second
)
