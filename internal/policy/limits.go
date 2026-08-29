package policy

import "time"

const (
	MemoryMaxBytes         int64 = 256 << 20
	MemorySwapBytes        int64 = 0
	TasksMax                     = 64
	CPUQuotaPercent              = 100
	OpenFilesMax                 = 256
	WallTime                     = 30 * time.Second
	ScopeRuntime                 = 35 * time.Second
	ProcessWaitDelay             = 2 * time.Second
	TeardownTimeout              = 3 * time.Second
	TeardownCommandTimeout       = 1 * time.Second
	OperationTimeout             = ScopeRuntime + ProcessWaitDelay + TeardownTimeout + ProcessWaitDelay
)

func ValidTimingPolicy() bool {
	return WallTime+ProcessWaitDelay < ScopeRuntime &&
		TeardownCommandTimeout <= TeardownTimeout &&
		OperationTimeout == ScopeRuntime+ProcessWaitDelay+TeardownTimeout+ProcessWaitDelay
}
