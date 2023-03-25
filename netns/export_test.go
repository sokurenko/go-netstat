package netns

var (
	// Exported for testing
	GetPidofNetNsFromProcInodes = getPidofNetNsFromProcInodes
	GetNetNsInodeFromSymlink    = getNetNsInodeFromSymlink
)
