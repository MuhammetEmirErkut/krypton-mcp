package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the current semantic version of KryptonMCP
	Version = "0.1.0-dev"
	// GitCommit is the git commit hash injected at build time
	GitCommit = "HEAD"
	// BuildDate is the RFC3339 build timestamp injected at build time
	BuildDate = "unknown"
)

// Info contains structured build and runtime metadata
type Info struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Get returns the current version info structure
func Get() Info {
	return Info{
		Version:   Version,
		GitCommit: GitCommit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

// String returns a human-readable representation of version info
func (i Info) String() string {
	return fmt.Sprintf("KryptonMCP %s (commit: %s, built: %s, %s/%s, %s)",
		i.Version, i.GitCommit, i.BuildDate, i.OS, i.Arch, i.GoVersion)
}
