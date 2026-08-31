// Package version carries build metadata, injected at link time.
package version

var (
	// Version is the semantic version of this build.
	Version = "0.1.0-dev"
	// Commit is the git commit this binary was built from.
	Commit = "unknown"
	// BuildTime is the RFC3339 timestamp of the build.
	BuildTime = "unknown"
)

// Info is the build metadata exposed on the health endpoint.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

// Current returns the build metadata for this binary.
func Current() Info {
	return Info{Version: Version, Commit: Commit, BuildTime: BuildTime}
}
