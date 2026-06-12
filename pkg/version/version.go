package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

var (
	// Version is the semantic version. Release builds override this via
	// ldflags (`make build-release VERSION=<tag>` in .github/workflows/release.yml),
	// so the tag is the source of truth; keep this constant in sync as the
	// fallback for plain `make build` / `go build`.
	Version = "0.26.6"

	// GitCommit is the git commit hash (set by build flag via ldflags)
	GitCommit = ""

	// BuildTime is the build timestamp (set by build flag via ldflags)
	BuildTime = ""

	// GoVersion is the Go version used to build
	GoVersion = runtime.Version()

	// Platform is the OS/Arch
	Platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
)

// Info contains all version information
type Info struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// GetVersion returns the current version
func GetVersion() string {
	return Version
}

// ClientVersionHeader is the HTTP header the CLI / MCP client sets to
// advertise its own version to the daemon, e.g.
//
//	X-Containarium-Client-Version: 0.22.4
//
// It lets a server log the client version and, if it chooses, refuse or
// warn on clients too old to speak its contract. Sent alongside a
// conventional User-Agent (see UserAgent) so a server can read whichever
// it prefers.
const ClientVersionHeader = "X-Containarium-Client-Version"

// UserAgent is the product/version token the CLI and MCP client send as
// their HTTP User-Agent when talking to the daemon, e.g. "containarium/0.22.4".
func UserAgent() string {
	return "containarium/" + Version
}

// GetBuildTime returns the build time
func GetBuildTime() string {
	return BuildTime
}

// GetCommitHash returns the git commit hash
// Tries GitCommit variable first (set via ldflags), then VCS build info, then "unknown"
func GetCommitHash() string {
	// First try the explicit GitCommit variable (set via ldflags)
	if GitCommit != "" {
		return GitCommit
	}

	// Fallback to VCS build info (if available)
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}

	var revision string
	var modified bool

	for _, setting := range bi.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}

	if revision == "" {
		return "unknown"
	}

	if modified {
		return revision + "-dirty"
	}

	return revision
}

// Get returns the version information
func Get() Info {
	return Info{
		Version:   Version,
		GitCommit: GetCommitHash(),
		BuildTime: BuildTime,
		GoVersion: GoVersion,
		Platform:  Platform,
	}
}

// String returns a human-readable version string
func String() string {
	return fmt.Sprintf("Containarium v%s", Version)
}

// Verbose returns a detailed version string
func Verbose() string {
	return fmt.Sprintf(`Containarium Version Information:
  Version:    %s
  Git Commit: %s
  Built:      %s
  Go Version: %s
  Platform:   %s`,
		Version, GetCommitHash(), BuildTime, GoVersion, Platform)
}
