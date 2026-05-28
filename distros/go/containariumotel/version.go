package containariumotel

// version is the distro version stamped into resource attrs as
// `containarium.distro=go/<version>`. Phase 6 of the rollout plan
// replaces this constant with a //go:embed VERSION binding so release
// builds pick up the daemon's git tag automatically; until then this
// hardcoded value tracks the design doc's example version.
const version = "0.20.0"
