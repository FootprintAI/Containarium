package sshauthz

// BackendResolver resolves the same backend identity as the SSH routing table.
// A subprocess adapter must obtain that identity from the sentinel's routing
// state; an SSH host:port alone is not a daemon HTTP endpoint.
type BackendResolver interface {
	BackendForLogin(login string) (backendID string, known bool)
}
