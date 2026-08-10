package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/secrets"
	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/container"
)

// Choosing how a tenant's secrets reach their box (#1190).
//
// The LXC path stamps `incus config set environment.<NAME>` for env rows and
// writes the container's tmpfs for file rows. Neither exists on K8s, so
// `secret set` succeeded there and the value never arrived — the RPC looks
// identical on both backends.
//
// On K8s every delivery mode collapses to one thing: a key in the tenant's
// mounted Secret. That is not a shortcut. The three LXC modes exist because
// three different mechanisms were needed to get a value to three different
// consumers; a mounted Secret serves all three, and the box's session
// environment is built from the same files (see images/agent-box).

// tenantSecretApplier is the K8s backend's secret materializer. Asserted for
// rather than added to BoxBackend: delivering a Secret is not an operation
// every backend has, and LXC's equivalent is a sequence of execs with no
// single object behind it.
type tenantSecretApplier interface {
	ApplyTenantSecrets(ctx context.Context, tenant string, data map[string][]byte) error
}

// stampSecrets delivers a tenant's secrets to their box on whichever backend
// is running, and is what the RPC and lifecycle call sites use.
//
// The LXC implementation is unchanged and still reached directly by name in
// the paths that are LXC-only.
func (s *ContainerServer) stampSecrets(ctx context.Context, username string) (int, error) {
	if s.boxes().Kind() == box.KindK8s {
		applier, ok := s.boxes().(tenantSecretApplier)
		if !ok {
			return 0, fmt.Errorf("secrets: the K8s box backend cannot materialize secrets; " +
				"they would be stored and never delivered")
		}
		return s.deliverSecretsToK8s(ctx, applier, username)
	}
	return s.stampSecretsOnLXC(ctx, username)
}

// deliverSecretsToK8s materializes every secret the tenant owns into their
// per-tenant Secret, which the box mounts.
//
// Deliberately delivers the whole set rather than a delta: the Secret is the
// desired state, and a deleted secret must disappear from the box. It also
// means delivery is idempotent, so a retry after a partial failure converges.
func (s *ContainerServer) deliverSecretsToK8s(ctx context.Context, applier tenantSecretApplier, username string) (int, error) {
	if s.secretsStore == nil {
		return 0, fmt.Errorf("secrets store not configured")
	}
	secretMap, err := s.secretsStore.LoadAllForUserWithDelivery(ctx, username)
	if err != nil {
		return 0, fmt.Errorf("load secrets: %w", err)
	}

	if err := applier.ApplyTenantSecrets(ctx, username, secretsToK8sData(secretMap)); err != nil {
		return 0, err
	}
	return len(secretMap), nil
}

// secretsToK8sData translates stored rows into the box's mounted files.
//
// Kept separate from the store read so the translation — the step where a
// delivery mode can be silently dropped — is testable without a database.
func secretsToK8sData(secretMap map[string]secrets.SecretValue) map[string][]byte {
	data := make(map[string][]byte, len(secretMap)+1)
	composeEnv := map[string]string{}
	for name, sv := range secretMap {
		if sv.Delivery == secrets.DeliveryCompose {
			// Compose rows are consumed as one dotenv file, not as
			// individual variables. Dropping them here rather than
			// carrying the mode across would be the same silent
			// non-delivery this issue is about, one mode narrower.
			composeEnv[name] = sv.Value
			continue
		}
		// env and file rows are the same object in the box: a file under
		// the secrets mount. env rows differ only in that the session
		// environment is built from them.
		data[name] = []byte(sv.Value)
	}
	if len(composeEnv) > 0 {
		// Rendered by the same function the LXC path uses, not a second
		// renderer: a compose app must see the same file on both backends,
		// and RenderEnvFile already sorts keys, so the bytes are stable
		// across deliveries rather than reshuffling on every pass.
		data[composeSecretKey] = container.RenderEnvFile(
			container.SecretsEnvFile.Header, composeEnv)
	}
	return data
}

// composeSecretKey is the file the compose dotenv lands on inside the box's
// secrets mount. Named after the LXC path's basename so a compose app's
// `env_file:` reference differs only in directory between the backends.
var composeSecretKey = pathBase(container.SecretsEnvFilePath)

func pathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// refreshSecretsMessage describes what a refresh actually did on the backend
// it ran on.
//
// The old wording named `<username>-container` and "re-stamped", which is the
// LXC mechanism and an object that does not exist on K8s. An operator there
// would be told their secrets landed somewhere they could not find (#1190).
func refreshSecretsMessage(kind box.BackendKind, username string, delivered int) string {
	if kind == box.KindK8s {
		return fmt.Sprintf(
			"delivered %d secret(s) to %s's box; the mount refreshes within about a minute, "+
				"and new sessions see the updated values", delivered, username)
	}
	return fmt.Sprintf(
		"re-stamped %d secret(s) on %s-container; new execs will see updated values",
		delivered, username)
}
