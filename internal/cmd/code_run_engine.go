package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/coderun/engine"
	"github.com/footprintai/containarium/internal/gatewayprovider"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

// `code run`'s engine + credential half (#1727).
//
// Everything below the command string is untouched: process_start, tail_log, the
// resumable reader, demux, attach/status/stop. The reader only ever sees bytes
// and offsets, so it is engine-agnostic by construction — which is why #1727 is
// a change to three functions and not to the streaming core.

// prepareCodeRun reads the box's code.json, mints this run's credential if it
// needs one, writes it, and returns the command process_start should spawn.
//
// The order matters: the credential file is on the box BEFORE process_start, so
// the run's very first action can already read it. Minting after the process
// starts would be a race the run usually loses.
func prepareCodeRun(ctx context.Context, sess *coderun.Session, box, runName string, diag io.Writer) (string, error) {
	cfg, err := readBoxCodeConfig(ctx, sess, diag)
	if err != nil {
		return "", err
	}

	eng, err := cfg.EngineFor()
	if err != nil {
		return "", fmt.Errorf("%s on %q: %w", engine.CodeConfigPath, box, err)
	}

	if cfg.Credential == engine.KindGateway {
		if err := mintAndWriteRunToken(ctx, sess, box, runName, cfg, eng, diag); err != nil {
			return "", err
		}
	}

	return eng.RunCommand(codeRunPrompt, codeRunStreamJSON, codeRunContinue), nil
}

// readBoxCodeConfig reads code.json off the box.
//
// A box with NO code.json is not an error: every box installed before #1727 is
// in exactly that state, and it was installed with Claude Code reading a tenant
// secret. Falling back to that is the compatibility contract — the alternative
// would break every existing box the moment this shipped.
//
// A code.json that exists but cannot be parsed IS an error, including one written
// by a newer CLI. That is the difference between "no record" and "a record this
// binary must not guess at".
func readBoxCodeConfig(ctx context.Context, sess *coderun.Session, diag io.Writer) (*engine.CodeConfig, error) {
	home, err := sess.HomeDir(ctx)
	if err != nil {
		return nil, err
	}
	path := coderun.ExpandHome(home, engine.CodeConfigPath)

	blob, err := sess.ReadFile(ctx, path)
	if err != nil {
		fmt.Fprintf(diag, "• no %s on this box — running the pre-#1727 default (engine=%s credential=%s)\n",
			engine.CodeConfigPath, engine.DefaultName, engine.DefaultKind)
		return &engine.CodeConfig{
			Version:    engine.CodeConfigVersion,
			Engine:     engine.DefaultName,
			Credential: engine.DefaultKind,
		}, nil
	}
	cfg, err := engine.ParseCodeConfig([]byte(blob))
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(diag, "• %s: engine=%s credential=%s", engine.CodeConfigPath, cfg.Engine, cfg.Credential)
	if cfg.Provider != "" {
		fmt.Fprintf(diag, " provider=%s", cfg.Provider)
	}
	if cfg.Model != "" {
		fmt.Fprintf(diag, " model=%s", cfg.Model)
	}
	fmt.Fprintln(diag)
	return cfg, nil
}

// mintAndWriteRunToken mints this run's gateway token and writes it to the
// engine's gateway.env at 0600, over the session already open to the box.
//
// The token is scoped as tightly as the RPC allows: this box, this provider, this
// run, this one model, and a TTL. So a leak is one box, one model, one run, at
// most the TTL — and revocable by its jti before that.
func mintAndWriteRunToken(ctx context.Context, sess *coderun.Session, box, runName string,
	cfg *engine.CodeConfig, eng engine.Engine, diag io.Writer) error {

	provider, err := gatewayprovider.FromName(cfg.Provider)
	if err != nil {
		return fmt.Errorf("%s records provider %q: %w", engine.CodeConfigPath, cfg.Provider, err)
	}

	ttl, err := codeRunTTL()
	if err != nil {
		return err
	}

	req := &pb.MintGatewayTokenRequest{
		Box:      box,
		Provider: provider,
		RunId:    codeRunID(runName),
		Ttl:      durationpb.New(ttl),
	}
	// allowed_models is the token's ceiling. Set only when the box recorded a
	// model: an empty list means "the gateway's own configured ceiling applies",
	// which is not the same as "no models" and must not be forged here.
	if cfg.Model != "" {
		req.AllowedModels = []string{cfg.Model}
	}

	resp, err := mintGatewayTokenFn(ctx, req)
	if err != nil {
		return fmt.Errorf("mint a gateway token for run %q on %q: %w", req.GetRunId(), box, err)
	}

	home, err := sess.HomeDir(ctx)
	if err != nil {
		return err
	}
	envPath := coderun.ExpandHome(home, eng.GatewayEnvPath())
	content := fmt.Sprintf("export %s=%s\nexport %s=%s\n",
		engine.GatewayURLEnvVar, resp.GetBaseUrl(),
		engine.GatewayTokenEnvVar, resp.GetToken())

	if err := sess.WriteFile(ctx, envPath, content, coderun.GatewayEnvFileMode); err != nil {
		return err
	}
	fmt.Fprintf(diag, "✓ minted %s token for run %q (expires %s), wrote %s 0600\n",
		cfg.Provider, req.GetRunId(), resp.GetExpiresAt().AsTime().Format(time.RFC3339), eng.GatewayEnvPath())
	return nil
}

// codeRunID is the run_id the token is bound to: the run's process name plus a
// timestamp.
//
// The timestamp is what makes it unique per run rather than per box, which is
// what lets one run's exit revoke exactly its own token without touching a
// concurrent run under a different --name.
func codeRunID(runName string) string {
	if runName == "" {
		runName = coderun.DefaultRunName
	}
	return runName + "-" + time.Now().UTC().Format("20060102T150405Z")
}

// codeRunTTL resolves --token-ttl. The server caps whatever is asked for, so
// this only has to reject values that are not durations at all.
func codeRunTTL() (time.Duration, error) {
	raw := strings.TrimSpace(codeRunTokenTTL)
	if raw == "" {
		return codeRunTokenTTLDefault, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("--token-ttl %q is not a duration (e.g. 2h, 90m): %w", raw, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("--token-ttl must be positive, got %q", raw)
	}
	return d, nil
}
