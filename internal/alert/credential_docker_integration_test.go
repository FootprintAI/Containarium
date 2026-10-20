//go:build integration

package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/coderun/engine"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type dockerCredentialProber struct {
	name    string
	failAck bool
}

func (p *dockerCredentialProber) run(ctx context.Context, args ...string) ([]byte, error) {
	command := append([]string{"exec", "-e", "HOME=/guest", p.name}, args...)
	return exec.CommandContext(ctx, "docker", command...).Output()
}
func (p *dockerCredentialProber) CredentialWatchTargets(context.Context) ([]CredentialWatchTarget, error) {
	return oneTargetProber(srcInteractive).targets, nil
}
func (p *dockerCredentialProber) ProbeCredential(ctx context.Context, _ CredentialWatchTarget) (pb.CodeCredentialSource, error) {
	script, _ := engine.CredentialAlertStatusScript(engine.NameClaude)
	out, err := p.run(ctx, "sh", "-c", script)
	if err != nil {
		return srcNone, err
	}
	switch strings.TrimSpace(string(out)) {
	case "interactive":
		return srcInteractive, nil
	case "expired":
		return srcExpired, nil
	case "api-key":
		return pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_API_KEY, nil
	case "none":
		return srcNone, nil
	}
	return srcNone, fmt.Errorf("invalid probe name")
}
func (p *dockerCredentialProber) CredentialEpisodes(ctx context.Context, _ CredentialWatchTarget) (CredentialEpisodes, error) {
	out, err := p.run(ctx, "node", "/tmp/app/dist/credential-state-cli.js", "snapshot")
	var result CredentialEpisodes
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(out, &result)
	return result, err
}
func (p *dockerCredentialProber) AcknowledgeCredentialEpisodes(ctx context.Context, _ CredentialWatchTarget, ids []string) error {
	if p.failAck {
		return fmt.Errorf("synthetic acknowledgement failure")
	}
	args := append([]string{"node", "/tmp/app/dist/credential-state-cli.js", "ack"}, ids...)
	_, err := p.run(ctx, args...)
	return err
}

func TestCredentialDockerEndToEnd(t *testing.T) {
	if os.Getenv("CONTAINARIUM_CREDENTIAL_DOCKER_E2E") != "1" {
		t.Skip("explicit opt-in required for isolated Docker fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	bundle, err := filepath.Abs("../../bin/agent-runtime-bundle.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	deps, err := filepath.Abs("../../agent-runtime/node_modules")
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	name := fmt.Sprintf("containarium-2790-%d", time.Now().UnixNano())
	image := os.Getenv("CONTAINARIUM_CREDENTIAL_DOCKER_IMAGE")
	if image == "" {
		image = "node:20-bookworm-slim"
	}
	args := []string{"run", "-d", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()), "--tmpfs", "/tmp:rw,mode=1777", "--mount", "type=bind,src=" + home + ",dst=/guest", "--mount", "type=bind,src=" + bundle + ",dst=/bundle.tar.gz,readonly", "--mount", "type=bind,src=" + deps + ",dst=/deps/node_modules,readonly", image, "sh", "-c", `mkdir -p /tmp/app && tar -xzf /bundle.tar.gz -C /tmp/app && ln -s /deps/node_modules /tmp/app/node_modules && exec sleep infinity`}
	if out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("fixture container: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	p := &dockerCredentialProber{name: name}
	for attempt := 0; attempt < 50; attempt++ {
		if _, err := p.run(ctx, "test", "-f", "/tmp/app/dist/credential-state-cli.js"); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	var calls atomic.Int32
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if strings.Contains(string(body), "FAKE_") {
			t.Error("fixture credential/provider body escaped into webhook")
		}
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer webhook.Close()
	store := credentialStateStore(t)
	notifier := NewCredentialWebhookNotifier(mapConfig{WebhookURLConfigKey: webhook.URL}, nil)
	watcher := NewCredentialWatcher(p, store, notifier)
	fixture := `import{mkdirSync,writeFileSync}from'node:fs';
import{ClaudeEngine}from'/tmp/app/dist/engines/claude.js';
import{trackClaudeCredentialState}from'/tmp/app/dist/credential-state.js';
const home='/guest';mkdirSync(home+'/.claude',{recursive:true});
const mode=process.argv[1],source=process.argv[2]??'oauth';
if(mode==='recent'||mode==='old'){writeFileSync(home+'/.claude/.credentials.json',JSON.stringify({accessToken:'FAKE_ONLY',refreshToken:'FAKE_ONLY',expiresAt:Date.now()-(mode==='old'?25:1)*3600000}));writeFileSync(home+'/.claude/settings.json','{"ANTHROPIC_API_KEY":"FAKE_ONLY"}');}
else{
const query=()=>Object.assign((async function*(){yield{type:'system',subtype:'init',apiKeySource:source};yield{type:'result',subtype:'success',is_error:mode==='fail',api_error_status:mode==='fail'?401:null,result:'FAKE_PROVIDER_BODY'};})(),{accountInfo:async()=>({apiKeySource:source,apiProvider:'firstParty'})});
const engine=trackClaudeCredentialState(new ClaudeEngine(query),home);
try{await engine.run('synthetic task',{model:'',systemPrompt:'',agentBoxCommand:'fake',agentBoxArgs:[],maxTurns:1},{append(){},close(){}});if(mode==='fail')throw Error('missed auth error');}catch(e){if(mode!=='fail'||e.message!=='coding-engine authentication failed')throw e;}
}`
	run := func(mode, source string) {
		t.Helper()
		if _, err := p.run(ctx, "node", "--input-type=module", "-e", fixture, mode, source); err != nil {
			t.Fatalf("synthetic run %s/%s: %v", mode, source, err)
		}
	}
	sweep := func(want int32) {
		t.Helper()
		watcher.Sweep(ctx)
		if calls.Load() != want {
			t.Fatalf("webhook calls=%d want=%d", calls.Load(), want)
		}
	}
	run("recent", "oauth")
	sweep(0)
	sweep(0)
	run("fail", "user")
	sweep(0) // Cached OAuth file does not change API-key behavior.
	run("fail", "oauth")
	run("fail", "oauth")
	run("success", "oauth")
	p.failAck = true
	sweep(1) // Recovery before sweep cannot delete pending evidence.
	second, err := NewPGCredentialStateStore(ctx, store.pool)
	if err != nil {
		t.Fatal(err)
	}
	p.failAck = false
	watcher = NewCredentialWatcher(p, second, notifier)
	sweep(1)
	if out, err := exec.CommandContext(ctx, "docker", "restart", name).CombinedOutput(); err != nil {
		t.Fatalf("restart: %v %s", err, out)
	}
	for attempt := 0; attempt < 50; attempt++ {
		if _, err := p.run(ctx, "test", "-f", "/tmp/app/dist/credential-state-cli.js"); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	sweep(1)
	run("fail", "oauth")
	sweep(2)
	sweep(2)
	run("success", "user")
	sweep(2) // Key-backed success does not recover OAuth.
	run("success", "oauth")
	sweep(2)
	run("old", "oauth")
	sweep(3)
	sweep(3)
	t.Log("packaged Node 20 runtime, isolated guest, real probe, PostgreSQL acknowledgement/restart and real webhook: PASS")
}
