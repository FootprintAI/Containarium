package sshauthz

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

// expiredBeforeCancellation models the interval before the context timer has
// delivered cancellation, even though its deadline has already passed.
type expiredBeforeCancellation struct{ context.Context }

func (expiredBeforeCancellation) Deadline() (time.Time, bool) {
	return time.Now().Add(-time.Second), true
}

type countingTransport struct{ calls int }

func (t *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return nil, &HTTPError{Status: http.StatusBadRequest}
}

func TestBridgeExpiredDeadlinePreservesGrace(t *testing.T) {
	transport := &countingTransport{}
	bridge := &BridgeClient{client: &http.Client{Transport: transport}}
	expired := expiredBeforeCancellation{context.Background()}
	_, err := bridge.Authorize(expired, "backend", &pb.AuthorizeSSHRequest{Login: "alice"})
	if !errors.Is(err, context.DeadlineExceeded) || !isOutage(err) || transport.calls != 0 {
		t.Fatalf("expired deadline: err=%v requests=%d", err, transport.calls)
	}
	now := time.Now()
	cache := NewCache(DefaultGrace, 10, func() time.Time { return now })
	key := testKey(t).PublicKey()
	ck := CacheKey{"backend", "alice", ssh.FingerprintSHA256(key)}
	cache.Put(ck, "cached-person", time.Second)
	now = now.Add(2 * time.Second)
	plugin, err := New(Config{Cache: cache, Resolver: resolverFunc(func(context.Context, string) (string, bool, error) { return "backend", true, nil }), Authorizer: authorizerFunc(func(_ context.Context, b string, r *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
		return bridge.Authorize(expired, b, r)
	})})
	if err != nil {
		t.Fatal(err)
	}
	up, err := plugin.PluginConfig().PublicKeyCallback(&libplugin.ConnMeta{UserName: "alice"}, key.Marshal())
	if err != nil || up.GetNextPlugin() == nil {
		t.Fatalf("did not defer: %v %v", up, err)
	}
	meta := up.GetNextPlugin().Meta
	if meta[sshsession.MetaAuthzDecision] != "ALLOW" || meta[sshsession.MetaUserID] != "cached-person" {
		t.Fatalf("lost grace attribution: %v", meta)
	}
	if _, ok := cache.Get(ck, true); !ok || transport.calls != 0 {
		t.Fatal("expired deadline removed positive or sent request")
	}
}

func TestBridgeCancelledContextSendsNoRequest(t *testing.T) {
	transport := &countingTransport{}
	bridge := &BridgeClient{client: &http.Client{Transport: transport}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := bridge.Authorize(ctx, "backend", &pb.AuthorizeSSHRequest{Login: "alice"})
	if !errors.Is(err, context.Canceled) || transport.calls != 0 {
		t.Fatalf("cancelled context: %v requests=%d", err, transport.calls)
	}
}
