package sshsession

import (
	"reflect"
	"testing"

	"github.com/tg123/sshpiper/libplugin"
)

// In enforce mode ssh-authz-plugin returns the upstream itself and writes the
// session records (#2741). This plugin then gets PipeStart and PipeError for a
// connection whose credential it never saw, and must write nothing for it, or
// the session would be recorded twice.
func TestPlugin_SkipUnobserved(t *testing.T) {
	ca := newTestCA(t)
	cert, _ := newTestUserCert(t, ca, "alice", 7)
	for _, tt := range []struct {
		name     string
		skip     bool
		observed bool
		want     int
	}{
		{name: "observed connection is recorded", skip: true, observed: true, want: 4},
		{name: "unobserved connection is skipped", skip: true},
		{name: "without SkipUnobserved every connection is recorded", want: 4},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := &fakeRecorder{}
			p := &Plugin{Recorder: rec, SkipUnobserved: tt.skip}
			cfg := p.Config()
			conn := &libplugin.ConnMeta{UserName: "boxuser", FromAddr: "203.0.113.7:1", UniqId: "s", Metadata: map[string]string{}}
			if tt.observed {
				up, err := cfg.PublicKeyCallback(conn, cert.Marshal())
				if err != nil {
					t.Fatal(err)
				}
				for k, v := range deferredMeta(t, up) {
					conn.Metadata[k] = v
				}
			}
			cfg.PipeStartCallback(conn)
			cfg.PipeErrorCallback(conn, nil)
			cfg.PipeStartCallback(&libplugin.ConnMeta{UserName: "boxuser", FromAddr: "203.0.113.7:2", UniqId: "s2", Metadata: conn.Metadata})
			p.Shutdown()
			if len(rec.recs) != tt.want {
				t.Fatalf("records = %+v, want %d", rec.recs, tt.want)
			}
		})
	}
}

// CredentialMeta is the metadata publicKeyCallback stashes, so a plugin that
// writes the records itself attributes them exactly as this one would.
func TestCredentialMetaMatchesPublicKeyCallback(t *testing.T) {
	ca := newTestCA(t)
	cert, key := newTestUserCert(t, ca, "alice", 7)
	for _, wire := range [][]byte{cert.Marshal(), key.Marshal(), []byte("bad")} {
		up, err := (&Plugin{}).Config().PublicKeyCallback(&libplugin.ConnMeta{}, wire)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := CredentialMeta(wire), deferredMeta(t, up); !reflect.DeepEqual(got, want) {
			t.Fatalf("CredentialMeta = %v, publicKeyCallback stashed %v", got, want)
		}
	}
}
