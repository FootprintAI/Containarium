package cloudexport

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// fakeTokenSource lets tests simulate a credential that resolves but
// can't actually mint a token (revoked, wrong scope, expired refresh
// token, ...) without any network call.
type fakeTokenSource struct {
	token *oauth2.Token
	err   error
}

func (f *fakeTokenSource) Token() (*oauth2.Token, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.token, nil
}

// TestProbe_ADC is the table from the design doc's test strategy:
// (no ADC / wrong-scope token / ok) -> (actionable error / actionable
// error / nil). No network or filesystem ADC search is exercised —
// gcpCredentialsLookup is swapped for the duration of each case.
func TestProbe_ADC(t *testing.T) {
	tests := []struct {
		name    string
		lookup  func(ctx context.Context) (*google.Credentials, error)
		wantErr bool
		wantSub string // substring the error must contain, if wantErr
	}{
		{
			name: "no ADC configured",
			lookup: func(ctx context.Context) (*google.Credentials, error) {
				return nil, errors.New("could not find default credentials")
			},
			wantErr: true,
			wantSub: "roles/monitoring.metricWriter",
		},
		{
			name: "credentials resolve but token source is nil",
			lookup: func(ctx context.Context) (*google.Credentials, error) {
				return &google.Credentials{}, nil
			},
			wantErr: true,
			wantSub: "roles/monitoring.metricWriter",
		},
		{
			name: "credentials resolve but token mint fails (revoked / wrong scope)",
			lookup: func(ctx context.Context) (*google.Credentials, error) {
				return &google.Credentials{
					TokenSource: &fakeTokenSource{err: errors.New("invalid_grant: token has been revoked")},
				}, nil
			},
			wantErr: true,
			wantSub: "roles/monitoring.metricWriter",
		},
		{
			name: "ok",
			lookup: func(ctx context.Context) (*google.Credentials, error) {
				return &google.Credentials{
					TokenSource: &fakeTokenSource{token: &oauth2.Token{
						AccessToken: "fake-token",
						Expiry:      time.Now().Add(time.Hour),
					}},
				}, nil
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			orig := gcpCredentialsLookup
			gcpCredentialsLookup = tc.lookup
			defer func() { gcpCredentialsLookup = orig }()

			sink := NewGCPSink()
			err := sink.Probe(context.Background())

			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			if tc.wantErr && tc.wantSub != "" && !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not contain expected hint %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestGCPSink_NewExporter_NotYetImplemented locks the #1069 scope
// decision: the actual Cloud Monitoring exporter lands with
// #1070/#1071, so NewExporter must fail loudly (not silently no-op)
// until then.
func TestGCPSink_NewExporter_NotYetImplemented(t *testing.T) {
	sink := NewGCPSink()
	_, err := sink.NewExporter(context.Background(), SinkConfig{})
	if err == nil {
		t.Fatal("expected NewExporter to error until #1070/#1071 wire the real exporter")
	}
}
