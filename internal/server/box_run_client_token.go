package server

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DaemonCapBoxRunClientToken: StartBoxRunRequest.client_token and
// BoxRun.client_token (#3668).
const DaemonCapBoxRunClientToken = "box_run_client_token"

// boxRunClientTokenMaxBytes bounds StartBoxRunRequest.client_token.
const boxRunClientTokenMaxBytes = 128

// validateBoxRunClientToken refuses a client_token the daemon would not store
// as sent (#3668). The token is free text the daemon never interprets, but it
// is handed back to every caller that lists the box's runs, and a caller may
// print it beside a run, so a control character (a line break, an escape
// sequence) that would garble or forge that output is refused rather than
// stored. Empty sets no token.
func validateBoxRunClientToken(token string) error {
	switch {
	case len(token) > boxRunClientTokenMaxBytes:
		return status.Errorf(codes.InvalidArgument, "client_token is longer than %d bytes", boxRunClientTokenMaxBytes)
	case !utf8.ValidString(token):
		return status.Error(codes.InvalidArgument, "client_token is not valid UTF-8")
	case strings.ContainsFunc(token, unicode.IsControl):
		return status.Error(codes.InvalidArgument, "client_token contains a control character")
	}
	return nil
}
