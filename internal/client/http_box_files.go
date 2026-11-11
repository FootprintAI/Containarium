package client

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Reading a box-file error off the REST gateway (#3548). The daemon's error
// handler (internal/gateway ErrorHandler) sends
//
//	{"error": "rpc error: code = DataLoss desc = ...", "code": 500, "message": "..."}
//
// so "code" is the HTTP status and the gRPC code is only in "error".
// boxFileHTTPError recovers the gRPC status from that, so a refusal is as typed
// over REST as over gRPC, and tells a route the daemon does not have (an old
// daemon) from a NOT_FOUND the RPC itself returned.

// gatewayErrorText is how status.Error renders: the gateway's "error" field.
var gatewayErrorText = regexp.MustCompile(`^rpc error: code = ([A-Za-z]+) desc = `)

// grpcCodeByName maps codes.Code.String() back to the code.
var grpcCodeByName = func() map[string]codes.Code {
	m := map[string]codes.Code{}
	for c := codes.OK; c <= codes.Unauthenticated; c++ {
		m[c.String()] = c
	}
	return m
}()

// gatewayRouteNotFound is the message of the gateway mux's own 404, the one a
// daemon without the route answers with.
const gatewayRouteNotFound = "Not Found"

// boxFileHTTPError turns a >= 400 response from a box-file route into an
// error. rpc names the RPC for the old-daemon message.
func boxFileHTTPError(statusCode int, body []byte, rpc string) error {
	var b struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &b)
	code, msg, ok := codes.Unknown, "", false
	if m := gatewayErrorText.FindStringSubmatch(b.Error); m != nil {
		if c, known := grpcCodeByName[m[1]]; known {
			code, msg, ok = c, b.Message, true
			if msg == "" {
				msg = b.Error[len(m[0]):]
			}
		}
	}
	if statusCode == http.StatusNotFound && (!bytes.Contains(body, []byte(`"code"`)) || (ok && code == codes.NotFound && msg == gatewayRouteNotFound)) {
		return status.Errorf(codes.Unimplemented, "server does not expose %s (HTTP 404)", rpc)
	}
	if ok {
		return status.Error(code, msg)
	}
	// Not the daemon's shape: a plain grpc-gateway status body, or anything else.
	if err := typedStatusError(body); err != nil && status.Code(err) <= codes.Unauthenticated {
		return err
	}
	return httpError(body, statusCode, rpc)
}
