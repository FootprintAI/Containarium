package mcp

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/coderun"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// put_file (#3548) is the MCP twin of `containarium code put-file`: a thin
// wrapper over client.PutBoxFile, the function the CLI calls, over the same
// REST path (PUT /v1/containers/{username}/files). CLI-first (CLAUDE.md): no
// endpoint of its own.
//
// The content is passed inline (text, or base64 for binary), never as a path:
// the tool does not read files on the MCP server's host, so a prompt cannot
// make it copy that host's files into a box.

// putBoxFileFn is that shared function. A variable only so a test can check it
// is the CLI's.
var putBoxFileFn = client.PutBoxFile

// newBoxFileAPI builds the CLI's typed HTTP client from this MCP client's
// transport, base URL and current token.
var newBoxFileAPI = func(c *Client) (*client.HTTPClient, error) {
	if c.tlsConfigErr != nil {
		return nil, fmt.Errorf("MCP client refuses to send request: %w", c.tlsConfigErr)
	}
	token, err := c.readToken()
	if err != nil {
		return nil, fmt.Errorf("authenticate: %w", err)
	}
	return client.NewHTTPClient(c.baseURL, token, client.WithHTTPClient(c.httpClient))
}

// PutBoxFile runs the shared write over this client.
func (c *Client) PutBoxFile(p client.BoxFileParams) (*pb.WriteBoxFileResponse, error) {
	hc, err := newBoxFileAPI(c)
	if err != nil {
		return nil, err
	}
	defer func() { _ = hc.Close() }()
	return putBoxFileFn(hc, p)
}

func putFileTool() Tool {
	return Tool{
		Name: "put_file",
		Description: fmt.Sprintf("Write one file into a box user's home directory so a run on the box can read it "+
			"(no SSH, and the bytes never pass through a shell). Pass the bytes inline: 'content' for text "+
			"or 'content_base64' for anything else, exactly one of them, at most %d bytes decoded. 'path' "+
			"is relative to the home directory and must stay inside it (no absolute path, no '..', nothing "+
			"under .ssh or .containarium). Parent directories are created 0700; the file appears whole or "+
			"not at all, owned by the box user, mode 0600 (or 0400), replacing an existing file. On a box with a "+
			"recorded tool-access level the box user is the unprivileged run user platform runs execute as, so "+
			"the file goes into that user's home; the path in the result is where the file is. The SHA-256 "+
			"of the content (or 'sha256' when given) is checked against the bytes on the box; a mismatch "+
			"leaves no file. Refusals are shown as 'refused (REASON)': INVALID_ARGUMENT (path, mode or size), "+
			"DATA_LOSS (checksum mismatch, nothing written), FAILED_PRECONDITION (a directory at the path), "+
			"PERMISSION_DENIED, NOT_FOUND. The per-call cap is the only daemon-side limit: total writes are "+
			"bounded by the box's own disk, so bound how many files you write. "+
			"Same function as `containarium code put-file`.", coderun.MaxBoxFileBytes),
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"box": map[string]interface{}{
					"type":        "string",
					"description": "The box (owner username) to write into. Mirrors the <box> argument.",
				},
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Destination relative to the box user's home, e.g. attachments/turn-1/brief.md. Mirrors <remote-path>.",
				},
				"content": map[string]interface{}{
					"type":        "string",
					"description": "The file's text, written as UTF-8. Use content_base64 instead for binary data.",
				},
				"content_base64": map[string]interface{}{
					"type":        "string",
					"description": "The file's bytes, standard base64 (RFC 4648, padded).",
				},
				"mode": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"0600", "0400"},
					"description": "File mode. Default 0600.",
				},
				"sha256": map[string]interface{}{
					"type":        "string",
					"description": "Lowercase hex SHA-256 the bytes on the box must match. Default: the checksum of the content sent.",
				},
			},
			"required": []string{"box", "path"},
		},
		Handler: handlePutFile,
	}
}

// parsePutFileArgs validates the arguments before any request is made.
func parsePutFileArgs(args map[string]interface{}) (client.BoxFileParams, error) {
	p := client.BoxFileParams{
		Box:    getStringArg(args, "box", ""),
		Path:   getStringArg(args, "path", ""),
		Mode:   getStringArg(args, "mode", ""),
		SHA256: getStringArg(args, "sha256", ""),
	}
	if err := client.ValidateBoxName(p.Box); err != nil {
		return p, err
	}
	if p.Path == "" {
		return p, errors.New("path is required: where to write the file, relative to the box user's home")
	}
	text, hasText := args["content"]
	enc, hasEnc := args["content_base64"]
	switch {
	case hasText == hasEnc:
		return p, errors.New("pass exactly one of content (text) or content_base64 (bytes)")
	case hasText:
		s, ok := text.(string)
		if !ok {
			return p, errors.New("content must be a string; use content_base64 for binary data")
		}
		p.Content = []byte(s)
	default:
		s, ok := enc.(string)
		if !ok {
			return p, errors.New("content_base64 must be a string")
		}
		// Refuse an oversized argument before decoding it.
		if len(s) > base64.StdEncoding.EncodedLen(coderun.MaxBoxFileBytes) {
			return p, fmt.Errorf("content_base64 decodes to more than the %d-byte limit", coderun.MaxBoxFileBytes)
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return p, fmt.Errorf("content_base64 is not valid base64: %w", err)
		}
		p.Content = b
	}
	if len(p.Content) > coderun.MaxBoxFileBytes {
		return p, fmt.Errorf("content is %d bytes; the limit is %d", len(p.Content), coderun.MaxBoxFileBytes)
	}
	if p.Mode != "" && p.Mode != "0600" && p.Mode != "0400" {
		return p, fmt.Errorf(`mode must be "0600" or "0400", got %q`, p.Mode)
	}
	return p, nil
}

func handlePutFile(api API, args map[string]interface{}) (string, error) {
	p, err := parsePutFileArgs(args)
	if err != nil {
		return "", err
	}
	resp, err := api.PutBoxFile(p)
	if status.Code(err) == codes.Unimplemented {
		return "", errors.New(client.BoxFilesUnsupportedMessage)
	}
	if err != nil {
		return "", err
	}
	return client.RenderBoxFileWrite(p.Box, resp), nil
}
