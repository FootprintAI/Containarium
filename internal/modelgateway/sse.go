package modelgateway

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
)

// SSE (server-sent events) interception for the OpenAI-compatible streaming
// chat path. The reverse proxy's ModifyResponse only buffers non-streaming
// JSON, so a streaming chat was previously BOTH unmetered and unfiltered. This
// file adds, for `text/event-stream` responses:
//
//   - token metering — the gateway injects `stream_options.include_usage` into
//     the request so the provider emits a final usage event, which we parse to
//     record input/output tokens (the streaming half of the metering plane).
//   - output filtering — a hold-back window over the assembled assistant text
//     so a verbatim leak of the system prompt (a skill persona — product IP) is
//     caught BEFORE it's emitted to the client and replaced with a refusal
//     (prompt-exfiltration hardening, layer 2).
//
// Both are FAIL-OPEN: any parse/shape we don't recognise is passed through
// unchanged, so a provider quirk degrades to "unfiltered/unmetered passthrough",
// never a broken chat.

const (
	// holdBack is how many trailing chars of the assembled response we withhold
	// before emitting, so a leak run (>= leakMinRun, which is smaller) is caught
	// within the window before any of it reaches the client.
	holdBack = 160
	// leakMinRun is the shortest verbatim run of the system prompt that counts
	// as a leak. Long enough that ordinary overlap (a shared sentence) doesn't
	// trip it; short enough to catch a real "print your instructions" echo.
	leakMinRun = 48
	redactNote = "[redacted: this assistant can't disclose its own instructions]"
)

// extractSystemPrompt pulls the concatenated system-role message text out of an
// OpenAI chat-completions request body. That text is the leak target (the skill
// persona's hidden prompt). Returns "" when there's no system message or the
// body isn't the shape we expect (→ filtering is skipped, fail-open).
func extractSystemPrompt(body []byte) string {
	var req struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if json.Unmarshal(body, &req) != nil {
		return ""
	}
	var b strings.Builder
	for _, m := range req.Messages {
		if m.Role != "system" {
			continue
		}
		// content is usually a string, occasionally an array of parts.
		var s string
		if json.Unmarshal(m.Content, &s) == nil {
			b.WriteString(s)
			b.WriteByte('\n')
			continue
		}
		var parts []struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(m.Content, &parts) == nil {
			for _, p := range parts {
				b.WriteString(p.Text)
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}

// requestModel pulls the "model" field from an OpenAI chat request body (the
// gemini-openai path carries the model in the body, not the URL). "" if absent.
func requestModel(body []byte) string {
	var req struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &req)
	return req.Model
}

// ensureStreamUsage adds `stream_options.include_usage=true` to a streaming
// OpenAI chat request so the provider emits a final usage event we can meter.
// Returns the (possibly rewritten) body and whether the request is streaming.
// Fail-open: on any shape we don't recognise, returns the body unchanged.
func ensureStreamUsage(body []byte) (out []byte, streaming bool) {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return body, false
	}
	s, _ := m["stream"].(bool)
	if !s {
		return body, false
	}
	so, _ := m["stream_options"].(map[string]any)
	if so == nil {
		so = map[string]any{}
	}
	so["include_usage"] = true
	m["stream_options"] = so
	nb, err := json.Marshal(m)
	if err != nil {
		return body, true
	}
	return nb, true
}

// normalize lowercases and collapses runs of whitespace, so a leak survives
// trivial reformatting (extra spaces / newlines) by the model.
func normalize(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

// leaks reports whether resp contains a verbatim run of >= leakMinRun chars of
// the system prompt (both normalized). O(len(resp)*len(sys)) substring scan —
// fine for chat-sized strings.
func leaks(resp, sysNorm string) bool {
	if len(sysNorm) < leakMinRun {
		return false
	}
	r := normalize(resp)
	if len(r) < leakMinRun {
		return false
	}
	// Slide a leakMinRun window over the response; any window that is a
	// substring of the system prompt is a verbatim leak.
	for i := 0; i+leakMinRun <= len(r); i++ {
		if strings.Contains(sysNorm, r[i:i+leakMinRun]) {
			return true
		}
	}
	return false
}

// sseChunk is the slice of an OpenAI streaming chunk we read. The top-level
// envelope fields (id/object/created/model) are captured so the re-serialized
// content chunks we emit carry the SAME envelope as the upstream — a chunk
// missing object/id/model is rejected by strict clients (LibreChat v0.8.6 hangs
// on it), so the filtered path must reproduce the full shape, not a minimal one.
type sseChunk struct {
	ID      string          `json:"id"`
	Object  string          `json:"object"`
	Created json.RawMessage `json:"created"`
	Model   string          `json:"model"`
	Choices []struct {
		Delta struct {
			Content   string          `json:"content"`
			ToolCalls json.RawMessage `json:"tool_calls"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
	Usage map[string]any `json:"usage"`
}

// outChunk is an OpenAI-shaped streaming chunk the gateway re-emits on the
// filtered path (held-back content, redaction note, finish/usage envelope). It
// mirrors the upstream envelope so strict clients accept it. Usage is kept as
// raw JSON: it is the provider's own pass-through metering object (the
// type-erasing wire boundary), forwarded verbatim, never constructed here.
type outChunk struct {
	ID      string          `json:"id,omitempty"`
	Object  string          `json:"object"`
	Created json.RawMessage `json:"created,omitempty"`
	Model   string          `json:"model,omitempty"`
	Choices []outChoice     `json:"choices,omitempty"`
	Usage   json.RawMessage `json:"usage,omitempty"`
}

type outChoice struct {
	Index        int      `json:"index"`
	Delta        outDelta `json:"delta"`
	FinishReason *string  `json:"finish_reason,omitempty"`
}

type outDelta struct {
	Content string `json:"content,omitempty"`
}

// chunkHasToolCalls reports whether a streaming choice carries a non-empty
// tool_calls array — the delta that asks the client to invoke a function.
func chunkHasToolCalls(ch sseChunk) bool {
	if len(ch.Choices) == 0 {
		return false
	}
	raw := strings.TrimSpace(string(ch.Choices[0].Delta.ToolCalls))
	return raw != "" && raw != "null" && raw != "[]"
}

// normalizeToolFinish rewrites finish_reason "stop" -> "tool_calls" in an
// OpenAI chat chunk payload. Gemini's OpenAI-compat surface returns "stop" even
// when it emitted a tool call, which is NOT OpenAI-conformant: an agent client
// (e.g. LibreChat) then never runs the tool and the turn hangs until reaped.
// Only choices whose finish_reason is exactly "stop" are touched; the tool_calls
// themselves and any provider extras are preserved. Fail-open: returns the input
// unchanged on any shape it doesn't recognise or if nothing changed.
func normalizeToolFinish(payload string) string {
	var m map[string]any
	if json.Unmarshal([]byte(payload), &m) != nil {
		return payload
	}
	chs, ok := m["choices"].([]any)
	if !ok {
		return payload
	}
	changed := false
	for _, c := range chs {
		cm, _ := c.(map[string]any)
		if cm == nil {
			continue
		}
		if fr, _ := cm["finish_reason"].(string); fr == "stop" {
			cm["finish_reason"] = "tool_calls"
			changed = true
		}
	}
	if !changed {
		return payload
	}
	nb, err := json.Marshal(m)
	if err != nil {
		return payload
	}
	return string(nb)
}

// standardizeToolCalls rewrites an OpenAI streaming chunk's tool_calls deltas to
// the spec shape a LangChain-based client (LibreChat v0.8.6) requires: each
// entry MUST carry an `index` (used to merge streamed tool-call deltas) and only
// the standard fields. Gemini's OpenAI-compat surface OMITS `index` and adds a
// non-standard `extra_content` (a `thought_signature`); without the index the
// client's stream parser throws and aborts the turn ("terminated") before it can
// run the tool, and the stray field can trip strict decoders. We inject a
// position-based index where missing and drop `extra_content`. Fail-open:
// returns the input unchanged on any shape it doesn't recognise or no change.
func standardizeToolCalls(payload string) string {
	var m map[string]any
	if json.Unmarshal([]byte(payload), &m) != nil {
		return payload
	}
	chs, ok := m["choices"].([]any)
	if !ok {
		return payload
	}
	changed := false
	for _, c := range chs {
		cm, _ := c.(map[string]any)
		if cm == nil {
			continue
		}
		delta, _ := cm["delta"].(map[string]any)
		if delta == nil {
			continue
		}
		tcs, _ := delta["tool_calls"].([]any)
		for i, tc := range tcs {
			tcm, _ := tc.(map[string]any)
			if tcm == nil {
				continue
			}
			if _, has := tcm["index"]; !has {
				tcm["index"] = i
				changed = true
			}
			if _, has := tcm["extra_content"]; has {
				delete(tcm, "extra_content")
				changed = true
			}
		}
	}
	if !changed {
		return payload
	}
	nb, err := json.Marshal(m)
	if err != nil {
		return payload
	}
	return string(nb)
}

// normalizeNonStreamToolFinish rewrites finish_reason "stop" -> "tool_calls" on
// a NON-streaming OpenAI chat response when the choice actually carries a
// message.tool_calls array (Gemini returns "stop" there too). Mutates decoded
// in place; reports whether anything changed.
func normalizeNonStreamToolFinish(decoded map[string]any) bool {
	chs, ok := decoded["choices"].([]any)
	if !ok {
		return false
	}
	changed := false
	for _, c := range chs {
		cm, _ := c.(map[string]any)
		if cm == nil {
			continue
		}
		if fr, _ := cm["finish_reason"].(string); fr != "stop" {
			continue
		}
		msg, _ := cm["message"].(map[string]any)
		if msg == nil {
			continue
		}
		if tc, ok := msg["tool_calls"].([]any); ok && len(tc) > 0 {
			cm["finish_reason"] = "tool_calls"
			changed = true
		}
	}
	return changed
}

// filterSSEStream copies an OpenAI-style SSE stream from src to dst, holding
// back the trailing window so a system-prompt leak is redacted before emission,
// and invoking onUsage with any final usage block. Content is re-emitted as
// `delta.content` chunks that carry the SAME envelope (id/object/created/model)
// as the upstream chunks — a minimal chunk missing those fields is dropped by
// strict clients (LibreChat v0.8.6 hangs). Non-content events pass through
// unchanged. Runs in its own goroutine; closes dst when done.
func filterSSEStream(dst *io.PipeWriter, src io.ReadCloser, sysPrompt string, parse func(map[string]any) Usage, onUsage func(Usage)) {
	defer src.Close()
	sysNorm := normalize(sysPrompt)
	filtering := sysNorm != "" && len(sysNorm) >= leakMinRun

	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var pending strings.Builder // assembled, not-yet-emitted content
	var emitted strings.Builder // already emitted content (for leak context)
	redacted := false
	// Usage arrives cumulatively across one or more events; record only the
	// FINAL value once (recording each event would double-count).
	var lastUsage Usage
	haveUsage := false
	// Gemini ends a tool-call turn with finish_reason "stop"; once we've seen a
	// tool call we rewrite that to the OpenAI-conformant "tool_calls" so the
	// agent client runs the tool instead of hanging.
	sawToolCall := false

	// Envelope fields captured from the first upstream chunk, so the chunks WE
	// synthesize (held-back content, redaction note, finish envelope) carry the
	// same id/object/created/model as the provider's own chunks. Without these a
	// strict client (LibreChat v0.8.6) drops the chunk and the stream "hangs".
	var envID, envObject, envModel string
	var envCreated json.RawMessage
	newChunk := func() outChunk {
		obj := envObject
		if obj == "" {
			obj = "chat.completion.chunk"
		}
		return outChunk{ID: envID, Object: obj, Created: envCreated, Model: envModel}
	}

	writeContent := func(s string) error {
		if s == "" {
			return nil
		}
		c := newChunk()
		c.Choices = []outChoice{{Delta: outDelta{Content: s}}}
		b, _ := json.Marshal(c)
		_, err := dst.Write([]byte("data: " + string(b) + "\n\n"))
		return err
	}

	var loopErr error
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "data:") {
			// comments / blank lines / event: lines — pass through.
			if _, err := dst.Write([]byte(line + "\n")); err != nil {
				loopErr = err
				break
			}
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
		if payload == "[DONE]" {
			break
		}
		var ch sseChunk
		if json.Unmarshal([]byte(payload), &ch) != nil {
			// Unknown chunk shape — pass through (fail-open).
			if _, err := dst.Write([]byte(line + "\n\n")); err != nil {
				loopErr = err
				break
			}
			continue
		}
		if envID == "" && ch.ID != "" {
			envID, envObject, envModel, envCreated = ch.ID, ch.Object, ch.Model, ch.Created
		}
		if ch.Usage != nil {
			lastUsage = parse(map[string]any{"usage": ch.Usage})
			haveUsage = true
		}
		if chunkHasToolCalls(ch) {
			sawToolCall = true
		}

		// Metering-only (no system prompt / filter disabled): pass the original
		// chunk through unchanged — no hold-back, no re-serialization — except we
		// still normalize a tool-call turn's finish_reason ("stop" -> "tool_calls")
		// so the agent client runs the tool. The tool_calls delta itself passes
		// through verbatim.
		if !filtering {
			out := line
			if chunkHasToolCalls(ch) {
				out = "data: " + normalizeToolFinish(standardizeToolCalls(payload))
			} else if sawToolCall && len(ch.Choices) > 0 && ch.Choices[0].FinishReason != nil && *ch.Choices[0].FinishReason == "stop" {
				out = "data: " + normalizeToolFinish(payload)
			}
			if _, err := dst.Write([]byte(out + "\n")); err != nil {
				loopErr = err
				break
			}
			continue
		}

		content := ""
		var finish *string
		if len(ch.Choices) > 0 {
			content = ch.Choices[0].Delta.Content
			finish = ch.Choices[0].FinishReason
		}

		// Tool-call chunks pass through verbatim (with finish_reason normalized).
		// A tool call is a structured function invocation, not free-text content,
		// so it is NOT a system-prompt-leak vector and must not be dropped or held
		// back — dropping it is exactly what hangs the agent. Flush any pending
		// safe content first to preserve ordering.
		if chunkHasToolCalls(ch) {
			if !redacted && pending.Len() > 0 {
				if err := writeContent(pending.String()); err != nil {
					loopErr = err
					break
				}
				emitted.WriteString(pending.String())
				pending.Reset()
			}
			if _, err := dst.Write([]byte("data: " + normalizeToolFinish(standardizeToolCalls(payload)) + "\n\n")); err != nil {
				loopErr = err
				break
			}
			continue
		}

		if content != "" && !redacted {
			if filtering && leaks(emitted.String()+pending.String()+content, sysNorm) {
				redacted = true
				pending.Reset()
				if err := writeContent(redactNote); err != nil {
					loopErr = err
					break
				}
			} else {
				pending.WriteString(content)
				// Emit everything except the trailing hold-back window.
				p := pending.String()
				if len(p) > holdBack {
					safe := p[:len(p)-holdBack]
					if err := writeContent(safe); err != nil {
						loopErr = err
						break
					}
					emitted.WriteString(safe)
					pending.Reset()
					pending.WriteString(p[len(p)-holdBack:])
				}
			}
		}

		// Preserve finish_reason / usage envelopes (carry the stream's end +
		// usage to the client) without the original content.
		if finish != nil || ch.Usage != nil {
			c := newChunk()
			if finish != nil {
				fr := *finish
				// Gemini ends a tool-call turn with "stop"; the agent client needs
				// the OpenAI-conformant "tool_calls" to run the tool.
				if fr == "stop" && sawToolCall {
					fr = "tool_calls"
				}
				c.Choices = []outChoice{{Delta: outDelta{}, FinishReason: &fr}}
			}
			if ch.Usage != nil {
				if ub, mErr := json.Marshal(ch.Usage); mErr == nil {
					c.Usage = ub
				}
			}
			eb, _ := json.Marshal(c)
			if _, err := dst.Write([]byte("data: " + string(eb) + "\n\n")); err != nil {
				loopErr = err
				break
			}
		}
	}

	// Flush any held-back tail (clean responses end here).
	if loopErr == nil && !redacted {
		_ = writeContent(pending.String())
	}
	if loopErr == nil {
		_, _ = dst.Write([]byte("data: [DONE]\n\n"))
	}
	// Meter once, with the final cumulative usage (recording each usage event
	// would double-count — usage arrives cumulatively across chunks).
	if haveUsage && onUsage != nil {
		onUsage(lastUsage)
	}
	_ = dst.CloseWithError(loopErr)
}
