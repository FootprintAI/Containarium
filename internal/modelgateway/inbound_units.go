package modelgateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strconv"
	"strings"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Scan units for the inbound guardrail: what a model response would write
// into a box. A coding CLI acts on assistant text and, above all, on tool
// calls (edit, write, shell), so the units are every text part and every
// tool call's name plus its argument string, reassembled across streamed
// chunks (docs/architecture/guardrail-inbound-and-server-policy.md, "What
// gets scanned"). Three wire shapes are recognised: OpenAI chat completions
// (and every OpenAI-shaped upstream), Anthropic messages, and Gemini's
// native generateContent. A body in none of these shapes is scanned whole,
// as one unit, so an unrecognised shape is never an unscanned one.

// unitBuilder accumulates text per unit key in first-seen order.
type unitBuilder struct {
	order []string
	parts map[string]*strings.Builder
	names map[string]string // tool-call name per tool unit key
}

func newUnitBuilder() *unitBuilder {
	return &unitBuilder{parts: map[string]*strings.Builder{}, names: map[string]string{}}
}

func (b *unitBuilder) add(key, s string) {
	sb, ok := b.parts[key]
	if !ok {
		sb = &strings.Builder{}
		b.parts[key] = sb
		b.order = append(b.order, key)
	}
	sb.WriteString(s)
}

func (b *unitBuilder) name(key, name string) {
	if name != "" {
		b.names[key] = name
		b.add(key, "") // register the unit even before any arguments arrive
	}
}

// units renders the accumulated parts. With nothing recognised it returns the
// whole raw body as one unit, keyed fallbackID.
func (b *unitBuilder) units(fallbackID string, raw []byte) []*pb.GuardrailTextUnit {
	if len(b.order) == 0 {
		return []*pb.GuardrailTextUnit{{UnitId: fallbackID, Text: string(raw)}}
	}
	out := make([]*pb.GuardrailTextUnit, 0, len(b.order))
	for _, k := range b.order {
		text := b.parts[k].String()
		if n, ok := b.names[k]; ok {
			text = n + "\n" + text
		}
		out = append(out, &pb.GuardrailTextUnit{UnitId: k, Text: text})
	}
	return out
}

// --- OpenAI chat completions (non-streaming message, streaming delta) ---

type oaiToolCall struct {
	Index    *int `json:"index"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type oaiMessage struct {
	Content   json.RawMessage `json:"content"` // string, or an array of {text} parts
	ToolCalls []oaiToolCall   `json:"tool_calls"`
}

type oaiBody struct {
	Choices []struct {
		Index   int        `json:"index"`
		Message oaiMessage `json:"message"`
		Delta   oaiMessage `json:"delta"`
	} `json:"choices"`
}

// textOf reads a content field that is either a JSON string or an array of
// parts with a text field.
func textOf(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(p.Text)
	}
	return b.String()
}

func (b *unitBuilder) addOpenAI(raw []byte) bool {
	var body oaiBody
	if json.Unmarshal(raw, &body) != nil || len(body.Choices) == 0 {
		return false
	}
	for _, c := range body.Choices {
		ci := strconv.Itoa(c.Index)
		for _, m := range []oaiMessage{c.Message, c.Delta} {
			if t := textOf(m.Content); t != "" {
				b.add("text/"+ci, t)
			}
			for pos, tc := range m.ToolCalls {
				ti := pos
				if tc.Index != nil {
					ti = *tc.Index
				}
				key := "tool/" + ci + "/" + strconv.Itoa(ti)
				b.name(key, tc.Function.Name)
				b.add(key, tc.Function.Arguments)
			}
		}
	}
	return true
}

// --- Anthropic messages (non-streaming message, streaming content_block events) ---

type anthropicBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

type anthropicBody struct {
	Type         string           `json:"type"`
	Index        int              `json:"index"`
	Content      []anthropicBlock `json:"content"`
	ContentBlock *anthropicBlock  `json:"content_block"`
	Delta        *struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		PartialJSON string `json:"partial_json"`
	} `json:"delta"`
}

func (b *unitBuilder) addAnthropicBlock(i int, blk anthropicBlock, streaming bool) {
	key := "text/" + strconv.Itoa(i)
	switch blk.Type {
	case "text":
		b.add(key, blk.Text)
	case "tool_use":
		key = "tool/" + strconv.Itoa(i)
		b.name(key, blk.Name)
		// A streamed tool_use starts with an empty input; the arguments
		// arrive as input_json_delta. Non-streaming carries them inline.
		if !streaming && len(blk.Input) > 0 {
			b.add(key, string(blk.Input))
		}
	}
}

func (b *unitBuilder) addAnthropic(raw []byte) bool {
	var body anthropicBody
	if json.Unmarshal(raw, &body) != nil {
		return false
	}
	switch body.Type {
	case "message":
		for i, blk := range body.Content {
			b.addAnthropicBlock(i, blk, false)
		}
		return len(body.Content) > 0
	case "content_block_start":
		if body.ContentBlock == nil {
			return false
		}
		b.addAnthropicBlock(body.Index, *body.ContentBlock, true)
		return true
	case "content_block_delta":
		if body.Delta == nil {
			return false
		}
		switch body.Delta.Type {
		case "text_delta":
			b.add("text/"+strconv.Itoa(body.Index), body.Delta.Text)
		case "input_json_delta":
			b.add("tool/"+strconv.Itoa(body.Index), body.Delta.PartialJSON)
		default:
			return false
		}
		return true
	}
	return false
}

// --- Gemini native generateContent (same shape streamed and not) ---

type geminiBody struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text         string `json:"text"`
				FunctionCall *struct {
					Name string          `json:"name"`
					Args json.RawMessage `json:"args"`
				} `json:"functionCall"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

func (b *unitBuilder) addGemini(raw []byte) bool {
	var body geminiBody
	if json.Unmarshal(raw, &body) != nil || len(body.Candidates) == 0 {
		return false
	}
	for ci, c := range body.Candidates {
		for pi, p := range c.Content.Parts {
			if p.Text != "" {
				b.add("text/"+strconv.Itoa(ci), p.Text)
			}
			if p.FunctionCall != nil {
				key := "tool/" + strconv.Itoa(ci) + "/" + strconv.Itoa(pi)
				b.name(key, p.FunctionCall.Name)
				b.add(key, string(p.FunctionCall.Args))
			}
		}
	}
	return true
}

// addJSON feeds one JSON document (a whole body or one SSE data payload).
func (b *unitBuilder) addJSON(raw []byte) bool {
	return b.addOpenAI(raw) || b.addAnthropic(raw) || b.addGemini(raw)
}

// inboundUnitsJSON is the scan input for a non-streaming body.
func inboundUnitsJSON(body []byte) []*pb.GuardrailTextUnit {
	b := newUnitBuilder()
	b.addJSON(body)
	return b.units("body", body)
}

// inboundUnitsSSE is the scan input for a held event stream: every data
// payload is fed through the same decoders, so arguments split across chunks
// are reassembled before anything is scanned.
func inboundUnitsSSE(held []byte) []*pb.GuardrailTextUnit {
	b := newUnitBuilder()
	sc := bufio.NewScanner(bytes.NewReader(held))
	sc.Buffer(make([]byte, 0, 64*1024), len(held)+1)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		payload, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		payload = strings.TrimSpace(payload)
		if payload == "" || payload == "[DONE]" {
			continue
		}
		b.addJSON([]byte(payload))
	}
	return b.units("stream", held)
}

// usageFromSSE returns the final usage block of a held event stream, the
// same cumulative-last-value rule filterSSEStream applies. ok is false when
// the stream carries none.
func usageFromSSE(held []byte, parse func(map[string]any) Usage) (u Usage, ok bool) {
	sc := bufio.NewScanner(bytes.NewReader(held))
	sc.Buffer(make([]byte, 0, 64*1024), len(held)+1)
	for sc.Scan() {
		payload, found := strings.CutPrefix(strings.TrimSpace(sc.Text()), "data:")
		if !found {
			continue
		}
		var ch sseChunk
		if json.Unmarshal([]byte(strings.TrimSpace(payload)), &ch) != nil || ch.Usage == nil {
			continue
		}
		u, ok = parse(map[string]any{"usage": ch.Usage}), true
	}
	return u, ok
}
