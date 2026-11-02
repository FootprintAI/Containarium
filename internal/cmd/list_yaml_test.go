package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
	"gopkg.in/yaml.v3"
)

// hostile holds the values a tenant can set that the terminal would act on.
var hostileLabelValues = []string{
	"evil\x1b[2J\x1b[Hgone",
	"line1\r\nline2",
	"cr\ronly",
	"lf\nonly",
	"nul\x00byte",
	"del\x7fbyte",
	"c1\u009bbyte",
	"sep here",
}

func hasRawControl(b []byte) (byte, bool) {
	for _, c := range b {
		if c == '\n' {
			continue // the emitter's own line breaks
		}
		if c < 0x20 || c == 0x7f {
			return c, true
		}
	}
	return 0, false
}

type yamlList struct {
	Containers []struct {
		Name   string            `yaml:"name"`
		Labels map[string]string `yaml:"labels"`
	} `yaml:"containers"`
	TotalCount int `yaml:"total_count"`
}

func TestListYAMLLabelsLossless(t *testing.T) {
	for _, v := range hostileLabelValues {
		c := incus.ContainerInfo{Name: "alice-container", State: "Running", Labels: map[string]string{"team": v, v: "x"}}
		var buf bytes.Buffer
		writeYAMLFormat(&buf, []incus.ContainerInfo{c})
		out := buf.Bytes()

		if b, bad := hasRawControl(out); bad {
			t.Errorf("%q: raw control byte 0x%02x in output:\n%q", v, b, out)
		}
		if bytes.ContainsAny(out, "\r  ") || bytes.Contains(out, []byte("\xc2\x9b")) {
			t.Errorf("%q: raw CR/C1/separator in output: %q", v, out)
		}
		var got yamlList
		if err := yaml.Unmarshal(out, &got); err != nil {
			t.Fatalf("%q: output does not parse: %v\n%q", v, err, out)
		}
		if len(got.Containers) != 1 || got.Containers[0].Labels["team"] != v || got.Containers[0].Labels[v] != "x" {
			t.Errorf("%q: round trip lost data: %+v", v, got.Containers)
		}
	}
}

func TestListYAMLHostileNameAndGroup(t *testing.T) {
	name := "bad\x1b[31mname\r\n"
	key := "e\x1b[1mnv"
	c := incus.ContainerInfo{Name: name, State: "Run\x1bning", IPAddress: "10.0.0.1\r", CPU: "2\n", Memory: "4\x1bGB", Labels: map[string]string{key: "p\x1b[0m\nq"}}

	var buf bytes.Buffer
	writeYAMLFormat(&buf, []incus.ContainerInfo{c})
	if b, bad := hasRawControl(buf.Bytes()); bad {
		t.Errorf("flat: raw 0x%02x in %q", b, buf.Bytes())
	}
	var flat yamlList
	if err := yaml.Unmarshal(buf.Bytes(), &flat); err != nil || flat.Containers[0].Name != name {
		t.Errorf("flat name round trip: err=%v got=%+v", err, flat)
	}

	buf.Reset()
	writeGroupedYAMLFormat(&buf, []incus.ContainerInfo{c}, key)
	if b, bad := hasRawControl(buf.Bytes()); bad {
		t.Errorf("grouped: raw 0x%02x in %q", b, buf.Bytes())
	}
	var grouped struct {
		GroupBy string `yaml:"group_by"`
		Groups  map[string][]struct {
			Name   string            `yaml:"name"`
			State  string            `yaml:"state"`
			IP     string            `yaml:"ip_address"`
			CPU    string            `yaml:"cpu"`
			Memory string            `yaml:"memory"`
			Labels map[string]string `yaml:"labels"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(buf.Bytes(), &grouped); err != nil {
		t.Fatalf("grouped does not parse: %v\n%q", err, buf.Bytes())
	}
	g := grouped.Groups["p\x1b[0m\nq"]
	if grouped.GroupBy != key || len(g) != 1 || g[0].Name != name || g[0].State != c.State ||
		g[0].IP != c.IPAddress || g[0].CPU != c.CPU || g[0].Memory != c.Memory {
		t.Errorf("grouped round trip: %+v", grouped.Groups)
	}
}

// Ordinary values must print exactly as before.
func TestListYAMLOrdinaryOutputUnchanged(t *testing.T) {
	c := incus.ContainerInfo{Name: "alice-container", State: "Running", IPAddress: "10.0.0.5", CPU: "2", Memory: "4GB", Labels: map[string]string{"env": "prod"}}
	var buf bytes.Buffer
	writeYAMLFormat(&buf, []incus.ContainerInfo{c})
	want := "containers:\n  - name: alice-container\n    state: Running\n    ip_address: 10.0.0.5\n    monitoring_enabled: false\n    cpu: 2\n    memory: 4GB\n    labels:\n      env: prod\ntotal_count: 1\n"
	if buf.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
}

// JSON already escapes control bytes; pin it.
func TestListJSONEscapesControlBytes(t *testing.T) {
	b, _ := json.MarshalIndent(listJSON{Containers: []incus.ContainerInfo{{Name: "a", Labels: map[string]string{"k": "x\x1b\r\n"}}}, TotalCount: 1}, "", "  ")
	if _, bad := hasRawControl(b); bad {
		t.Errorf("raw control byte in JSON: %q", b)
	}
}
