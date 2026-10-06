package client

import (
	"encoding/json"
	"testing"
)

// #2239: the daemon's camelCase `sshHost` must survive the REST mapper so
// `ssh-config sync` can use it.
func TestContainerToIncusInfo_CarriesSSHHost(t *testing.T) {
	var c containerResponse
	body := `{"name":"test","username":"test-7f3a","state":"CONTAINER_STATE_RUNNING","sshHost":"region-a.example.com","network":{"ipAddress":"192.0.2.10"}}`
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		t.Fatal(err)
	}
	info := containerToIncusInfo(&c)
	if info.SSHHost != "region-a.example.com" || info.Username != "test-7f3a" || info.IPAddress != "192.0.2.10" {
		t.Fatalf("unexpected info: %+v", info)
	}
}
