package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Wire-format regression tests.
//
// These tests decode hand-built JSON fixtures that match the shape
// grpc-gateway actually emits — in particular int64 protobuf scalars
// serialized as JSON strings ("createdAt": "1771122760", not
// "createdAt": 1771122760). Symmetric httptest mocks where we encode
// our own structs as the response would round-trip cleanly under any
// tag scheme; only fixtures that mirror the real wire shape catch
// divergence between client and server.
//
// Background: a missing `,string` tag on Container.CreatedAt and the
// ContainerMetrics int64 fields shipped to main and broke every
// list_containers / get_container / get_metrics call against a real
// deployment. These tests hold the line so it can't happen again.
//
// To refresh a fixture, capture a real response with curl, scrub
// hostnames / IPs / customer container names down to demo values
// (alice/bob), and replace it. Don't check in raw production data.

const fixtureDir = "testdata"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir, name))
	require.NoError(t, err, "read fixture %s", name)
	return data
}

// TestWireFormat_ListContainers is the regression test for the bug
// fixed in PR #116. The fixture has int64 fields encoded as strings
// (the real grpc-gateway shape); without `,string` tags on the client
// struct, this test panics on json.Unmarshal.
func TestWireFormat_ListContainers(t *testing.T) {
	var resp ListContainersResponse
	require.NoError(t, json.Unmarshal(loadFixture(t, "list_containers_response.json"), &resp))

	assert.Equal(t, 3, resp.TotalCount)
	require.Len(t, resp.Containers, 3)

	// alice — running, has a real createdAt timestamp
	alice := resp.Containers[0]
	assert.Equal(t, "alice-container", alice.Name)
	assert.Equal(t, "alice", alice.Username)
	assert.Equal(t, "CONTAINER_STATE_RUNNING", alice.State)
	assert.NotNil(t, alice.Network)
	assert.Equal(t, "10.0.0.10", alice.Network.IPAddress)
	// THE bug-prevention assertion: createdAt must round-trip from
	// string-encoded JSON into a positive int64.
	assert.Equal(t, int64(1771122760), alice.CreatedAt)

	// ws2022 — Windows container with the cosmetic zero-time epoch
	// (-62135596800 = year 0001, what the server emits for
	// time.IsZero()). The decoder must accept it without error even
	// though it's nonsense.
	ws := resp.Containers[2]
	assert.Equal(t, "ws2022", ws.Name)
	assert.Equal(t, "CONTAINER_STATE_STOPPED", ws.State)
	assert.Equal(t, int64(-62135596800), ws.CreatedAt)
}

func TestWireFormat_GetContainer(t *testing.T) {
	var resp GetContainerResponse
	require.NoError(t, json.Unmarshal(loadFixture(t, "get_container_response.json"), &resp))

	assert.Equal(t, "alice-container", resp.Container.Name)
	assert.Equal(t, int64(1771122760), resp.Container.CreatedAt)
	assert.Equal(t, int64(1771209160), resp.Container.UpdatedAt)

	// Embedded metrics must also decode the int64-as-string fields.
	require.NotNil(t, resp.Metrics)
	assert.Equal(t, "alice-container", resp.Metrics.Name)
	assert.Equal(t, int64(1234), resp.Metrics.CPUUsageSeconds)
	assert.Equal(t, int64(536870912), resp.Metrics.MemoryUsageBytes)
	assert.Equal(t, int32(42), resp.Metrics.ProcessCount) // int32 stays numeric
}

func TestWireFormat_GetMetrics(t *testing.T) {
	var resp GetMetricsResponse
	require.NoError(t, json.Unmarshal(loadFixture(t, "get_metrics_response.json"), &resp))

	require.Len(t, resp.Metrics, 2)
	// Spot-check the GPU container's larger numbers — well above 2^32
	// so any accidental int32 truncation would show up as a parse
	// error or negative value.
	bob := resp.Metrics[1]
	assert.Equal(t, "bob-gpu-container", bob.Name)
	assert.Equal(t, int64(34359738368), bob.MemoryUsageBytes) // 32 GiB
	assert.Equal(t, int64(214748364800), bob.DiskUsageBytes)  // 200 GiB
}

func TestWireFormat_GetSystemInfo(t *testing.T) {
	var resp GetSystemInfoResponse
	require.NoError(t, json.Unmarshal(loadFixture(t, "get_system_info_response.json"), &resp))

	assert.Equal(t, "6.23.0", resp.Info.IncusVersion)
	assert.Equal(t, "Ubuntu 24.04.1 LTS", resp.Info.OS)
	// container counts are int (not int64), no string-encoding
	assert.Equal(t, 22, resp.Info.ContainersRunning)
	assert.Equal(t, 24, resp.Info.ContainersTotal)
}

func TestWireFormat_CreateContainer(t *testing.T) {
	var resp CreateContainerResponse
	require.NoError(t, json.Unmarshal(loadFixture(t, "create_container_response.json"), &resp))

	assert.Equal(t, "alice-container", resp.Container.Name)
	assert.Equal(t, "Container created successfully", resp.Message)
	assert.Equal(t, "ssh alice@10.0.0.10", resp.SSHCommand)
	// createdAt must decode even on a freshly-created container
	assert.Equal(t, int64(1771209160), resp.Container.CreatedAt)
}

func TestWireFormat_ListBackends(t *testing.T) {
	var resp ListBackendsResponse
	require.NoError(t, json.Unmarshal(loadFixture(t, "list_backends_response.json"), &resp))

	require.Len(t, resp.Backends, 3)

	// First backend is the local daemon — type "local", healthy, with version.
	local := resp.Backends[0]
	assert.Equal(t, "local", local.Type)
	assert.True(t, local.Healthy)
	assert.Equal(t, "0.16.4", local.Version)
	assert.Equal(t, int32(16), local.ContainerCount)
	// uptimeSeconds is int64, which the proto-first /v1/backends RPC
	// (grpc-gateway protojson, #354) string-encodes ("345600"). flexInt64
	// decodes that string form; EqualValues compares the numeric value
	// regardless of the flexInt64 vs int64 type.
	assert.EqualValues(t, 345600, local.UptimeSeconds)

	// Second backend is a tunnel peer with a GPU. VRAMBytes is likewise an
	// int64 string-encoded by protojson.
	gpuPeer := resp.Backends[1]
	assert.Equal(t, "tunnel", gpuPeer.Type)
	assert.True(t, gpuPeer.Healthy)
	require.Len(t, gpuPeer.GPUs, 1)
	assert.Equal(t, "NVIDIA", gpuPeer.GPUs[0].Vendor)
	assert.Equal(t, "GeForce RTX 3090", gpuPeer.GPUs[0].ModelName)
	assert.EqualValues(t, 25769803776, gpuPeer.GPUs[0].VRAMBytes) // 24 GiB

	// Third backend is unhealthy — health flag must round-trip false
	// (no "omitempty" gotcha eating the field).
	dead := resp.Backends[2]
	assert.False(t, dead.Healthy)
	assert.Equal(t, int32(0), dead.ContainerCount)
}

// TestWireFormat_AddRoute notes a known mismatch and documents it: our
// AddRouteResponse.Route declares fields named Domain / ContainerName,
// but the wire shape from grpc-gateway uses fullDomain / username
// (the proto's actual field names — see ProxyRoute in
// proto/containarium/v1/network.proto). The current handler in
// expose_port falls back to caller-supplied values when these decode
// as empty; this test pins that behavior so a future refactor that
// "fixes" the field names without updating the fallback breaks loudly.
func TestWireFormat_AddRoute(t *testing.T) {
	var resp AddRouteResponse
	require.NoError(t, json.Unmarshal(loadFixture(t, "add_route_response.json"), &resp))

	// These DON'T populate from the wire shape — different field names —
	// so the handler must fall back. Document the gap.
	assert.Empty(t, resp.Route.Domain, "Domain field doesn't exist in proto; fullDomain does. Handler must fall back.")
	assert.Empty(t, resp.Route.ContainerName, "ContainerName field doesn't exist in proto; username does. Handler must fall back.")

	// These DO populate — common ground between client struct and proto.
	assert.Equal(t, "10.0.0.10", resp.Route.ContainerIP)
	assert.Equal(t, int32(8080), resp.Route.Port)
	assert.Equal(t, "route added", resp.Message)
}
