package mcp

// #1214: list_containers printed "Found 0 container(s):" and then listed the
// whole fleet. Cosmetic for a human, who sees the boxes underneath. Not
// cosmetic for an agent: the count is the first token in the response and
// directly contradicts the payload, and an agent that concludes a backend is
// empty — and therefore safe to wipe — is making the "orphan" inference that
// has already deleted a live container here once.
//
// The summary line is now derived from the rendered list, so it cannot
// disagree with it whatever the daemon reports.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noTotalCount tells listServer to omit the totalCount field entirely, the
// way a daemon that never populates it would.
const noTotalCount = -1

// listServer returns a stub daemon emitting n containers, with whatever
// totalCount the caller wants to claim.
func listServer(t *testing.T, n int, claimedTotal int) *httptest.Server {
	t.Helper()
	var boxes []string
	for i := 0; i < n; i++ {
		boxes = append(boxes, fmt.Sprintf(
			`{"name":"box%d","username":"cld-%d","state":"CONTAINER_STATE_RUNNING"}`, i, i))
	}
	total := fmt.Sprintf(`,"totalCount":%d`, claimedTotal)
	if claimedTotal == noTotalCount {
		total = ""
	}
	body := fmt.Sprintf(`{"containers":[%s]%s}`, strings.Join(boxes, ","), total)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// countRendered counts the container entries actually printed.
func countRendered(out string) int {
	return strings.Count(out, "📦 ")
}

// summaryCount extracts N from "Found N container(s):".
func summaryCount(t *testing.T, out string) int {
	t.Helper()
	const prefix = "Found "
	i := strings.Index(out, prefix)
	require.GreaterOrEqual(t, i, 0, "output has no summary line:\n%s", out)
	rest := out[i+len(prefix):]
	j := strings.Index(rest, " ")
	require.Greater(t, j, 0, "malformed summary line")
	n, err := strconv.Atoi(rest[:j])
	require.NoError(t, err, "summary count is not a number: %q", rest[:j])
	return n
}

// The acceptance criterion: summary agrees with body for a NON-EMPTY list.
// The empty case already read correctly (its guard uses len(resp.Containers)),
// which is exactly why the bug survived — the only covered case was the one
// that worked.
//
// The stub omits totalCount rather than setting it correctly. Setting it
// correctly would make this test pass with the bug still in place, since
// both sides would happen to agree — a test that cannot fail, which is the
// same shape of mistake as the bug itself.
func TestListContainers_SummaryAgreesWithBody(t *testing.T) {
	for _, n := range []int{1, 3, 31} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			out, err := handleListContainers(NewClient(listServer(t, n, noTotalCount).URL, "t"), map[string]interface{}{})
			require.NoError(t, err)

			assert.Equal(t, n, summaryCount(t, out), "summary line disagrees with the request")
			assert.Equal(t, n, countRendered(out), "rendered entries disagree with the request")
			assert.Equal(t, countRendered(out), summaryCount(t, out),
				"summary line and body must never disagree — that is what makes this a trap for an agent")
		})
	}
}

// The live shape of the bug: a daemon that reports totalCount=0 while
// returning a full fleet. The MCP server and the daemon are released and
// upgraded separately, so an MCP build will meet daemons that populate the
// field and daemons that don't; the summary must be right against both.
func TestListContainers_CountIgnoresAWrongTotalCount(t *testing.T) {
	out, err := handleListContainers(NewClient(listServer(t, 31, 0).URL, "t"), map[string]interface{}{})
	require.NoError(t, err)

	assert.NotContains(t, out, "Found 0 container(s)",
		"reported 0 while listing a full fleet — an agent reading this can conclude the backend is empty (#1214)")
	assert.Equal(t, 31, summaryCount(t, out))
	assert.Equal(t, 31, countRendered(out))
}

// A daemon over-reporting is the same defect in the other direction: the
// summary must still describe what was rendered.
func TestListContainers_CountIgnoresAnInflatedTotalCount(t *testing.T) {
	out, err := handleListContainers(NewClient(listServer(t, 2, 900).URL, "t"), map[string]interface{}{})
	require.NoError(t, err)

	assert.Equal(t, 2, summaryCount(t, out), "summary must count what it printed, not what the daemon claimed")
	assert.NotContains(t, out, "900")
}

// The empty case must keep its distinct message rather than falling into
// "Found 0 container(s):" with nothing after it.
func TestListContainers_EmptyStaysDistinct(t *testing.T) {
	out, err := handleListContainers(NewClient(listServer(t, 0, 0).URL, "t"), map[string]interface{}{})
	require.NoError(t, err)
	assert.Equal(t, "No containers found.", out)
}
