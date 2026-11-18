package incus

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/limitio"
	incusclient "github.com/lxc/incus/v7/client"
)

// #3684: the console log is written by whatever runs in the box, so it is
// read through the shared capped reader like exec output and file reads.

// fakeConsoleLogServer answers GetInstanceConsoleLog with n bytes.
type fakeConsoleLogServer struct {
	incusclient.InstanceServer
	n int64
}

func (f *fakeConsoleLogServer) GetInstanceConsoleLog(string, *incusclient.InstanceConsoleLogArgs) (io.ReadCloser, error) {
	return io.NopCloser(repeatReader('c', f.n)), nil
}

func TestGetConsoleLog_ExactCapIsNotTooLarge(t *testing.T) {
	c := &Client{server: &fakeConsoleLogServer{n: limitio.MaxConsoleLogBytes}}
	got, err := c.GetConsoleLog("box")
	if err != nil {
		t.Fatalf("GetConsoleLog at exactly the cap: %v", err)
	}
	if int64(len(got)) != limitio.MaxConsoleLogBytes {
		t.Fatalf("len = %d, want %d", len(got), limitio.MaxConsoleLogBytes)
	}
}

func TestGetConsoleLog_OverCapIsAnError(t *testing.T) {
	c := &Client{server: &fakeConsoleLogServer{n: limitio.MaxConsoleLogBytes + 1}}
	_, err := c.GetConsoleLog("box")
	if !errors.Is(err, limitio.ErrTooLarge) {
		t.Fatalf("err = %v, want limitio.ErrTooLarge", err)
	}
	if !strings.Contains(err.Error(), "console log") {
		t.Fatalf("err = %v, want it to name the console log read", err)
	}
}
