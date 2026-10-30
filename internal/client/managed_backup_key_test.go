package client

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// #3213: the HTTP client reads managed_backup_key_configured from the
// camelCase JSON grpc-gateway emits for SystemInfo; absent (an older daemon)
// reads as false.
func TestHTTPManagedBackupKeyConfigured(t *testing.T) {
	for name, tc := range map[string]struct {
		info *pb.SystemInfo
		want bool
	}{
		"managed key": {&pb.SystemInfo{Hostname: "h", ManagedBackupKeyConfigured: true}, true},
		"no key":      {&pb.SystemInfo{Hostname: "h"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			// A real gateway response also carries quoted memory int64s.
			tc.info.TotalMemoryBytes = 32 << 30
			tc.info.AvailableMemoryBytes = 16 << 30
			body, err := protojson.Marshal(&pb.GetSystemInfoResponse{Info: tc.info})
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
			}))
			defer srv.Close()
			c, err := NewHTTPClient(srv.URL, "tok")
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.ManagedBackupKeyConfigured()
			if err != nil || got != tc.want {
				t.Errorf("got (%v, %v), want (%v, nil)", got, err, tc.want)
			}
		})
	}
}

// gatewayBody marshals resp the way grpc-gateway does and asserts the body
// really carries quoted int64s, so a fixture that degrades to all-zero
// (omitted) int64 fields fails loudly instead of silently passing (#3312).
func gatewayBody(t *testing.T, resp *pb.GetSystemInfoResponse) []byte {
	t.Helper()
	body, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"totalMemoryBytes":"`, `"availableMemoryBytes":"`} {
		if !regexp.MustCompile(regexp.QuoteMeta(want) + `\d+"`).Match(body) {
			t.Fatalf("fixture lost its quoted int64 %s in %s", want, body)
		}
	}
	return body
}

func gatewayServer(t *testing.T, body []byte) *HTTPClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// #3312: the gateway emits int64 as quoted strings; the key-detection path
// must decode such a body. TestHTTPManagedBackupKeyConfigured's body had
// every int64 at zero (omitted), so it passed on the #3250 bug.
func TestHTTPManagedBackupKeyConfiguredGatewayShapedInt64(t *testing.T) {
	for name, want := range map[string]bool{"managed key": true, "no key": false} {
		t.Run(name, func(t *testing.T) {
			body := gatewayBody(t, &pb.GetSystemInfoResponse{Info: &pb.SystemInfo{
				Hostname:                   "h",
				TotalMemoryBytes:           17179869184,
				AvailableMemoryBytes:       8589934592,
				TotalDiskBytes:             500107862016,
				AvailableDiskBytes:         250053931008,
				UptimeSeconds:              86400,
				ManagedBackupKeyConfigured: want,
			}})
			got, err := gatewayServer(t, body).ManagedBackupKeyConfigured()
			if err != nil || got != want {
				t.Errorf("got (%v, %v), want (%v, nil)", got, err, want)
			}
		})
	}
}

// fillNonZero sets every field of m to a non-zero value via protoreflect,
// recursing into messages, lists and maps, so a field added to the proto
// later is covered without touching this test.
func fillNonZero(m protoreflect.Message, depth int) {
	fds := m.Descriptor().Fields()
	for i := 0; i < fds.Len(); i++ {
		fd := fds.Get(i)
		if oo := fd.ContainingOneof(); oo != nil && m.WhichOneof(oo) != nil {
			continue
		}
		switch {
		case fd.IsList():
			l := m.Mutable(fd).List()
			if fd.Message() != nil {
				if depth == 0 {
					continue
				}
				e := l.NewElement()
				fillNonZero(e.Message(), depth-1)
				l.Append(e)
			} else {
				l.Append(scalarNonZero(fd))
			}
		case fd.IsMap():
			mp := m.Mutable(fd).Map()
			var v protoreflect.Value
			if fd.MapValue().Message() != nil {
				if depth == 0 {
					continue
				}
				v = mp.NewValue()
				fillNonZero(v.Message(), depth-1)
			} else {
				v = scalarNonZero(fd.MapValue())
			}
			mp.Set(scalarNonZero(fd.MapKey()).MapKey(), v)
		case fd.Message() != nil:
			if depth == 0 {
				continue
			}
			sub := m.NewField(fd)
			fillNonZero(sub.Message(), depth-1)
			m.Set(fd, sub)
		default:
			m.Set(fd, scalarNonZero(fd))
		}
	}
}

func scalarNonZero(fd protoreflect.FieldDescriptor) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(true)
	case protoreflect.EnumKind:
		vals := fd.Enum().Values()
		v := vals.Get(0)
		if vals.Len() > 1 {
			v = vals.Get(1)
		}
		return protoreflect.ValueOfEnum(v.Number())
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(7)
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(4294967297) // > 2^32; within Timestamp/Duration range; gateway quotes it
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(7)
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(4294967297)
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(1.5)
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(2.5)
	case protoreflect.StringKind:
		return protoreflect.ValueOfString("x")
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes([]byte("x"))
	}
	panic("unsupported kind " + fd.Kind().String())
}

// #3312 drift guard: every pb.SystemInfo field populated non-zero, rendered
// by protojson (gateway shape), must decode through GetSystemInfo. A new
// int64/enum field without a matching tag on the hand-written systemInfo
// struct fails here until #3292 replaces the struct with pb.SystemInfo.
func TestGetSystemInfoDecodesEveryPopulatedSystemInfoField(t *testing.T) {
	info := &pb.SystemInfo{}
	fillNonZero(info.ProtoReflect(), 3)
	if !info.ProtoReflect().Has(info.ProtoReflect().Descriptor().Fields().ByName("total_memory_bytes")) {
		t.Fatal("fixture not populated")
	}
	body := gatewayBody(t, &pb.GetSystemInfoResponse{Info: info})
	if _, err := gatewayServer(t, body).GetSystemInfo(); err != nil {
		t.Fatalf("GetSystemInfo failed to decode a fully-populated gateway body: %v\nbody: %s", err, body)
	}
}
