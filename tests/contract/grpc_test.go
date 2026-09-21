package contract

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	wardenv1 "github.com/go-freya/freya/services/warden/api/proto/warden/v1"
	"github.com/go-freya/freya/services/warden/pkg/wardenmanifest"
)

// TestGRPCSurface proves the generated service matches contracts/warden.v1.proto
// and every manifest method exists (and vice versa).
func TestGRPCSurface(t *testing.T) {
	svc := wardenv1.File_warden_v1_warden_proto.Services().ByName("Secrets")
	if svc == nil {
		t.Fatal("service Secrets missing")
	}
	want := map[string]bool{"Get": true, "GetPassword": true, "Check": true}
	for i := 0; i < svc.Methods().Len(); i++ {
		m := svc.Methods().Get(i)
		if !want[string(m.Name())] {
			t.Errorf("unexpected method %s", m.Name())
		}
		delete(want, string(m.Name()))
		if m.IsStreamingClient() || m.IsStreamingServer() {
			t.Errorf("%s streams", m.Name())
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing methods %v", want)
	}
	for _, mm := range wardenmanifest.Methods {
		name := protoreflect.Name(mm.FullMethod[len("/warden.v1.Secrets/"):])
		if svc.Methods().ByName(name) == nil {
			t.Errorf("manifest method %s not in the proto", mm.FullMethod)
		}
	}
	// Response shapes: material only in GetPassword.
	msgs := wardenv1.File_warden_v1_warden_proto.Messages()
	if msgs.ByName("GetResponse").Fields().ByName("password") != nil {
		t.Error("GetResponse carries a password field")
	}
	if msgs.ByName("GetPasswordResponse").Fields().ByName("password") == nil {
		t.Error("GetPasswordResponse lacks the password field")
	}
}
