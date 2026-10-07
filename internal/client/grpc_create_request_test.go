package client

import "testing"

// The gRPC create request carries --labels (#2358).
func TestNewCreateContainerRequest_Labels(t *testing.T) {
	labels := map[string]string{"cloud_org_id": "org-a"}
	req := newCreateContainerRequest("alice", "img", "1", "1GB", "10GB", nil, false, "", nil, 0, 0, false, "", "", GitSourceOpts{}, 0, 0, 0, "", EncryptionOpts{}, "", "", "", labels)
	if req.Username != "alice" || req.Labels["cloud_org_id"] != "org-a" {
		t.Errorf("request = %+v", req)
	}
	if req := newCreateContainerRequest("alice", "img", "1", "1GB", "10GB", nil, false, "", nil, 0, 0, false, "", "", GitSourceOpts{}, 0, 0, 0, "", EncryptionOpts{}, "", "", "", nil); len(req.Labels) != 0 {
		t.Errorf("nil labels must stay empty, got %v", req.Labels)
	}
}
