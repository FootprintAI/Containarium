package gateway

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/footprintai/containarium/internal/incus"
)

// CoreServicesHandler handles core infrastructure service queries.
type CoreServicesHandler struct {
	client *incus.Client
}

// NewCoreServicesHandler creates a new handler (connects to Incus directly).
func NewCoreServicesHandler() (*CoreServicesHandler, error) {
	client, err := incus.New()
	if err != nil {
		return nil, err
	}
	return &CoreServicesHandler{client: client}, nil
}

// CoreServiceInfo is the JSON representation of a single core service.
type CoreServiceInfo struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	State     string `json:"state"`
	IPAddress string `json:"ipAddress"`
}

// HandleGetCoreServices handles GET /v1/system/core-services.
func (h *CoreServicesHandler) HandleGetCoreServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	containers, err := h.client.ListContainers()
	if err != nil {
		log.Printf("core-services: failed to list containers: %v", err)
		http.Error(w, `{"error":"failed to list containers"}`, http.StatusInternalServerError)
		return
	}

	var services []CoreServiceInfo
	for _, c := range containers {
		if !c.Role.IsCoreRole() {
			continue
		}
		services = append(services, CoreServiceInfo{
			Name:      c.Name,
			Role:      string(c.Role),
			State:     c.State,
			IPAddress: c.IPAddress,
		})
	}

	// Ensure we return an empty array, not null
	if services == nil {
		services = []CoreServiceInfo{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"services": services,
	})
}
