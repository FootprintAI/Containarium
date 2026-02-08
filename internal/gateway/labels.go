package gateway

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/footprintai/containarium/internal/container"
)

// LabelHandler handles label operations
type LabelHandler struct {
	manager *container.Manager
}

// NewLabelHandler creates a new label handler
func NewLabelHandler() (*LabelHandler, error) {
	mgr, err := container.New()
	if err != nil {
		return nil, err
	}
	return &LabelHandler{manager: mgr}, nil
}

// SetLabelsRequest is the request body for setting labels
type SetLabelsRequest struct {
	Labels map[string]string `json:"labels"`
}

// LabelResponse is the response for label operations
type LabelResponse struct {
	Container string            `json:"container"`
	Labels    map[string]string `json:"labels"`
	Message   string            `json:"message,omitempty"`
}

// HandleSetLabels handles PUT /v1/containers/{username}/labels
func (h *LabelHandler) HandleSetLabels(w http.ResponseWriter, r *http.Request) {
	// Extract username from path: /v1/containers/{username}/labels
	path := strings.TrimPrefix(r.URL.Path, "/v1/containers/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "labels" {
		http.Error(w, `{"error":"invalid path"}`, http.StatusBadRequest)
		return
	}
	username := parts[0]
	containerName := username + "-container"

	// Check if container exists
	if !h.manager.ContainerExists(containerName) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "container not found"})
		return
	}

	// Parse request body
	var req SetLabelsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}

	// Set labels (Manager expects username, not containerName)
	for key, value := range req.Labels {
		if err := h.manager.AddLabel(username, key, value); err != nil {
			log.Printf("Failed to set label %s=%s on %s: %v", key, value, containerName, err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "failed to set label: " + err.Error()})
			return
		}
	}

	// Get updated labels (Manager expects username, not containerName)
	labels, _ := h.manager.GetLabels(username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LabelResponse{
		Container: containerName,
		Labels:    labels,
		Message:   "labels updated",
	})
}

// HandleRemoveLabel handles DELETE /v1/containers/{username}/labels/{key}
func (h *LabelHandler) HandleRemoveLabel(w http.ResponseWriter, r *http.Request) {
	// Extract username and key from path: /v1/containers/{username}/labels/{key}
	path := strings.TrimPrefix(r.URL.Path, "/v1/containers/")
	parts := strings.Split(path, "/")
	if len(parts) < 3 || parts[1] != "labels" {
		http.Error(w, `{"error":"invalid path"}`, http.StatusBadRequest)
		return
	}
	username := parts[0]
	labelKey := parts[2]
	containerName := username + "-container"

	// Check if container exists
	if !h.manager.ContainerExists(containerName) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "container not found"})
		return
	}

	// Remove label (Manager expects username, not containerName)
	if err := h.manager.RemoveLabel(username, labelKey); err != nil {
		log.Printf("Failed to remove label %s from %s: %v", labelKey, containerName, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to remove label: " + err.Error()})
		return
	}

	// Get updated labels (Manager expects username, not containerName)
	labels, _ := h.manager.GetLabels(username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LabelResponse{
		Container: containerName,
		Labels:    labels,
		Message:   "label removed",
	})
}

// HandleGetLabels handles GET /v1/containers/{username}/labels
func (h *LabelHandler) HandleGetLabels(w http.ResponseWriter, r *http.Request) {
	// Extract username from path: /v1/containers/{username}/labels
	path := strings.TrimPrefix(r.URL.Path, "/v1/containers/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "labels" {
		http.Error(w, `{"error":"invalid path"}`, http.StatusBadRequest)
		return
	}
	username := parts[0]
	containerName := username + "-container"

	// Check if container exists
	if !h.manager.ContainerExists(containerName) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "container not found"})
		return
	}

	// Get labels (Manager expects username, not containerName)
	labels, err := h.manager.GetLabels(username)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to get labels: " + err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LabelResponse{
		Container: containerName,
		Labels:    labels,
	})
}
