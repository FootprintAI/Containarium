package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
)

// registerAuditEndpoint registers the audit logs query endpoint on the HTTP mux.
func registerAuditEndpoint(mux *http.ServeMux, store *audit.Store, authMW *auth.AuthMiddleware) {
	mux.HandleFunc("/v1/audit/logs", func(w http.ResponseWriter, r *http.Request) {
		// Validate auth token from query param or Authorization header
		token := r.URL.Query().Get("token")
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}
		if token == "" {
			http.Error(w, `{"error": "unauthorized: token required", "code": 401}`, http.StatusUnauthorized)
			return
		}
		if _, err := authMW.ValidateToken(token); err != nil {
			http.Error(w, `{"error": "unauthorized: invalid token", "code": 401}`, http.StatusUnauthorized)
			return
		}

		handleAuditQuery(w, r, store)
	})
}

// auditLogJSON is the JSON representation of a single audit log entry.
type auditLogJSON struct {
	ID           int64  `json:"id"`
	Timestamp    string `json:"timestamp"`
	Username     string `json:"username"`
	Action       string `json:"action"`
	ResourceType string `json:"resourceType"`
	ResourceID   string `json:"resourceId"`
	Detail       string `json:"detail"`
	SourceIP     string `json:"sourceIp"`
	StatusCode   int    `json:"statusCode"`
}

// auditLogsResponse is the JSON response for the audit logs endpoint.
type auditLogsResponse struct {
	Logs       []auditLogJSON `json:"logs"`
	TotalCount int32          `json:"totalCount"`
}

func handleAuditQuery(w http.ResponseWriter, r *http.Request, store *audit.Store) {
	q := r.URL.Query()

	params := audit.QueryParams{
		Username:     q.Get("username"),
		Action:       q.Get("action"),
		ResourceType: q.Get("resource_type"),
	}

	if fromStr := q.Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error": "invalid from date: %s"}`, err.Error()), http.StatusBadRequest)
			return
		}
		params.From = t
	}

	if toStr := q.Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error": "invalid to date: %s"}`, err.Error()), http.StatusBadRequest)
			return
		}
		params.To = t
	}

	if limitStr := q.Get("limit"); limitStr != "" {
		n, err := strconv.Atoi(limitStr)
		if err == nil {
			params.Limit = n
		}
	}
	if params.Limit <= 0 {
		params.Limit = 50
	}

	if offsetStr := q.Get("offset"); offsetStr != "" {
		n, err := strconv.Atoi(offsetStr)
		if err == nil {
			params.Offset = n
		}
	}

	entries, totalCount, err := store.Query(r.Context(), params)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "failed to query audit logs: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	logs := make([]auditLogJSON, 0, len(entries))
	for _, e := range entries {
		logs = append(logs, auditLogJSON{
			ID:           e.ID,
			Timestamp:    e.Timestamp.Format(time.RFC3339),
			Username:     e.Username,
			Action:       e.Action,
			ResourceType: e.ResourceType,
			ResourceID:   e.ResourceID,
			Detail:       e.Detail,
			SourceIP:     e.SourceIP,
			StatusCode:   e.StatusCode,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(auditLogsResponse{
		Logs:       logs,
		TotalCount: totalCount,
	})
}
