package gateway

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/security"
)

// registerSecurityExport registers the CSV export endpoint on the HTTP mux
func registerSecurityExport(mux *http.ServeMux, store *security.Store, authMW *auth.AuthMiddleware) {
	mux.HandleFunc("/v1/security/clamav-reports/export", func(w http.ResponseWriter, r *http.Request) {
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

		handleClamavExport(w, r, store)
	})
}

func handleClamavExport(w http.ResponseWriter, r *http.Request, store *security.Store) {
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
	containerName := r.URL.Query().Get("container_name")
	status := r.URL.Query().Get("status")

	if from == "" || to == "" {
		http.Error(w, `{"error": "from and to date parameters are required (ISO 8601 format)"}`, http.StatusBadRequest)
		return
	}

	reports, err := store.ListReportsForExport(r.Context(), from, to, containerName, status)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "failed to query reports: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("clamav-report-%s-to-%s.csv", from, to)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))

	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Header
	writer.Write([]string{"Container", "Username", "Status", "Findings Count", "Findings", "Scanned At", "Scan Duration"})

	// Data rows
	for _, report := range reports {
		writer.Write([]string{
			report.ContainerName,
			report.Username,
			report.Status,
			strconv.Itoa(int(report.FindingsCount)),
			report.Findings,
			report.ScannedAt,
			report.ScanDuration,
		})
	}
}
