package gateway

import (
	"encoding/csv"
	"fmt"
	"log"
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
		token := ""
		if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
		if token == "" {
			// Deprecated: a token in the URL leaks through access logs,
			// Referer headers and browser history. Prefer the header.
			if token = r.URL.Query().Get("token"); token != "" {
				log.Printf("WARNING: clamav export client used deprecated ?token= (remote=%s) — use the Authorization header", r.RemoteAddr)
			}
		}
		if token == "" {
			http.Error(w, `{"error": "unauthorized: token required", "code": 401}`, http.StatusUnauthorized)
			return
		}
		claims, err := authMW.ValidateToken(token)
		if err != nil {
			http.Error(w, `{"error": "unauthorized: invalid token", "code": 401}`, http.StatusUnauthorized)
			return
		}
		// Mirror SecurityServer.ListClamavReports: a valid token is not enough.
		containerName := strings.TrimSpace(r.URL.Query().Get("container_name"))
		if status, msg := authorizeClamavExport(claims, containerName); status != 0 {
			http.Error(w, fmt.Sprintf(`{"error": "forbidden: %s", "code": %d}`, msg, status), status)
			return
		}

		handleClamavExport(w, r, store, containerName)
	})
}

func handleClamavExport(w http.ResponseWriter, r *http.Request, store *security.Store, containerName string) {
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
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
	_ = writer.Write([]string{"Container", "Username", "Status", "Findings Count", "Findings", "Scanned At", "Scan Duration"})

	// Data rows
	for _, report := range reports {
		_ = writer.Write([]string{
			csvSafe(report.ContainerName),
			csvSafe(report.Username),
			csvSafe(report.Status),
			strconv.Itoa(int(report.FindingsCount)),
			csvSafe(report.Findings),
			csvSafe(report.ScannedAt),
			csvSafe(report.ScanDuration),
		})
	}
}

// authorizeClamavExport applies the same rules as the gRPC ListClamavReports:
// scoped tokens need security:read; an export spanning every container
// (no container_name) is admin-only; otherwise the caller must own the named
// container (admins always pass). It returns (0, "") when allowed.
func authorizeClamavExport(claims *auth.Claims, containerName string) (int, string) {
	if claims == nil {
		return http.StatusUnauthorized, "no authenticated subject"
	}
	// Same decision as RequireScope: an unscoped token is refused when
	// strict-scopes mode is on, otherwise it is unrestricted.
	if claims.Scopes == nil && auth.StrictScopesEnabled() {
		return http.StatusForbidden, "scope required: " + auth.ScopeSecurityRead
	}
	if claims.Scopes != nil && !auth.HasScope(claims.Scopes, auth.ScopeSecurityRead) {
		return http.StatusForbidden, "scope required: " + auth.ScopeSecurityRead
	}
	if auth.HasRole(claims.Roles, auth.RoleAdmin) {
		return 0, ""
	}
	if containerName == "" {
		return http.StatusForbidden, "container_name is required for non-admin callers"
	}
	owner, ok := auth.OwnerFromContainerName(containerName)
	if !ok || owner != claims.Username {
		return http.StatusForbidden, "not authorized for this container"
	}
	return 0, ""
}

// csvSafe neutralizes spreadsheet formula injection: a cell that starts with
// =, +, -, @, tab or CR is prefixed with a single quote.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}
