package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// grpc-gateway status codes this package special-cases. Kept as named
// constants (not bare literals at each call site) per the strong-typing
// convention — these are google.rpc.Code values, not arbitrary numbers.
const (
	grpcCodeInvalidArgument  = 3
	grpcCodePermissionDenied = 7
	grpcCodeUnauthenticated  = 16
)

// cloudAPIError is a decoded grpc-gateway JSON error body
// ({"code":N,"message":"...","details":[]}) from a hosted-control-plane-only
// endpoint. A typed error (not a flattened string) so a caller that needs to
// special-case a specific code — org set-default-region enriching an
// InvalidArgument with the valid region list (#1607 acceptance 4) — can
// errors.As it instead of string-matching the message.
type cloudAPIError struct {
	Status  int
	Code    int
	Message string
}

func (e *cloudAPIError) Error() string {
	// #1607 acceptance 3: a caller without permission sees a permission
	// error, not the server's generic message alone — the message is written
	// for an operator reading a log, not someone staring at a CLI prompt.
	if e.Code == grpcCodePermissionDenied || e.Code == grpcCodeUnauthenticated {
		return "permission denied: " + e.Message
	}
	return e.Message
}

// apiErrorFromBody turns a non-2xx response into a *cloudAPIError when the
// body parses as the standard grpc-gateway error shape, or a generic error
// otherwise (an unparseable body is still surfaced, just without a Code a
// caller could switch on).
func apiErrorFromBody(status int, body []byte) error {
	var e struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &e); err != nil || e.Message == "" {
		return fmt.Errorf("api error (status %d): %s", status, string(body))
	}
	return &cloudAPIError{Status: status, Code: e.Code, Message: e.Message}
}

// doCloudAPIRequest issues one request against the hosted control plane's
// REST surface (org / region endpoints — no OSS proto exists for these, they
// are cloud-only, so this hand-rolls JSON like fetchBackends does for
// /v1/backends rather than pulling in generated cloud client stubs this repo
// doesn't have). body is marshaled as the request body when non-nil (PUT/POST);
// nil means no body (GET).
func doCloudAPIRequest(method, path string, body any) ([]byte, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required (or `containarium login` first)")
	}
	target := strings.TrimSuffix(serverAddr, "/") + path

	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, apiErrorFromBody(resp.StatusCode, respBody)
	}
	return respBody, nil
}

// requireCloudTarget is the shared guard every command in this file opens
// with: control-plane-only operations refuse cleanly against a standalone
// daemon (#1607 acceptance 2), the mirror of errUnsupportedOnCloud.
func requireCloudTarget(op string) error {
	if !isCloudTarget(serverAddr, authToken) {
		return errRequiresCloud(op)
	}
	return nil
}

// requireSessionOrgID resolves the org this session belongs to, or a clear
// error when there isn't one to resolve — never sends an empty org_id to the
// API and lets a confusing 404 stand in for "you're not logged in".
func requireSessionOrgID() (string, error) {
	orgID := resolveOrgID(serverAddr)
	if orgID == "" {
		return "", fmt.Errorf("no organization on this session (run `containarium login` first, or `containarium whoami` to check)")
	}
	return orgID, nil
}

// fetchRegions returns the control plane's configured sentinel region codes,
// sorted. Valid input for --region and org set-default-region.
func fetchRegions() ([]string, error) {
	body, err := doCloudAPIRequest(http.MethodGet, "/v1/regions", nil)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Regions []string `json:"regions"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	sort.Strings(parsed.Regions)
	return parsed.Regions, nil
}

// organization is the wire shape of GetOrganization/SetDefaultRegion's
// response, narrowed to the fields these commands read.
type organization struct {
	ID            string `json:"id"`
	DefaultRegion string `json:"defaultRegion"`
}

type organizationEnvelope struct {
	Organization organization `json:"organization"`
}

var regionsCmd = &cobra.Command{
	Use:   "regions",
	Short: "List the region codes a hosted control plane serves",
	Long: `Cloud-only — a standalone daemon has no regions. Valid input for
'containarium create --region' and 'containarium org set-default-region'.`,
	Args: cobra.NoArgs,
	RunE: runRegions,
}

func runRegions(_ *cobra.Command, _ []string) error {
	if err := requireCloudTarget("regions"); err != nil {
		return err
	}
	regions, err := fetchRegions()
	if err != nil {
		return err
	}
	if len(regions) == 0 {
		fmt.Println("(no regions configured — single-sentinel / legacy deploy)")
		return nil
	}
	for _, r := range regions {
		fmt.Println(r)
	}
	return nil
}

var orgCmd = &cobra.Command{
	Use:   "org",
	Short: "Act on the organization your session belongs to (hosted control plane only)",
	Long: `Every org-level setting was read-only from this CLI — 'whoami' reports
which org a credential belongs to but nothing here could act on it. This
group is where org-level writes land, starting with the default placement
region (#1607).

Cloud-only: a standalone daemon has no organizations.`,
}

var orgGetDefaultRegionCmd = &cobra.Command{
	Use:   "get-default-region",
	Short: "Show the org's default container-placement region",
	Long: `Prints "(no default region set)" when none is configured — that is the
condition 'containarium create' with no --region and no org default refuses
against on a multi-region control plane (see #1606).`,
	Args: cobra.NoArgs,
	RunE: runOrgGetDefaultRegion,
}

var orgSetDefaultRegionCmd = &cobra.Command{
	Use:   "set-default-region <code>",
	Short: "Set the org's default container-placement region",
	Long: `Sets the region a container create lands in when --region is omitted (see
'containarium create --region'). This is the CLI-reachable fix for the dead
end #1606 describes: an org with no default and a create with no --region.

Owner/admin only — enforced server-side; a caller without permission sees a
permission error here, not a generic failure. Run 'containarium regions'
first to see the valid codes.`,
	Args: cobra.ExactArgs(1),
	RunE: runOrgSetDefaultRegion,
}

func init() {
	rootCmd.AddCommand(regionsCmd)
	rootCmd.AddCommand(orgCmd)
	orgCmd.AddCommand(orgGetDefaultRegionCmd, orgSetDefaultRegionCmd)
}

func runOrgGetDefaultRegion(_ *cobra.Command, _ []string) error {
	if err := requireCloudTarget("org get-default-region"); err != nil {
		return err
	}
	orgID, err := requireSessionOrgID()
	if err != nil {
		return err
	}
	body, err := doCloudAPIRequest(http.MethodGet, "/v1/orgs/"+url.PathEscape(orgID), nil)
	if err != nil {
		return err
	}
	var env organizationEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if env.Organization.DefaultRegion == "" {
		fmt.Println("(no default region set)")
		return nil
	}
	fmt.Println(env.Organization.DefaultRegion)
	return nil
}

func runOrgSetDefaultRegion(_ *cobra.Command, args []string) error {
	if err := requireCloudTarget("org set-default-region"); err != nil {
		return err
	}
	orgID, err := requireSessionOrgID()
	if err != nil {
		return err
	}
	region := args[0]

	_, err = doCloudAPIRequest(http.MethodPut, "/v1/orgs/"+url.PathEscape(orgID)+"/default-region",
		map[string]string{"region": region})
	if err != nil {
		var apiErr *cloudAPIError
		if errors.As(err, &apiErr) && apiErr.Code == grpcCodeInvalidArgument {
			return fmt.Errorf("%w\n\nValid region codes: %s", err, validRegionsHint())
		}
		return err
	}
	fmt.Printf("Default region set to %q.\n", region)
	return nil
}

// validRegionsHint is best-effort: if the follow-up list call itself fails,
// the original error (already returned to the caller) still stands — this
// only decorates it, never replaces it or masks the real failure.
func validRegionsHint() string {
	regions, err := fetchRegions()
	if err != nil || len(regions) == 0 {
		return "(unable to fetch the list — run `containarium regions`)"
	}
	return strings.Join(regions, ", ")
}
