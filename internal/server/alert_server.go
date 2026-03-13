package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/footprintai/containarium/internal/alert"
	"github.com/footprintai/containarium/internal/app"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SetAlertManager sets the alert store and manager on the container server.
// Called from dual_server.go after the alert components are initialized.
func (s *ContainerServer) SetAlertManager(store *alert.Store, manager *alert.Manager, webhookURL string, webhookSecret string, coreServices *CoreServices, daemonConfigStore *app.DaemonConfigStore) {
	s.alertStore = store
	s.alertManager = manager
	s.alertWebhookURL = webhookURL
	s.alertWebhookSecret = webhookSecret
	s.coreServices = coreServices
	s.daemonConfigStore = daemonConfigStore
}

// SetAlertDeliveryStore sets the delivery store for recording webhook delivery attempts
func (s *ContainerServer) SetAlertDeliveryStore(ds *alert.DeliveryStore) {
	s.alertDeliveryStore = ds
}

// CreateAlertRule creates a new custom alert rule
func (s *ContainerServer) CreateAlertRule(ctx context.Context, req *pb.CreateAlertRuleRequest) (*pb.CreateAlertRuleResponse, error) {
	if s.alertStore == nil {
		return nil, status.Error(codes.Unavailable, "alerting is not configured")
	}

	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if req.Expr == "" {
		return nil, status.Error(codes.InvalidArgument, "expr is required")
	}

	severity := req.Severity
	if severity == "" {
		severity = "warning"
	}
	duration := req.Duration
	if duration == "" {
		duration = "5m"
	}

	rule := &alert.AlertRule{
		Name:        req.Name,
		Expr:        req.Expr,
		Duration:    duration,
		Severity:    severity,
		Description: req.Description,
		Labels:      req.Labels,
		Annotations: req.Annotations,
		Enabled:     req.Enabled,
	}

	created, err := s.alertStore.Create(ctx, rule)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create alert rule: %v", err)
	}

	// Sync rules to vmalert (best-effort)
	if s.alertManager != nil {
		if err := s.alertManager.SyncRules(ctx); err != nil {
			log.Printf("Warning: failed to sync alert rules after create: %v", err)
		}
	}

	return &pb.CreateAlertRuleResponse{
		Rule: alertRuleToProto(created),
	}, nil
}

// ListAlertRules lists all custom alert rules
func (s *ContainerServer) ListAlertRules(ctx context.Context, req *pb.ListAlertRulesRequest) (*pb.ListAlertRulesResponse, error) {
	if s.alertStore == nil {
		return &pb.ListAlertRulesResponse{}, nil
	}

	rules, err := s.alertStore.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list alert rules: %v", err)
	}

	pbRules := make([]*pb.AlertRule, len(rules))
	for i, rule := range rules {
		pbRules[i] = alertRuleToProto(rule)
	}

	return &pb.ListAlertRulesResponse{Rules: pbRules}, nil
}

// GetAlertRule gets a single alert rule by ID
func (s *ContainerServer) GetAlertRule(ctx context.Context, req *pb.GetAlertRuleRequest) (*pb.GetAlertRuleResponse, error) {
	if s.alertStore == nil {
		return nil, status.Error(codes.Unavailable, "alerting is not configured")
	}

	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	rule, err := s.alertStore.Get(ctx, req.Id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, status.Errorf(codes.NotFound, "alert rule not found: %s", req.Id)
		}
		return nil, status.Errorf(codes.Internal, "failed to get alert rule: %v", err)
	}

	return &pb.GetAlertRuleResponse{Rule: alertRuleToProto(rule)}, nil
}

// UpdateAlertRule updates an existing alert rule
func (s *ContainerServer) UpdateAlertRule(ctx context.Context, req *pb.UpdateAlertRuleRequest) (*pb.UpdateAlertRuleResponse, error) {
	if s.alertStore == nil {
		return nil, status.Error(codes.Unavailable, "alerting is not configured")
	}

	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	// Get existing rule to preserve fields not in the update
	existing, err := s.alertStore.Get(ctx, req.Id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, status.Errorf(codes.NotFound, "alert rule not found: %s", req.Id)
		}
		return nil, status.Errorf(codes.Internal, "failed to get alert rule: %v", err)
	}

	// Apply updates
	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.Expr != "" {
		existing.Expr = req.Expr
	}
	if req.Duration != "" {
		existing.Duration = req.Duration
	}
	if req.Severity != "" {
		existing.Severity = req.Severity
	}
	if req.Description != "" {
		existing.Description = req.Description
	}
	if req.Labels != nil {
		existing.Labels = req.Labels
	}
	if req.Annotations != nil {
		existing.Annotations = req.Annotations
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}

	updated, err := s.alertStore.Update(ctx, existing)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update alert rule: %v", err)
	}

	// Sync rules to vmalert (best-effort)
	if s.alertManager != nil {
		if err := s.alertManager.SyncRules(ctx); err != nil {
			log.Printf("Warning: failed to sync alert rules after update: %v", err)
		}
	}

	return &pb.UpdateAlertRuleResponse{Rule: alertRuleToProto(updated)}, nil
}

// DeleteAlertRule deletes an alert rule
func (s *ContainerServer) DeleteAlertRule(ctx context.Context, req *pb.DeleteAlertRuleRequest) (*pb.DeleteAlertRuleResponse, error) {
	if s.alertStore == nil {
		return nil, status.Error(codes.Unavailable, "alerting is not configured")
	}

	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	if err := s.alertStore.Delete(ctx, req.Id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, status.Errorf(codes.NotFound, "alert rule not found: %s", req.Id)
		}
		return nil, status.Errorf(codes.Internal, "failed to delete alert rule: %v", err)
	}

	// Sync rules to vmalert (best-effort)
	if s.alertManager != nil {
		if err := s.alertManager.SyncRules(ctx); err != nil {
			log.Printf("Warning: failed to sync alert rules after delete: %v", err)
		}
	}

	return &pb.DeleteAlertRuleResponse{}, nil
}

// GetAlertingInfo returns alerting system status
func (s *ContainerServer) GetAlertingInfo(ctx context.Context, req *pb.GetAlertingInfoRequest) (*pb.GetAlertingInfoResponse, error) {
	resp := &pb.GetAlertingInfoResponse{
		Enabled: s.alertStore != nil,
	}

	if s.alertStore == nil {
		return resp, nil
	}

	// Check vmalert health
	resp.VmalertStatus = checkHTTPHealth(fmt.Sprintf("http://%s:%d/-/healthy", s.victoriaMetricsIP(), DefaultVMAlertPort))

	// Check alertmanager health (path includes external-url prefix)
	resp.AlertmanagerStatus = checkHTTPHealth(fmt.Sprintf("http://%s:%d/alertmanager/-/healthy", s.victoriaMetricsIP(), DefaultAlertmanagerPort))

	// Mask webhook URL for security
	if s.alertWebhookURL != "" {
		resp.WebhookUrl = maskURL(s.alertWebhookURL)
	}

	// Indicate whether a signing secret is configured
	resp.WebhookSecretConfigured = s.alertWebhookSecret != ""

	// Count rules
	rules, err := s.alertStore.List(ctx)
	if err == nil {
		resp.CustomRules = int32(len(rules))
	}
	// Default rules count is static (9 rules in default.yml)
	resp.TotalRules = 9 + resp.CustomRules

	return resp, nil
}

// victoriaMetricsIP returns the IP of the VictoriaMetrics container
func (s *ContainerServer) victoriaMetricsIP() string {
	// Extract IP from URL like "http://10.100.0.5:8428"
	url := s.victoriaMetricsURL
	if url == "" {
		return "localhost"
	}
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	if idx := strings.Index(url, ":"); idx > 0 {
		return url[:idx]
	}
	return url
}

// checkHTTPHealth performs a simple HTTP GET and returns "healthy" or "unhealthy"
func checkHTTPHealth(url string) string {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "unhealthy"
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return "healthy"
	}
	return "unhealthy"
}

// maskURL masks the URL for display (shows host but hides path/query)
func maskURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	// Show scheme + host, mask the rest
	parts := strings.SplitN(rawURL, "//", 2)
	if len(parts) < 2 {
		return "***"
	}
	hostPart := parts[1]
	if idx := strings.Index(hostPart, "/"); idx > 0 {
		return parts[0] + "//" + hostPart[:idx] + "/***"
	}
	return rawURL
}

// ListDefaultAlertRules returns the built-in default alert rules
func (s *ContainerServer) ListDefaultAlertRules(ctx context.Context, req *pb.ListDefaultAlertRulesRequest) (*pb.ListDefaultAlertRulesResponse, error) {
	rules, err := parseDefaultAlertRules()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse default rules: %v", err)
	}
	return &pb.ListDefaultAlertRulesResponse{Rules: rules}, nil
}

// parseDefaultAlertRules parses the DefaultAlertRules YAML constant into protobuf AlertRule messages
func parseDefaultAlertRules() ([]*pb.AlertRule, error) {
	var rulesFile struct {
		Groups []struct {
			Name  string `yaml:"name"`
			Rules []struct {
				Alert       string            `yaml:"alert"`
				Expr        string            `yaml:"expr"`
				For         string            `yaml:"for"`
				Labels      map[string]string `yaml:"labels"`
				Annotations map[string]string `yaml:"annotations"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}

	if err := yaml.Unmarshal([]byte(DefaultAlertRules), &rulesFile); err != nil {
		return nil, fmt.Errorf("failed to parse default rules YAML: %w", err)
	}

	var pbRules []*pb.AlertRule
	for _, group := range rulesFile.Groups {
		for _, rule := range group.Rules {
			severity := rule.Labels["severity"]
			description := rule.Annotations["description"]
			pbRules = append(pbRules, &pb.AlertRule{
				Id:          fmt.Sprintf("default-%s", strings.ToLower(rule.Alert)),
				Name:        rule.Alert,
				Expr:        rule.Expr,
				Duration:    rule.For,
				Severity:    severity,
				Description: description,
				Labels:      rule.Labels,
				Annotations: rule.Annotations,
				Enabled:     true,
			})
		}
	}
	return pbRules, nil
}

// UpdateAlertingConfig updates the alerting system configuration (webhook URL and/or secret)
func (s *ContainerServer) UpdateAlertingConfig(ctx context.Context, req *pb.UpdateAlertingConfigRequest) (*pb.UpdateAlertingConfigResponse, error) {
	if s.alertStore == nil {
		return nil, status.Error(codes.Unavailable, "alerting is not configured")
	}

	if s.coreServices == nil {
		return nil, status.Error(codes.Unavailable, "core services not available for webhook update")
	}

	// Handle webhook secret generation
	var generatedSecret string
	if req.GenerateWebhookSecret {
		generatedSecret = generateWebhookSecret()
		s.alertWebhookSecret = generatedSecret

		// Persist secret to database
		if s.daemonConfigStore != nil {
			if err := s.daemonConfigStore.Set(ctx, "alert_webhook_secret", generatedSecret); err != nil {
				log.Printf("Warning: failed to persist webhook secret to database: %v", err)
			} else {
				log.Printf("Webhook secret generated and persisted to database")
			}
		}

		// Update gateway relay config if available
		if s.alertRelayConfigFn != nil {
			s.alertRelayConfigFn(s.alertWebhookURL, s.alertWebhookSecret)
		}
	}

	// Update webhook URL if provided (or explicitly clearing it)
	webhookURL := req.WebhookUrl
	if webhookURL != "" || !req.GenerateWebhookSecret {
		// Route through relay if a signing secret is configured
		relayURL := webhookURL
		if s.alertWebhookSecret != "" && webhookURL != "" && s.hostRelayURL != "" {
			relayURL = s.hostRelayURL
		}

		// Update alertmanager config in the container
		if err := s.coreServices.UpdateAlertmanagerWebhook(ctx, relayURL); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to update webhook: %v", err)
		}

		// Update in-memory webhook URL
		s.alertWebhookURL = webhookURL

		// Update gateway relay config if available
		if s.alertRelayConfigFn != nil {
			s.alertRelayConfigFn(s.alertWebhookURL, s.alertWebhookSecret)
		}

		// Persist to database if config store is available
		if s.daemonConfigStore != nil {
			if err := s.daemonConfigStore.Set(ctx, "alert_webhook_url", webhookURL); err != nil {
				log.Printf("Warning: failed to persist webhook URL to database: %v", err)
			} else {
				log.Printf("Webhook URL persisted to database")
			}
		}
	}

	resp := &pb.UpdateAlertingConfigResponse{
		Success: true,
	}
	if s.alertWebhookURL != "" {
		resp.WebhookUrl = maskURL(s.alertWebhookURL)
	}
	if generatedSecret != "" {
		resp.WebhookSecret = generatedSecret
	}
	return resp, nil
}

// TestWebhook sends a test notification to the configured webhook with current system status
func (s *ContainerServer) TestWebhook(ctx context.Context, req *pb.TestWebhookRequest) (*pb.TestWebhookResponse, error) {
	if s.alertWebhookURL == "" {
		return &pb.TestWebhookResponse{
			Success:    false,
			StatusCode: 0,
			Message:    "No webhook URL configured. Set a webhook URL first.",
		}, nil
	}

	// Gather current system status
	vmIP := s.victoriaMetricsIP()
	vmalertStatus := checkHTTPHealth(fmt.Sprintf("http://%s:%d/-/healthy", vmIP, DefaultVMAlertPort))
	amStatus := checkHTTPHealth(fmt.Sprintf("http://%s:%d/alertmanager/-/healthy", vmIP, DefaultAlertmanagerPort))

	customRuleCount := 0
	if s.alertStore != nil {
		if rules, err := s.alertStore.List(ctx); err == nil {
			customRuleCount = len(rules)
		}
	}

	// Build Alertmanager webhook payload
	now := time.Now().UTC()
	payload := map[string]interface{}{
		"version":  "4",
		"status":   "firing",
		"receiver": "webhook",
		"alerts": []map[string]interface{}{
			{
				"status": "firing",
				"labels": map[string]string{
					"alertname": "ContinariumTestAlert",
					"severity":  "info",
					"source":    "test",
					"instance":  vmIP,
				},
				"annotations": map[string]string{
					"summary":     "Test alert from Containarium",
					"description": fmt.Sprintf("This is a test notification. System status: vmalert=%s, alertmanager=%s, default_rules=9, custom_rules=%d", vmalertStatus, amStatus, customRuleCount),
				},
				"startsAt":     now.Format(time.RFC3339),
				"endsAt":       now.Add(5 * time.Minute).Format(time.RFC3339),
				"generatorURL": fmt.Sprintf("http://%s:%d", vmIP, DefaultVMAlertPort),
			},
		},
		"groupLabels": map[string]string{
			"alertname": "ContinariumTestAlert",
		},
		"commonLabels": map[string]string{
			"alertname": "ContinariumTestAlert",
			"severity":  "info",
			"source":    "test",
		},
		"commonAnnotations": map[string]string{
			"summary": "Test alert from Containarium",
		},
		"externalURL": fmt.Sprintf("http://%s:%d/alertmanager", vmIP, DefaultAlertmanagerPort),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal payload: %v", err)
	}

	// Send to webhook
	start := time.Now()
	client := &http.Client{Timeout: 10 * time.Second}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.alertWebhookURL, bytes.NewReader(body))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Sign payload with HMAC-SHA256 if secret is configured
	if s.alertWebhookSecret != "" {
		sig := signPayload(body, s.alertWebhookSecret)
		httpReq.Header.Set("X-Containarium-Signature", sig)
	}

	resp, err := client.Do(httpReq)
	durationMs := int(time.Since(start).Milliseconds())
	if err != nil {
		// Record failed delivery
		s.recordDelivery(ctx, "ContinariumTestAlert", "test", s.alertWebhookURL, false, 0, fmt.Sprintf("Failed to reach webhook: %v", err), len(body), durationMs)
		return &pb.TestWebhookResponse{
			Success:    false,
			StatusCode: 0,
			Message:    fmt.Sprintf("Failed to reach webhook: %v", err),
		}, nil
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	errMsg := ""
	msg := fmt.Sprintf("Test notification sent successfully (HTTP %d)", resp.StatusCode)
	if !success {
		errMsg = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(respBody))
		msg = fmt.Sprintf("Webhook returned %s", errMsg)
	}

	// Record delivery
	s.recordDelivery(ctx, "ContinariumTestAlert", "test", s.alertWebhookURL, success, resp.StatusCode, errMsg, len(body), durationMs)

	return &pb.TestWebhookResponse{
		Success:    success,
		StatusCode: int32(resp.StatusCode),
		Message:    msg,
	}, nil
}

// recordDelivery records a webhook delivery attempt (best-effort)
func (s *ContainerServer) recordDelivery(ctx context.Context, alertName, source, webhookURL string, success bool, httpStatus int, errMsg string, payloadSize, durationMs int) {
	if s.alertDeliveryStore == nil {
		return
	}
	d := &alert.WebhookDelivery{
		AlertName:    alertName,
		Source:       source,
		WebhookURL:   maskURL(webhookURL),
		Success:      success,
		HTTPStatus:   httpStatus,
		ErrorMessage: errMsg,
		PayloadSize:  payloadSize,
		DurationMs:   durationMs,
	}
	if err := s.alertDeliveryStore.Record(ctx, d); err != nil {
		log.Printf("Warning: failed to record delivery: %v", err)
	}
}

// ListWebhookDeliveries returns webhook delivery history
func (s *ContainerServer) ListWebhookDeliveries(ctx context.Context, req *pb.ListWebhookDeliveriesRequest) (*pb.ListWebhookDeliveriesResponse, error) {
	if s.alertDeliveryStore == nil {
		return &pb.ListWebhookDeliveriesResponse{}, nil
	}

	limit := int(req.Limit)
	offset := int(req.Offset)

	deliveries, total, err := s.alertDeliveryStore.List(ctx, limit, offset)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list deliveries: %v", err)
	}

	pbDeliveries := make([]*pb.WebhookDelivery, len(deliveries))
	for i, d := range deliveries {
		pbDeliveries[i] = &pb.WebhookDelivery{
			Id:           d.ID,
			Timestamp:    d.Timestamp.Format(time.RFC3339),
			AlertName:    d.AlertName,
			Source:       d.Source,
			WebhookUrl:   d.WebhookURL,
			Success:      d.Success,
			HttpStatus:   int32(d.HTTPStatus),
			ErrorMessage: d.ErrorMessage,
			PayloadSize:  int32(d.PayloadSize),
			DurationMs:   int32(d.DurationMs),
		}
	}

	return &pb.ListWebhookDeliveriesResponse{
		Deliveries: pbDeliveries,
		TotalCount: int32(total),
	}, nil
}

// SetAlertRelayConfig sets the callback and relay URL used to update the gateway
// relay config when the webhook URL or secret changes at runtime.
func (s *ContainerServer) SetAlertRelayConfig(relayURL string, fn func(webhookURL, secret string)) {
	s.hostRelayURL = relayURL
	s.alertRelayConfigFn = fn
}

// signPayload computes HMAC-SHA256 of payload using the given secret and returns
// the signature in the format "sha256=<hex>".
func signPayload(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// generateWebhookSecret generates a cryptographically random 32-byte secret
// encoded as base64url (no padding).
func generateWebhookSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback — should never happen
		return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// alertRuleToProto converts an internal AlertRule to a protobuf AlertRule
func alertRuleToProto(rule *alert.AlertRule) *pb.AlertRule {
	return &pb.AlertRule{
		Id:          rule.ID,
		Name:        rule.Name,
		Expr:        rule.Expr,
		Duration:    rule.Duration,
		Severity:    rule.Severity,
		Description: rule.Description,
		Labels:      rule.Labels,
		Annotations: rule.Annotations,
		Enabled:     rule.Enabled,
		CreatedAt:   rule.CreatedAt.Unix(),
		UpdatedAt:   rule.UpdatedAt.Unix(),
	}
}
