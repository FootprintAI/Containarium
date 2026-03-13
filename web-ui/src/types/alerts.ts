export interface AlertRule {
  id: string;
  name: string;
  expr: string;
  duration: string;
  severity: string;
  description: string;
  labels: Record<string, string>;
  annotations: Record<string, string>;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface AlertRulesResponse {
  rules: AlertRule[];
}

export interface AlertingInfoResponse {
  enabled: boolean;
  vmalertStatus: string;
  alertmanagerStatus: string;
  webhookUrl: string;
  totalRules: number;
  customRules: number;
  webhookSecretConfigured: boolean;
}

export interface CreateAlertRuleRequest {
  name: string;
  expr: string;
  duration: string;
  severity: string;
  description?: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
  enabled: boolean;
}

export interface UpdateAlertRuleRequest {
  name?: string;
  expr?: string;
  duration?: string;
  severity?: string;
  description?: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
  enabled?: boolean;
}

export interface UpdateAlertingConfigRequest {
  webhookUrl: string;
  generateWebhookSecret?: boolean;
}

export interface UpdateAlertingConfigResponse {
  webhookUrl: string;
  success: boolean;
  webhookSecret?: string;
}

export interface TestWebhookResponse {
  success: boolean;
  statusCode: number;
  message: string;
}

export interface WebhookDelivery {
  id: number;
  timestamp: string;
  alertName: string;
  source: string;
  webhookUrl: string;
  success: boolean;
  httpStatus: number;
  errorMessage: string;
  payloadSize: number;
  durationMs: number;
}

export interface WebhookDeliveriesResponse {
  deliveries: WebhookDelivery[];
  totalCount: number;
}
