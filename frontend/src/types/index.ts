export type Severity = "high" | "medium" | "low";

export interface RateLimitConfig {
  requests_per_second: number;
}

export interface ScanConfig {
  max_prompts: number;
  categories: string[];
  timeout: number;
  rate_limit: RateLimitConfig;
  max_requests?: number;
  max_tokens?: number;
  cost_limit?: number;
  max_concurrent_requests: number;
}

export interface TargetInput {
  endpoint_url: string;
  api_key?: string;
  request_template: Record<string, unknown>;
  headers: Record<string, string>;
  timeout: number;
}

export interface StartScanRequest {
  target: TargetInput;
  config: ScanConfig;
}

export interface StartScanResponse {
  scan_id: string;
  status: string;
  created_at: string;
}

export interface ScanStatusResponse {
  scan_id: string;
  status: string;
  progress: {
    total_prompts: number;
    completed_prompts: number;
  };
  created_at: string;
  completed_at?: string;
  error_message?: string;
}

export interface ReportVulnerability {
  id: string;
  type: string;
  severity: Severity;
  confidence: number;
  attack_prompt: string;
  response_text: string;
  detection_method: string;
  evidence: Record<string, unknown>;
  suggested_fix: string;
}

export interface ReportResponse {
  scan_id: string;
  target_endpoint: string;
  status: string;
  created_at: string;
  completed_at?: string;
  scan_duration_seconds?: number;
  resource_usage: {
    total_requests: number;
    total_tokens: number;
    total_cost: number;
  };
  summary: {
    total_vulnerabilities: number;
    high_severity: number;
    medium_severity: number;
    low_severity: number;
  };
  vulnerabilities: ReportVulnerability[];
}

export interface ScanHistoryItem {
  scan_id: string;
  target_endpoint: string;
  status: string;
  created_at: string;
  completed_at?: string;
  vulnerability_count: number;
}
