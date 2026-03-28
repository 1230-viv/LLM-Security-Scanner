import type {
  ReportResponse,
  ScanHistoryItem,
  ScanStatusResponse,
  StartScanRequest,
  StartScanResponse,
} from "@/types";

const API_BASE =
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000/api/v1";
const API_TOKEN = import.meta.env.VITE_API_TOKEN ?? "change-me";

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-Scanner-Token": API_TOKEN,
      ...(options.headers ?? {}),
    },
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `HTTP ${response.status}`);
  }

  return (await response.json()) as T;
}

export function createScan(payload: StartScanRequest): Promise<StartScanResponse> {
  return request<StartScanResponse>("/scan", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getScanStatus(scanId: string): Promise<ScanStatusResponse> {
  return request<ScanStatusResponse>(`/scan/${scanId}`);
}

export function getReport(scanId: string): Promise<ReportResponse> {
  return request<ReportResponse>(`/report/${scanId}?format=json`);
}

export async function getMarkdownReport(scanId: string): Promise<string> {
  const response = await fetch(`${API_BASE}/report/${scanId}?format=markdown`, {
    headers: {
      "X-Scanner-Token": API_TOKEN,
    },
  });

  if (!response.ok) {
    throw new Error(await response.text());
  }

  return response.text();
}

export function getHistory(limit = 50): Promise<ScanHistoryItem[]> {
  return request<ScanHistoryItem[]>(`/history?limit=${limit}`);
}
