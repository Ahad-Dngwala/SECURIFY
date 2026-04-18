const BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type AttackType = 'ddos' | 'brute_force' | 'data_exfil' | 'port_scan' | 'priv_esc';
export type CloudProvider = 'AWS' | 'Azure' | 'GCP';

export interface Explanation {
  feature: string;
  impact: number;
}

export interface Prediction {
  is_attack: boolean;
  attack_probability: number;
  cloud_source: CloudProvider;
  src_ip: string;
  severity: Severity;
  explanation: Explanation[];
}

export interface Stats {
  total_predictions: number;
  total_attacks: number;
  normal_events: number;
  attack_rate_percent: number;
}

export interface BatchResult {
  count: number;
  results: Prediction[];
}

/** A single log entry for terminal display — constructed client-side from Prediction */
export interface LogEntry {
  id: string;
  timestamp: Date;
  cloud: CloudProvider;
  severity: Severity;
  ip: string;
  message: string;
  isAttack: boolean;
  probability: number;
  prediction: Prediction;
}

let _logCounter = 0;

export function predictionToLog(p: Prediction): LogEntry {
  _logCounter++;
  const verb = p.is_attack ? 'THREAT DETECTED' : 'PASS';
  const topFeat = p.explanation?.[0]?.feature ?? 'n/a';
  const msg = p.is_attack
    ? `[${p.severity}] ${verb} from ${p.src_ip} — top_signal: ${topFeat} (p=${(p.attack_probability * 100).toFixed(1)}%)`
    : `[OK] Normal traffic from ${p.src_ip} — confidence: ${((1 - p.attack_probability) * 100).toFixed(1)}%`;

  return {
    id: `log-${_logCounter}-${Date.now()}`,
    timestamp: new Date(),
    cloud: p.cloud_source as CloudProvider,
    severity: p.severity,
    ip: p.src_ip,
    message: msg,
    isAttack: p.is_attack,
    probability: p.attack_probability,
    prediction: p,
  };
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json() as Promise<T>;
}

export const api = {
  health:        ()                      => get<{ status: string }>('/'),
  simulate:      ()                      => get<Prediction>('/simulate'),
  simulateAttack:(type: AttackType)      => get<Prediction>(`/simulate/attack?type=${type}`),
  batchSimulate: (n: number)             => get<BatchResult>(`/simulate/batch?n=${n}`),
  stats:         ()                      => get<Stats>('/stats'),
};

export const ATTACK_INFO: Record<AttackType, { label: string; desc: string; preview: string }> = {
  ddos:        { label: 'DDoS Attack',              desc: 'Overwhelm target with massive request volume.',          preview: 'Expect: request_rate spike >1000 req/s, short sessions' },
  brute_force: { label: 'Brute Force',              desc: 'Repeated login attempts to guess credentials.',          preview: 'Expect: failed_logins surge, unusual time access' },
  data_exfil:  { label: 'Data Exfiltration',        desc: 'Unauthorized large data transfer to external IP.',       preview: 'Expect: data_transferred spike, geo_anomaly flag' },
  port_scan:   { label: 'Port Scan',                desc: 'Probe open ports to map attack surface.',                preview: 'Expect: port_scan flag, high request_rate' },
  priv_esc:    { label: 'Privilege Escalation',     desc: 'Attempt to gain higher-level permissions.',              preview: 'Expect: priv_escalation attempts, failed logins' },
};
