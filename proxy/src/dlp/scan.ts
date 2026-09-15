/**
 * Outbound content inspection (DLP).
 *
 * Scans a request body for well-known credential shapes before Grenz forwards
 * it — closing the "allowed action, malicious payload" gap (e.g. an agent
 * pasting a secret into a permitted `pr:comment`, or POSTing credentials to an
 * allowed host).
 *
 * CRITICAL: a finding reports only the DETECTOR NAME and a match count — never
 * the matched text. The secret must never reach a log, reason code, or response.
 * Detectors are curated for low false-positives; scanning is opt-in per policy.
 */

export interface DlpFinding {
  readonly detector: string;
  readonly count: number;
}

interface Detector {
  readonly name: string;
  readonly re: RegExp;
}

// Ordered, curated, high-signal patterns. Keep false-positives low: prefer
// vendor-prefixed tokens over generic entropy.
const DETECTORS: readonly Detector[] = [
  { name: "aws_access_key", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: "github_token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { name: "github_pat", re: /\bgithub_pat_[A-Za-z0-9_]{50,}\b/g },
  { name: "slack_token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: "google_api_key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: "stripe_secret_key", re: /\bsk_live_[0-9A-Za-z]{24,}\b/g },
  { name: "openai_key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/g },
  { name: "private_key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g },
  {
    name: "generic_secret_assignment",
    re: /(?:password|passwd|secret|api[_-]?key|access[_-]?token)["']?\s*[=:]\s*["']?[^\s"'&,;]{12,}/gi,
  },
];

// Cap work on huge bodies: scan the first ~1 MB only.
const MAX_SCAN_BYTES = 1_000_000;

/** Scan text for credential shapes. Returns detector names + counts, no values. */
export function scanForSecrets(text: string): DlpFinding[] {
  const hay = text.length > MAX_SCAN_BYTES ? text.slice(0, MAX_SCAN_BYTES) : text;
  const findings: DlpFinding[] = [];
  for (const d of DETECTORS) {
    d.re.lastIndex = 0;
    const matches = hay.match(d.re);
    if (matches && matches.length > 0) findings.push({ detector: d.name, count: matches.length });
  }
  return findings;
}

/** Scan raw bytes (decoded lossily as UTF-8; binary won't match the patterns). */
export function scanBytes(bytes: Uint8Array): DlpFinding[] {
  const slice = bytes.byteLength > MAX_SCAN_BYTES ? bytes.subarray(0, MAX_SCAN_BYTES) : bytes;
  return scanForSecrets(new TextDecoder("utf-8", { fatal: false }).decode(slice));
}

/** Comma-joined detector names for an operational log line (safe — no values). */
export function findingLabel(findings: readonly DlpFinding[]): string {
  return findings.map((f) => f.detector).join(",");
}
