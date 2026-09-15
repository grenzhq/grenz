/**
 * LLM client — behind an interface so the one real network call is swappable
 * and fakeable in tests, mirroring notify/notifier.ts + notify/slack.ts. Uses
 * Anthropic's Messages API directly via `fetch()` — no SDK dependency, so
 * `bun build --compile` stays clean (the proxy takes on no runtime deps that
 * would break the single-binary compile).
 */

export interface LlmClient {
  complete(prompt: string): Promise<string>;
}

const ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION = "2023-06-01";
const MAX_TOKENS = 4096;

export const DEFAULT_MODEL = "claude-haiku-4-5-20251001";

export class AnthropicLlmClient implements LlmClient {
  constructor(
    private readonly apiKey: string,
    private readonly model: string,
  ) {}

  async complete(prompt: string): Promise<string> {
    const res = await fetch(ANTHROPIC_API_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": this.apiKey,
        "anthropic-version": ANTHROPIC_VERSION,
      },
      body: JSON.stringify({
        model: this.model,
        max_tokens: MAX_TOKENS,
        messages: [{ role: "user", content: prompt }],
      }),
    });
    if (!res.ok) {
      throw new Error(`Anthropic API returned ${res.status}`);
    }
    const data = (await res.json()) as { content?: Array<{ type: string; text?: string }> };
    const text = data.content?.find((b) => b.type === "text")?.text;
    if (!text) {
      throw new Error("Anthropic API response had no text content");
    }
    return text;
  }
}
