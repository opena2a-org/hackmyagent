/**
 * Raw Anthropic API Client (Layer 3)
 *
 * Zero-dependency fetch() client for Claude API.
 * Used only in CLI standalone mode (--deep with ANTHROPIC_API_KEY).
 */

export interface AnthropicMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface AnthropicRequest {
  model: string;
  max_tokens: number;
  system?: string;
  messages: AnthropicMessage[];
}

export interface AnthropicResponse {
  id: string;
  content: Array<{ type: string; text: string }>;
  model: string;
  usage: {
    input_tokens: number;
    output_tokens: number;
  };
}

export interface AnthropicError {
  type: string;
  error: {
    type: string;
    message: string;
  };
}

/** Model ID mapping */
const MODEL_IDS = {
  haiku: 'claude-haiku-4-5-20251001',
  sonnet: 'claude-sonnet-4-5-20250929',
} as const;

export class AnthropicClient {
  private apiKey: string;
  private baseUrl: string;

  constructor(apiKey: string, baseUrl: string = 'https://api.anthropic.com') {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl;
  }

  /**
   * Send a message to Claude and get a text response.
   */
  async chat(
    model: 'haiku' | 'sonnet',
    systemPrompt: string,
    userMessage: string,
    maxTokens: number = 4096
  ): Promise<{ text: string; inputTokens: number; outputTokens: number }> {
    const request: AnthropicRequest = {
      model: MODEL_IDS[model],
      max_tokens: maxTokens,
      system: systemPrompt,
      messages: [{ role: 'user', content: userMessage }],
    };

    const response = await fetch(`${this.baseUrl}/v1/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      let errorMessage: string;
      try {
        const parsed = JSON.parse(errorBody) as AnthropicError;
        errorMessage = parsed.error?.message || errorBody;
      } catch {
        errorMessage = errorBody;
      }
      throw new Error(
        `Anthropic API error (${response.status}): ${errorMessage}`
      );
    }

    const body = (await response.json()) as AnthropicResponse;
    const text = body.content
      .filter((c) => c.type === 'text')
      .map((c) => c.text)
      .join('');

    return {
      text,
      inputTokens: body.usage.input_tokens,
      outputTokens: body.usage.output_tokens,
    };
  }
}
