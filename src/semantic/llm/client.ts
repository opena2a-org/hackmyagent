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

/** A client tool the model is offered, as the Messages API declares one. */
export interface AnthropicTool {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
}

export interface AnthropicRequest {
  model: string;
  max_tokens: number;
  system?: string;
  messages: AnthropicMessage[];
  tools?: AnthropicTool[];
  tool_choice?: { type: 'tool'; name: string; disable_parallel_tool_use?: boolean };
}

export interface AnthropicResponse {
  id: string;
  content: Array<{ type: string; text?: string; name?: string; input?: unknown }>;
  model: string;
  stop_reason?: string | null;
  usage: {
    input_tokens: number;
    output_tokens: number;
  };
}

/**
 * What came back from a forced tool call, as the transport carried it.
 *
 * Nothing here is interpreted: no text is kept, and a missing stop reason is
 * `null` rather than a guess. Deciding what the answer means belongs to the
 * caller, which must treat "no call" as a non-answer, never as an empty one.
 */
export interface AnthropicToolResponse {
  stopReason: string | null;
  toolCalls: Array<{ name: string; input: unknown }>;
  inputTokens: number;
  outputTokens: number;
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
    const body = await this.send({
      model: MODEL_IDS[model],
      max_tokens: maxTokens,
      system: systemPrompt,
      messages: [{ role: 'user', content: userMessage }],
    });
    const text = body.content
      .filter((c) => c.type === 'text')
      .map((c) => c.text ?? '')
      .join('');

    return {
      text,
      inputTokens: body.usage.input_tokens,
      outputTokens: body.usage.output_tokens,
    };
  }

  /**
   * Send a message that must be answered by calling `tool`, exactly once.
   *
   * The answer is the tool call's `input`, which arrives as an object in the
   * response body, so no text in the reply is read. `disable_parallel_tool_use`
   * asks for one call rather than one or more, and the caller still refuses a
   * reply holding two. An error status, including a request the model rejects,
   * is thrown by `send`, so it reaches the caller as a failure, never as an
   * empty result.
   */
  async callTool(
    model: 'haiku' | 'sonnet',
    systemPrompt: string,
    userMessage: string,
    tool: AnthropicTool,
    maxTokens: number = 4096
  ): Promise<AnthropicToolResponse> {
    const body = await this.send({
      model: MODEL_IDS[model],
      max_tokens: maxTokens,
      system: systemPrompt,
      messages: [{ role: 'user', content: userMessage }],
      tools: [tool],
      tool_choice: { type: 'tool', name: tool.name, disable_parallel_tool_use: true },
    });

    return {
      stopReason: body.stop_reason ?? null,
      toolCalls: body.content
        .filter((c) => c.type === 'tool_use')
        .map((c) => ({ name: String(c.name), input: c.input })),
      inputTokens: body.usage.input_tokens,
      outputTokens: body.usage.output_tokens,
    };
  }

  private async send(request: AnthropicRequest): Promise<AnthropicResponse> {
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

    return (await response.json()) as AnthropicResponse;
  }
}
