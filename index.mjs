import { generatePKCE } from "@openauthjs/openauth/pkce";

const CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const CLAUDE_CODE_VERSION = "2.1.2";
const CLAUDE_CODE_SYSTEM_PROMPT =
  "You are Claude Code, Anthropic's official CLI for Claude.";

const CLAUDE_CODE_TOOL_NAMES = {
  read: "Read",
  write: "Write",
  edit: "Edit",
  bash: "Bash",
  grep: "Grep",
  find: "Glob",
  glob: "Glob",
  ls: "Ls",
};

const CLAUDE_CODE_TOOL_NAMES_REVERSE = Object.fromEntries(
  Object.entries(CLAUDE_CODE_TOOL_NAMES).map(([key, value]) => [value, key]),
);

const toClaudeCodeName = (name) => CLAUDE_CODE_TOOL_NAMES[name] || name;

const fromClaudeCodeName = (name, reverseMap) =>
  reverseMap?.get(name) || CLAUDE_CODE_TOOL_NAMES_REVERSE[name] || name;

const CLAUDE_CODE_BETAS = [
  "claude-code-20250219",
  "oauth-2025-04-20",
  "fine-grained-tool-streaming-2025-05-14",
  "interleaved-thinking-2025-05-14",
];

const TOOL_CALL_ID_PATTERN = /[^a-zA-Z0-9_-]/g;

const normalizeToolCallId = (id) =>
  id.replace(TOOL_CALL_ID_PATTERN, "").slice(0, 40);

const sanitizeToolCallId = (id) => id.replace(TOOL_CALL_ID_PATTERN, "_");

const sanitizeSurrogates = (text) =>
  text.replace(
    /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g,
    "",
  );

const stripThinkingTags = (text) => text.replace(/<\/?thinking>/g, "");

const normalizeText = (text) => sanitizeSurrogates(text);

const normalizeThinkingText = (text) =>
  sanitizeSurrogates(stripThinkingTags(text));

const hasImageOnlyContent = (blocks) =>
  Array.isArray(blocks) &&
  blocks.length > 0 &&
  blocks.every((block) => block?.type === "image");

const normalizeContentBlocks = (content) => {
  if (typeof content === "string") {
    return normalizeText(content);
  }
  if (!Array.isArray(content)) return content;

  const normalized = content.map((block) => {
    if (!block || typeof block !== "object") return block;
    if (block.type === "text") {
      return { ...block, text: normalizeText(block.text ?? "") };
    }
    return block;
  });

  if (hasImageOnlyContent(normalized)) {
    normalized.unshift({ type: "text", text: "(see attached image)" });
  }

  return normalized;
};

const injectClaudeCodeSystemPrompt = (system) => {
  if (!system) return CLAUDE_CODE_SYSTEM_PROMPT;

  if (typeof system === "string") {
    const normalized = normalizeText(system);
    if (normalized.startsWith(CLAUDE_CODE_SYSTEM_PROMPT)) return normalized;
    return `${CLAUDE_CODE_SYSTEM_PROMPT}\n${normalized}`;
  }

  if (Array.isArray(system)) {
    const normalizedBlocks = system.map((block) => {
      if (block?.type === "text" && typeof block.text === "string") {
        return { ...block, text: normalizeText(block.text) };
      }
      return block;
    });

    const firstBlock = normalizedBlocks[0];
    if (
      firstBlock?.type === "text" &&
      typeof firstBlock.text === "string" &&
      firstBlock.text.startsWith(CLAUDE_CODE_SYSTEM_PROMPT)
    ) {
      return normalizedBlocks;
    }

    return [{ type: "text", text: CLAUDE_CODE_SYSTEM_PROMPT }, ...normalizedBlocks];
  }

  return system;
};

const transformMessages = (messages, mapToolName) => {
  const toolCallIdMap = new Map();

  const transformed = messages.map((message) => {
    if (!message || typeof message !== "object") return message;

    const content = message.content;
    if (typeof content === "string") {
      return { ...message, content: normalizeText(content) };
    }

    if (!Array.isArray(content)) return message;

    const normalizedBlocks = content.flatMap((block) => {
      if (!block || typeof block !== "object") return [block];

      if (block.type === "text") {
        return [{ ...block, text: normalizeText(block.text ?? "") }];
      }

      if (block.type === "thinking") {
        const thinkingText = normalizeThinkingText(block.thinking ?? "");
        if (!thinkingText.trim()) return [];
        return [{ type: "text", text: thinkingText }];
      }

      if (block.type === "tool_use") {
        const rawId = String(block.id ?? "");
        const normalizedId = sanitizeToolCallId(normalizeToolCallId(rawId));
        if (rawId && normalizedId && rawId !== normalizedId) {
          toolCallIdMap.set(rawId, normalizedId);
        }
        return [
          {
            ...block,
            id: normalizedId || rawId,
            name: mapToolName(block.name),
          },
        ];
      }

      if (block.type === "tool_result") {
        const rawToolUseId = String(block.tool_use_id ?? "");
        const mappedToolUseId = toolCallIdMap.get(rawToolUseId) ?? rawToolUseId;
        const normalizedToolUseId = sanitizeToolCallId(
          normalizeToolCallId(mappedToolUseId),
        );
        return [
          {
            ...block,
            tool_use_id: normalizedToolUseId || mappedToolUseId,
            content: normalizeContentBlocks(block.content),
          },
        ];
      }

      if (block.type === "image") {
        return [block];
      }

      return [block];
    });

    if (hasImageOnlyContent(normalizedBlocks)) {
      normalizedBlocks.unshift({ type: "text", text: "(see attached image)" });
    }

    return { ...message, content: normalizedBlocks };
  });

  const result = [];
  let pendingToolCalls = [];
  let existingToolResultIds = new Set();

  for (const message of transformed) {
    if (message?.role === "assistant") {
      if (pendingToolCalls.length > 0) {
        const missingResults = pendingToolCalls.filter(
          (toolCall) => !existingToolResultIds.has(toolCall.id),
        );
        if (missingResults.length > 0) {
          result.push({
            role: "user",
            content: missingResults.map((toolCall) => ({
              type: "tool_result",
              tool_use_id: toolCall.id,
              content: [{ type: "text", text: "No result provided" }],
              is_error: true,
            })),
          });
        }
      }

      const toolCalls = Array.isArray(message.content)
        ? message.content.filter((block) => block?.type === "tool_use")
        : [];

      pendingToolCalls = toolCalls.map((toolCall) => ({
        id: toolCall.id,
        name: toolCall.name,
      }));
      existingToolResultIds = new Set();

      result.push(message);
      continue;
    }

    if (message?.role === "user") {
      const toolResultIds = Array.isArray(message.content)
        ? message.content
            .filter((block) => block?.type === "tool_result")
            .map((block) => block.tool_use_id)
            .filter(Boolean)
        : [];

      if (toolResultIds.length > 0) {
        toolResultIds.forEach((toolUseId) => existingToolResultIds.add(toolUseId));
        result.push(message);
        continue;
      }

      if (pendingToolCalls.length > 0) {
        const missingResults = pendingToolCalls.filter(
          (toolCall) => !existingToolResultIds.has(toolCall.id),
        );
        if (missingResults.length > 0) {
          result.push({
            role: "user",
            content: missingResults.map((toolCall) => ({
              type: "tool_result",
              tool_use_id: toolCall.id,
              content: [{ type: "text", text: "No result provided" }],
              is_error: true,
            })),
          });
        }
        pendingToolCalls = [];
        existingToolResultIds = new Set();
      }

      result.push(message);
      continue;
    }

    result.push(message);
  }

  if (pendingToolCalls.length > 0) {
    const missingResults = pendingToolCalls.filter(
      (toolCall) => !existingToolResultIds.has(toolCall.id),
    );
    if (missingResults.length > 0) {
      result.push({
        role: "user",
        content: missingResults.map((toolCall) => ({
          type: "tool_result",
          tool_use_id: toolCall.id,
          content: [{ type: "text", text: "No result provided" }],
          is_error: true,
        })),
      });
    }
  }

  return result;
};

/**
 * @param {"max" | "console"} mode
 */
async function authorize(mode) {
  const pkce = await generatePKCE();

  const url = new URL(
    `https://${mode === "console" ? "console.anthropic.com" : "claude.ai"}/oauth/authorize`,
    import.meta.url,
  );
  url.searchParams.set("code", "true");
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("response_type", "code");
  url.searchParams.set(
    "redirect_uri",
    "https://console.anthropic.com/oauth/code/callback",
  );
  url.searchParams.set(
    "scope",
    "org:create_api_key user:profile user:inference",
  );
  url.searchParams.set("code_challenge", pkce.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", pkce.verifier);
  return {
    url: url.toString(),
    verifier: pkce.verifier,
  };
}

/**
 * @param {string} code
 * @param {string} verifier
 */
async function exchange(code, verifier) {
  const splits = code.split("#");
  const result = await fetch("https://console.anthropic.com/v1/oauth/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      code: splits[0],
      state: splits[1],
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      redirect_uri: "https://console.anthropic.com/oauth/code/callback",
      code_verifier: verifier,
    }),
  });
  if (!result.ok)
    return {
      type: "failed",
    };
  const json = await result.json();
  return {
    type: "success",
    refresh: json.refresh_token,
    access: json.access_token,
    expires: Date.now() + json.expires_in * 1000,
  };
}

/**
 * @type {import('@opencode-ai/plugin').Plugin}
 */
export async function AnthropicAuthPlugin({ client }) {
  return {
    auth: {
      provider: "anthropic",
      async loader(getAuth, provider) {
        const auth = await getAuth();
        if (auth.type === "oauth") {
          // zero out cost for max plan
          for (const model of Object.values(provider.models)) {
            model.cost = {
              input: 0,
              output: 0,
              cache: {
                read: 0,
                write: 0,
              },
            };
          }
          return {
            apiKey: "",
            /**
             * @param {any} input
             * @param {any} init
             */
            async fetch(input, init) {
              const auth = await getAuth();
              if (auth.type !== "oauth") return fetch(input, init);
              if (!auth.access || auth.expires < Date.now()) {
                const response = await fetch(
                  "https://console.anthropic.com/v1/oauth/token",
                  {
                    method: "POST",
                    headers: {
                      "Content-Type": "application/json",
                    },
                    body: JSON.stringify({
                      grant_type: "refresh_token",
                      refresh_token: auth.refresh,
                      client_id: CLIENT_ID,
                    }),
                  },
                );
                if (!response.ok) {
                  throw new Error(`Token refresh failed: ${response.status}`);
                }
                const json = await response.json();
                await client.auth.set({
                  path: {
                    id: "anthropic",
                  },
                  body: {
                    type: "oauth",
                    refresh: json.refresh_token,
                    access: json.access_token,
                    expires: Date.now() + json.expires_in * 1000,
                  },
                });
                auth.access = json.access_token;
              }
              const requestInit = init ?? {};

              const requestHeaders = new Headers();
              if (input instanceof Request) {
                input.headers.forEach((value, key) => {
                  requestHeaders.set(key, value);
                });
              }
              if (requestInit.headers) {
                if (requestInit.headers instanceof Headers) {
                  requestInit.headers.forEach((value, key) => {
                    requestHeaders.set(key, value);
                  });
                } else if (Array.isArray(requestInit.headers)) {
                  for (const [key, value] of requestInit.headers) {
                    if (typeof value !== "undefined") {
                      requestHeaders.set(key, String(value));
                    }
                  }
                } else {
                  for (const [key, value] of Object.entries(requestInit.headers)) {
                    if (typeof value !== "undefined") {
                      requestHeaders.set(key, String(value));
                    }
                  }
                }
              }

              const isOAuthToken = auth.access?.includes("sk-ant-oat");
              const incomingBeta = requestHeaders.get("anthropic-beta") || "";
              const incomingBetasList = incomingBeta
                .split(",")
                .map((b) => b.trim())
                .filter(Boolean);

              const mergedBetas = Array.from(
                new Set([
                  ...(isOAuthToken ? CLAUDE_CODE_BETAS : []),
                  ...incomingBetasList,
                ]),
              ).join(",");

              requestHeaders.set("authorization", `Bearer ${auth.access}`);
              requestHeaders.set("anthropic-beta", mergedBetas);
              if (isOAuthToken) {
                requestHeaders.set(
                  "user-agent",
                  `claude-cli/${CLAUDE_CODE_VERSION} (external, cli)`,
                );
                requestHeaders.set("x-app", "cli");
              }
              requestHeaders.delete("x-api-key");

              const reverseToolNameMap = new Map();
              const mapToolName = (name) => {
                if (!isOAuthToken || !name) return name;
                const mapped = toClaudeCodeName(name);
                if (!reverseToolNameMap.has(mapped) && mapped !== name) {
                  reverseToolNameMap.set(mapped, name);
                }
                return mapped;
              };

              let body = requestInit.body;
              if (body && typeof body === "string") {
                try {
                  const parsed = JSON.parse(body);

                  if (isOAuthToken) {
                    parsed.system = injectClaudeCodeSystemPrompt(parsed.system);
                  } else if (typeof parsed.system === "string") {
                    parsed.system = normalizeText(parsed.system);
                  } else if (Array.isArray(parsed.system)) {
                    parsed.system = parsed.system.map((block) => {
                      if (block?.type === "text" && typeof block.text === "string") {
                        return { ...block, text: normalizeText(block.text) };
                      }
                      return block;
                    });
                  }

                  if (parsed.tools && Array.isArray(parsed.tools)) {
                    parsed.tools = parsed.tools.map((tool) => ({
                      ...tool,
                      name: tool.name ? mapToolName(tool.name) : tool.name,
                    }));
                  }

                  if (
                    parsed.tool_choice &&
                    typeof parsed.tool_choice === "object" &&
                    parsed.tool_choice.type === "tool" &&
                    parsed.tool_choice.name
                  ) {
                    parsed.tool_choice = {
                      ...parsed.tool_choice,
                      name: mapToolName(parsed.tool_choice.name),
                    };
                  }

                  if (parsed.messages && Array.isArray(parsed.messages)) {
                    parsed.messages = transformMessages(parsed.messages, mapToolName);
                  }

                  body = JSON.stringify(parsed);
                } catch (e) {
                  // ignore parse errors
                }
              }

              let requestInput = input;
              let requestUrl = null;
              try {
                if (typeof input === "string" || input instanceof URL) {
                  requestUrl = new URL(input.toString());
                } else if (input instanceof Request) {
                  requestUrl = new URL(input.url);
                }
              } catch {
                requestUrl = null;
              }

              if (
                requestUrl &&
                requestUrl.pathname === "/v1/messages" &&
                !requestUrl.searchParams.has("beta")
              ) {
                requestUrl.searchParams.set("beta", "true");
                requestInput =
                  input instanceof Request
                    ? new Request(requestUrl.toString(), input)
                    : requestUrl;
              }

              const response = await fetch(requestInput, {
                ...requestInit,
                body,
                headers: requestHeaders,
              });

              // Transform streaming response to rename tools back
              if (response.body) {
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                const encoder = new TextEncoder();

                const stream = new ReadableStream({
                  async pull(controller) {
                    const { done, value } = await reader.read();
                    if (done) {
                      controller.close();
                      return;
                    }

                    let text = decoder.decode(value, { stream: true });
                    if (isOAuthToken) {
                      text = text.replace(
                        /("name"\s*:\s*")([^"]+)(")/g,
                        (match, prefix, name, suffix) => {
                          const mapped = fromClaudeCodeName(name, reverseToolNameMap);
                          if (mapped === name) return match;
                          return `${prefix}${mapped}${suffix}`;
                        },
                      );
                    }
                    controller.enqueue(encoder.encode(text));
                  },
                });

                return new Response(stream, {
                  status: response.status,
                  statusText: response.statusText,
                  headers: response.headers,
                });
              }

              return response;
            },
          };
        }

        return {};
      },
      methods: [
        {
          label: "Claude Pro/Max",
          type: "oauth",
          authorize: async () => {
            const { url, verifier } = await authorize("max");
            return {
              url: url,
              instructions: "Paste the authorization code here: ",
              method: "code",
              callback: async (code) => {
                const credentials = await exchange(code, verifier);
                return credentials;
              },
            };
          },
        },
        {
          label: "Create an API Key",
          type: "oauth",
          authorize: async () => {
            const { url, verifier } = await authorize("console");
            return {
              url: url,
              instructions: "Paste the authorization code here: ",
              method: "code",
              callback: async (code) => {
                const credentials = await exchange(code, verifier);
                if (credentials.type === "failed") return credentials;
                const result = await fetch(
                  `https://api.anthropic.com/api/oauth/claude_cli/create_api_key`,
                  {
                    method: "POST",
                    headers: {
                      "Content-Type": "application/json",
                      authorization: `Bearer ${credentials.access}`,
                    },
                  },
                ).then((r) => r.json());
                return { type: "success", key: result.raw_key };
              },
            };
          },
        },
        {
          provider: "anthropic",
          label: "Manually enter API Key",
          type: "api",
        },
      ],
    },
  };
}
