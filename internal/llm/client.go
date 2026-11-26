// Package llm provides an OpenAI-compatible chat completions client with tool calling.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Client calls any OpenAI-compatible /v1/chat/completions endpoint.
type Client struct {
	baseURL        string
	apiKey         string
	model          string
	httpClient     *http.Client
	maxRetries     int
	retryBaseDelay time.Duration
}

// NewClient creates a new LLM client with default retry settings.
func NewClient(baseURL, apiKey, model string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		model:   model,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		maxRetries:     2,
		retryBaseDelay: time.Second,
	}
}

// WithRetry configures retry count and base backoff delay for transient failures.
func (c *Client) WithRetry(maxRetries int, baseDelay time.Duration) *Client {
	if maxRetries < 0 {
		maxRetries = 0
	}
	c.maxRetries = maxRetries
	if baseDelay > 0 {
		c.retryBaseDelay = baseDelay
	}
	return c
}

// Model returns the configured model name.
func (c *Client) Model() string {
	return c.model
}

// WithModel returns a shallow copy of Client configured with model (or c if empty/unchanged).
func (c *Client) WithModel(model string) *Client {
	model = strings.TrimSpace(model)
	if model == "" || model == c.model {
		return c
	}
	cp := *c
	cp.model = model
	return &cp
}

// Message represents a single chat message in a conversation.
type Message struct {
	Role       string     `json:"role"` // system, user, assistant, tool
	Content    string     `json:"content,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
}

// ToolCall represents a function call requested by the model.
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

// FunctionCall holds the function name and raw JSON arguments.
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ToolDefinition describes a callable tool passed to the model.
type ToolDefinition struct {
	Type     string             `json:"type"`
	Function FunctionDefinition `json:"function"`
}

// FunctionDefinition describes a tool's name, purpose, and JSON Schema parameters.
type FunctionDefinition struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Parameters  any    `json:"parameters"`
}

// Usage captures token consumption returned by the LLM provider.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ChatResponse holds the assistant message and token usage.
type ChatResponse struct {
	Message Message
	Usage   Usage
}

type chatRequest struct {
	Model    string           `json:"model"`
	Messages []Message        `json:"messages"`
	Tools    []ToolDefinition `json:"tools,omitempty"`
}

type chatCompletionResponse struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
	Usage Usage `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Chat sends a conversation and tool definitions to the LLM and returns the next assistant turn.
func (c *Client) Chat(ctx context.Context, messages []Message, tools []ToolDefinition) (ChatResponse, error) {
	reqBody := chatRequest{
		Model:    c.model,
		Messages: messages,
		Tools:    tools,
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return ChatResponse{}, err
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if ctx.Err() != nil {
			return ChatResponse{}, ctx.Err()
		}
		chatResp, retryAfter, retryable, callErr := c.doOnce(ctx, raw)
		if callErr == nil {
			return chatResp, nil
		}
		lastErr = callErr
		if !retryable || attempt == c.maxRetries {
			break
		}

		delay := c.retryBaseDelay * time.Duration(1<<attempt)
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
		if retryAfter > 0 {
			delay = retryAfter
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ChatResponse{}, ctx.Err()
		case <-timer.C:
		}
	}
	return ChatResponse{}, lastErr
}

func (c *Client) doOnce(ctx context.Context, raw []byte) (ChatResponse, time.Duration, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(raw))
	if err != nil {
		return ChatResponse{}, 0, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		retryable := ctx.Err() == nil
		return ChatResponse{}, 0, retryable, c.redactErr(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return ChatResponse{}, 0, true, c.redactErr(err)
	}
	if resp.StatusCode >= 300 {
		retryable := isRetryableStatus(resp.StatusCode)
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		msg := c.redactString(strings.TrimSpace(string(body)))
		return ChatResponse{}, retryAfter, retryable, fmt.Errorf("llm %s: %s", resp.Status, msg)
	}

	var parsed chatCompletionResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ChatResponse{}, 0, false, fmt.Errorf("decode llm response: %w", err)
	}
	if parsed.Error != nil {
		return ChatResponse{}, 0, false, fmt.Errorf("llm error: %s", c.redactString(parsed.Error.Message))
	}
	if len(parsed.Choices) == 0 {
		return ChatResponse{}, 0, false, fmt.Errorf("llm returned zero choices")
	}

	return ChatResponse{
		Message: parsed.Choices[0].Message,
		Usage:   parsed.Usage,
	}, 0, false, nil
}

func isRetryableStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func parseRetryAfter(val string) time.Duration {
	val = strings.TrimSpace(val)
	if val == "" {
		return 0
	}
	secs, err := strconv.Atoi(val)
	if err != nil || secs <= 0 {
		return 0
	}
	if secs > 15 {
		secs = 15
	}
	return time.Duration(secs) * time.Second
}

func (c *Client) redactErr(err error) error {
	if err == nil || c.apiKey == "" {
		return err
	}
	return fmt.Errorf("%s", c.redactString(err.Error()))
}

func (c *Client) redactString(s string) string {
	if c.apiKey == "" {
		return s
	}
	return strings.ReplaceAll(s, c.apiKey, "[REDACTED]")
}
