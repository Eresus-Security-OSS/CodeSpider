// Package llm provides an OpenAI-compatible chat completions client with tool calling.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client calls any OpenAI-compatible /v1/chat/completions endpoint.
type Client struct {
	baseURL    string
	apiKey     string
	model      string
	httpClient *http.Client
}

// NewClient creates a new LLM client.
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
	}
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(raw))
	if err != nil {
		return ChatResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ChatResponse{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return ChatResponse{}, err
	}
	if resp.StatusCode >= 300 {
		return ChatResponse{}, fmt.Errorf("llm %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var parsed chatCompletionResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ChatResponse{}, fmt.Errorf("decode llm response: %w", err)
	}
	if parsed.Error != nil {
		return ChatResponse{}, fmt.Errorf("llm error: %s", parsed.Error.Message)
	}
	if len(parsed.Choices) == 0 {
		return ChatResponse{}, fmt.Errorf("llm returned zero choices")
	}

	return ChatResponse{
		Message: parsed.Choices[0].Message,
		Usage:   parsed.Usage,
	}, nil
}
