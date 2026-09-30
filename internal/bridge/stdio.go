package bridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const maxMCPMessage = 2 << 20
const Version = "1.0.2"

type requestEnvelope struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type stdioState struct {
	version            string
	clientCapabilities any
	clientInfo         any
}

func (c *Client) ServeStdio(ctx context.Context, input io.Reader, output io.Writer) error {
	if _, err := c.ActiveSession(ctx); err != nil {
		return err
	}
	state := stdioState{version: "2025-06-18", clientCapabilities: map[string]any{}, clientInfo: map[string]any{"name": "hostwatch-go-mcp", "version": Version}}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), maxMCPMessage)
	writer := bufio.NewWriter(output)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var envelope requestEnvelope
		if err := json.Unmarshal(line, &envelope); err != nil || envelope.Method == "" {
			continue
		}
		if envelope.Method == "initialize" {
			var params struct {
				ProtocolVersion string `json:"protocolVersion"`
				Capabilities    any    `json:"capabilities"`
				ClientInfo      any    `json:"clientInfo"`
			}
			if json.Unmarshal(envelope.Params, &params) == nil {
				if params.ProtocolVersion != "" {
					state.version = params.ProtocolVersion
				}
				if params.Capabilities != nil {
					state.clientCapabilities = params.Capabilities
				}
				if params.ClientInfo != nil {
					state.clientInfo = params.ClientInfo
				}
			}
		}
		payload := append([]byte(nil), line...)
		if state.version == "2026-07-28" {
			var err error
			payload, err = addModernMetadata(payload, state)
			if err != nil {
				writeMCPError(writer, envelope.ID, "Invalid MCP request")
				continue
			}
		}
		messages, err := c.forward(ctx, payload, envelope, state.version)
		if err != nil {
			writeMCPError(writer, envelope.ID, err.Error())
			continue
		}
		if envelope.Method == "initialize" && len(messages) > 0 {
			var reply struct {
				Result struct {
					ProtocolVersion string `json:"protocolVersion"`
				} `json:"result"`
			}
			if json.Unmarshal(messages[0], &reply) == nil && reply.Result.ProtocolVersion != "" {
				state.version = reply.Result.ProtocolVersion
			}
		}
		for _, message := range messages {
			if _, err := writer.Write(message); err != nil {
				return err
			}
			if err := writer.WriteByte('\n'); err != nil {
				return err
			}
		}
		if err := writer.Flush(); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func addModernMetadata(raw []byte, state stdioState) ([]byte, error) {
	var message map[string]any
	if err := json.Unmarshal(raw, &message); err != nil {
		return nil, err
	}
	params, _ := message["params"].(map[string]any)
	if params == nil {
		params = map[string]any{}
	}
	meta, _ := params["_meta"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	meta["io.modelcontextprotocol/protocolVersion"] = state.version
	meta["io.modelcontextprotocol/clientCapabilities"] = state.clientCapabilities
	meta["io.modelcontextprotocol/clientInfo"] = state.clientInfo
	params["_meta"] = meta
	message["params"] = params
	return json.Marshal(message)
}

func writeMCPError(writer *bufio.Writer, id json.RawMessage, message string) {
	if len(id) == 0 {
		return
	}
	result, _ := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: id, Error: struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{Code: -32000, Message: message}})
	_, _ = writer.Write(result)
	_ = writer.WriteByte('\n')
	_ = writer.Flush()
}

func (c *Client) forward(ctx context.Context, payload []byte, envelope requestEnvelope, version string) ([][]byte, error) {
	session, err := c.ActiveSession(ctx)
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		response, err := c.postMCP(ctx, payload, envelope, version, session.AccessToken)
		if err != nil {
			return nil, err
		}
		if response.StatusCode == http.StatusUnauthorized && attempt == 0 {
			response.Body.Close()
			session, err = c.Refresh(ctx, session)
			if err != nil {
				return nil, err
			}
			continue
		}
		defer response.Body.Close()
		if response.StatusCode == http.StatusAccepted || response.StatusCode == http.StatusNoContent {
			return nil, nil
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return nil, fmt.Errorf("Hostwatch MCP HTTP %d", response.StatusCode)
		}
		if strings.Contains(response.Header.Get("Content-Type"), "text/event-stream") {
			return readSSE(response.Body)
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, maxMCPMessage+1))
		if err != nil {
			return nil, err
		}
		if len(data) > maxMCPMessage {
			return nil, errors.New("Hostwatch MCP response is too large")
		}
		data = bytes.TrimSpace(data)
		if len(data) == 0 {
			return nil, nil
		}
		if !json.Valid(data) {
			return nil, errors.New("Hostwatch MCP response is not valid JSON")
		}
		return [][]byte{data}, nil
	}
	return nil, errors.New("Hostwatch session expired; run login")
}

func (c *Client) postMCP(ctx context.Context, payload []byte, envelope requestEnvelope, version, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Origin+"/mcp", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("MCP-Protocol-Version", version)
	if version == "2026-07-28" {
		req.Header.Set("Mcp-Method", envelope.Method)
		var params struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(envelope.Params, &params) == nil && params.Name != "" {
			req.Header.Set("Mcp-Name", params.Name)
		}
	}
	return c.HTTP.Do(req)
}

func readSSE(body io.Reader) ([][]byte, error) {
	scanner := bufio.NewScanner(io.LimitReader(body, maxMCPMessage+1))
	scanner.Buffer(make([]byte, 64*1024), maxMCPMessage)
	var messages [][]byte
	var event []string
	flush := func() error {
		if len(event) == 0 {
			return nil
		}
		data := []byte(strings.Join(event, "\n"))
		event = nil
		if bytes.Equal(data, []byte("[DONE]")) {
			return nil
		}
		if !json.Valid(data) {
			return errors.New("Hostwatch MCP SSE event is not valid JSON")
		}
		messages = append(messages, data)
		return nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if err := flush(); err != nil {
				return nil, err
			}
		} else if strings.HasPrefix(line, "data: ") {
			event = append(event, strings.TrimPrefix(line, "data: "))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return messages, nil
}
