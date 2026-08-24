package mcp

import "encoding/json"

// Implementation describes the name and version of an MCP client or server
type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ClientCapabilities represents the features supported by an MCP client
type ClientCapabilities struct {
	Experimental map[string]any `json:"experimental,omitempty"`
	Sampling     map[string]any `json:"sampling,omitempty"`
	Roots        map[string]any `json:"roots,omitempty"`
}

// ServerCapabilities represents the features supported by an MCP server
type ServerCapabilities struct {
	Experimental map[string]any       `json:"experimental,omitempty"`
	Logging      map[string]any       `json:"logging,omitempty"`
	Prompts      *PromptsCapability   `json:"prompts,omitempty"`
	Resources    *ResourcesCapability `json:"resources,omitempty"`
	Tools        *ToolsCapability     `json:"tools,omitempty"`
}

// ToolsCapability indicates support for tool invocation
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// PromptsCapability indicates support for prompt templates
type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ResourcesCapability indicates support for readable resources
type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

// InitializeParams is sent by the client in the "initialize" request
type InitializeParams struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      Implementation     `json:"clientInfo"`
}

// InitializeResult is returned by the server for the "initialize" request
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      Implementation     `json:"serverInfo"`
	Instructions    string             `json:"instructions,omitempty"`
}

// Tool represents a tool executable by an MCP server
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema ToolInputSchema `json:"inputSchema"`
}

// ToolInputSchema describes JSON schema constraints for tool parameters
type ToolInputSchema struct {
	Type                 string                 `json:"type"`
	Properties           map[string]any         `json:"properties,omitempty"`
	Required             []string               `json:"required,omitempty"`
	AdditionalProperties any                    `json:"additionalProperties,omitempty"`
	Definitions          map[string]any         `json:"definitions,omitempty"`
	Description          string                 `json:"description,omitempty"`
	Extra                map[string]interface{} `json:"-"`
}

// ListToolsParams specifies optional pagination for tools/list
type ListToolsParams struct {
	Cursor string `json:"cursor,omitempty"`
}

// ListToolsResult contains the list of tools available on the server
type ListToolsResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

// CallToolParams contains arguments when invoking a tool
type CallToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// Content represents polymorphic output content items (text, image, resource)
type Content struct {
	Type     string          `json:"type"` // "text", "image", "resource"
	Text     string          `json:"text,omitempty"`
	Data     string          `json:"data,omitempty"`     // Base64 for images
	MIMEType string          `json:"mimeType,omitempty"` // For images or resources
	Resource json.RawMessage `json:"resource,omitempty"`
}

// NewTextContent helper constructor
func NewTextContent(text string) Content {
	return Content{
		Type: "text",
		Text: text,
	}
}

// CallToolResult contains the tool execution output
type CallToolResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// Resource represents a readable piece of data exposed by the server
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

// ListResourcesParams pagination parameters for resources/list
type ListResourcesParams struct {
	Cursor string `json:"cursor,omitempty"`
}

// ListResourcesResult contains available resources
type ListResourcesResult struct {
	Resources  []Resource `json:"resources"`
	NextCursor string     `json:"nextCursor,omitempty"`
}

// ReadResourceParams specifies the resource to read
type ReadResourceParams struct {
	URI string `json:"uri"`
}

// ResourceContent contains the contents of a read resource
type ResourceContent struct {
	URI      string `json:"uri"`
	MIMEType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"` // Base64
}

// ReadResourceResult returns content of requested resources
type ReadResourceResult struct {
	Contents []ResourceContent `json:"contents"`
}

// Prompt represents a prompt template available on the server
type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

// PromptArgument describes an input parameter for a prompt template
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// ListPromptsParams pagination for prompts/list
type ListPromptsParams struct {
	Cursor string `json:"cursor,omitempty"`
}

// ListPromptsResult contains available prompts
type ListPromptsResult struct {
	Prompts    []Prompt `json:"prompts"`
	NextCursor string   `json:"nextCursor,omitempty"`
}

// GetPromptParams specifies parameters when fetching a prompt
type GetPromptParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

// PromptMessage contains role and content for a prompt
type PromptMessage struct {
	Role    string  `json:"role"` // "user" or "assistant"
	Content Content `json:"content"`
}

// GetPromptResult contains the rendered prompt messages
type GetPromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}
