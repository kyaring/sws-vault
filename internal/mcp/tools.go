package mcp

func Tools() []map[string]any {
	return []map[string]any{{"name": "vault_list", "description": "List secret metadata", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"ns": map[string]string{"type": "string"}}}}, {"name": "vault_fetch", "description": "Fetch a bound remote resource", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"secret": map[string]string{"type": "string"}, "url": map[string]string{"type": "string"}, "method": map[string]string{"type": "string"}, "headers": map[string]any{"type": "object", "additionalProperties": map[string]string{"type": "string"}}, "body": map[string]string{"type": "string"}}}}, {"name": "vault_intent", "description": "Create one-time entry intent", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"label": map[string]string{"type": "string"}}, "required": []string{"label"}}}}
}
