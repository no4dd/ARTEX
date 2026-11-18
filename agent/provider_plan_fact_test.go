package agent

import "testing"

func TestPlanSingleFactToolRemovesBatchField(t *testing.T) {
	params := map[string]any{
		"properties": map[string]any{"summary": map[string]any{"type": "string"}, "facts": map[string]any{"type": "array"}},
		"required":   []any{"summary", "facts"},
	}
	tool := map[string]any{"name": "record_fact", "parameters": params}
	planSingleFactTool(tool)
	if _, exists := params["properties"].(map[string]any)["facts"]; exists {
		t.Fatal("batch field still available to strict plan tool")
	}
	required := params["required"].([]any)
	if len(required) != 1 || required[0] != "summary" {
		t.Fatalf("batch field still required: %v", required)
	}
}
