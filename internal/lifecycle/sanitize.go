package lifecycle

import (
	"regexp"
	"strings"
)

const syntheticCanary = "SYNTHETIC_CANARY_DO_NOT_EMIT_184"

var secretPattern = regexp.MustCompile(`(?i)(secret|token|password)[=:][^\s,;]+`)

func sanitizeMap(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}
	return sanitize(input).(map[string]any)
}

func sanitize(value any) any {
	switch typed := value.(type) {
	case string:
		withoutCanary := strings.ReplaceAll(typed, syntheticCanary, "[REDACTED]")
		return secretPattern.ReplaceAllString(withoutCanary, "[REDACTED]")
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[key] = sanitize(item)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = sanitize(item)
		}
		return result
	case []string:
		result := make([]string, len(typed))
		for index, item := range typed {
			result[index] = sanitize(item).(string)
		}
		return result
	default:
		return value
	}
}
