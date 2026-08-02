package rules

import "strings"

// lower is a small helper so rule files can compare keys case-insensitively
// without repeating the import.
func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
