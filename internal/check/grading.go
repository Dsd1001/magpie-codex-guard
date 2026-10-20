package check

import (
	"regexp"
	"strings"
)

var numberWithUnit = regexp.MustCompile(`(?i)(?:\*\*)?(\d+(?:\.\d+)?)(?:\*\*)?\s*(?:inches|inch|英寸)`)

func Grade(id, answer string) string {
	if id != "milk" {
		return "manual"
	}
	if strings.Trim(strings.TrimSpace(answer), "*` ") == "46.24" {
		return "passed"
	}
	matches := numberWithUnit.FindAllStringSubmatch(answer, -1)
	if len(matches) > 0 && matches[len(matches)-1][1] == "46.24" {
		return "passed"
	}
	return "failed"
}
