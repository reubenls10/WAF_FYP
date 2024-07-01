package conf

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
)

// Load the entire file content
func loadFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return lines, nil
}

// Toggle rule (enable or disable)
func ToggleRule(fileName string, ruleID string, enable bool) error {
	filePath := "./coreruleset/rules/" + fileName
	lines, err := loadFile(filePath)
	if err != nil {
		return err
	}

	var buffer bytes.Buffer
	inRule := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmedLine := strings.TrimSpace(line)
		if strings.Contains(trimmedLine, "id:"+ruleID) || ((strings.HasPrefix(trimmedLine, "SecRule") || strings.HasPrefix(trimmedLine, "#SecRule")) && i+1 < len(lines) && strings.Contains(lines[i+1], "id:"+ruleID)) {
			inRule = true
		}

		if inRule {
			if enable {
				// Uncomment the line
				buffer.WriteString(strings.TrimPrefix(trimmedLine, "#") + "\n")
			} else {
				// Comment the line
				if !strings.HasPrefix(trimmedLine, "#") {
					buffer.WriteString("#" + line + "\n")
				} else {
					buffer.WriteString(line + "\n")
				}
			}
			// End the rule if it does not continue on the next line
			if !strings.HasSuffix(trimmedLine, "\\") && !strings.HasSuffix(trimmedLine, "chain\"") {
				inRule = false
			}
		} else {
			buffer.WriteString(line + "\n")
		}
	}

	return os.WriteFile(filePath, buffer.Bytes(), 0644)
}

// Toggle all rules in the group (enable or disable)
func ToggleRuleGroup(fileName string, enable bool) error {
	filePath := "./coreruleset/rules/" + fileName
	lines, err := loadFile(filePath)
	if err != nil {
		return err
	}

	var buffer bytes.Buffer
	inRule := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "SecRule") || strings.HasPrefix(trimmedLine, "#SecRule") {
			inRule = true
		}

		if inRule {
			if enable {
				// Uncomment the line
				buffer.WriteString(strings.TrimPrefix(trimmedLine, "#") + "\n")
			} else {
				// Comment the line
				if !strings.HasPrefix(trimmedLine, "#") {
					buffer.WriteString("#" + line + "\n")
				} else {
					buffer.WriteString(line + "\n")
				}
			}
			// End the rule if it does not continue on the next line
			if !strings.HasSuffix(trimmedLine, "\\") && !strings.HasSuffix(trimmedLine, "chain\"") {
				inRule = false
			}
		} else {
			buffer.WriteString(line + "\n")
		}
	}

	return os.WriteFile(filePath, buffer.Bytes(), 0644)
}

func AddCustomRule(raw_rule string) error {
	filePath := "./coreruleset/rules/CUSTOM-RULES.conf"
	
	// Open the file in append mode, create it if it doesn't exist
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Write the raw rule to the file with a newline
	if _, err := file.WriteString(raw_rule + "\n\n"); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	return nil
}