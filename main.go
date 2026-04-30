package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

type Finding struct {
	Message  string
	Count    int
	Severity string
}

func getSeverity(count int) string {
	if count >= 10 {
		return "CRITICAL"
	}

	if count >= 5 {
		return "HIGH"
	}

	if count >= 2 {
		return "MEDIUM"
	}

	return "LOW"
}

func isSecuritySignal(line string) bool {
	return strings.Contains(line, "login failed") ||
		strings.Contains(line, "invalid credentials") ||
		strings.Contains(line, "authentication failed") ||
		strings.Contains(line, "unauthorized") ||
		strings.Contains(line, "forbidden") ||
		strings.Contains(line, "access denied") ||
		strings.Contains(line, "invalid token") ||
		strings.Contains(line, "expired token")
}

func mapToSortedSlice(m map[string]int) []Finding {
	var findings []Finding

	for msg, count := range m {
		findings = append(findings, Finding{
			Message:  msg,
			Count:    count,
			Severity: getSeverity(count),
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Count > findings[j].Count
	})

	return findings
}

func main() {
	args := os.Args

	// Comprobamos que haya al menos 2 argumentos
	if len(args) < 2 {
		fmt.Println("Usage: appsentinel <command> [file]")
		return
	}

	command := args[1]

	// Comprobamos que comando introduce
	if command == "analyze" {

		// Comprobamos que haya al menos 3 argumentos (comando completo)
		if len(args) < 3 {
			fmt.Println("Usage: appsentinel analyze <file>")
			return
		}

		filepath := args[2]

		file, err := os.Open(filepath)

		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}

		defer file.Close()

		scanner := bufio.NewScanner(file)

		errorMap := make(map[string]int)
		warningMap := make(map[string]int)
		securityMap := make(map[string]int)

		for scanner.Scan() {
			line := scanner.Text()
			lowerLine := strings.ToLower(line)

			// PRIORIDAD 1: SECURITY
			if isSecuritySignal(lowerLine) {
				securityMap[line]++
				continue
			}

			// PRIORIDAD 2: ERROR
			if strings.Contains(line, "ERROR") {
				errorMap[line]++
				continue
			}

			// PRIORIDAD 3: WARNING
			if strings.Contains(line, "WARN") {
				warningMap[line]++
				continue
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading file:", err)
			return
		}

		// OUTPUT
		fmt.Println("\nAppSentinel Report")
		fmt.Println("------------------")

		fmt.Println("\nCRITICAL")
		errorFindings := mapToSortedSlice(errorMap)
		for _, f := range errorFindings {
			fmt.Printf("- [%s] %dx %s\n", f.Severity, f.Count, f.Message)
		}

		fmt.Println("\nWARNING")
		warnFindings := mapToSortedSlice(warningMap)
		for _, f := range warnFindings {
			fmt.Printf("- [%s] %dx %s\n", f.Severity, f.Count, f.Message)
		}

		fmt.Println("\nSECURITY")
		secFindings := mapToSortedSlice(securityMap)
		for _, f := range secFindings {
			fmt.Printf("- [%s] %dx %s\n\n", f.Severity, f.Count, f.Message)
		}

		return
	}

	fmt.Println("Unknown command:", command)

}
