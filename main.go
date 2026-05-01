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

type Incident struct {
	Title       string
	Description string
	Severity    string
}

func deduplicateIncidents(incidents []Incident) []Incident {
	var result []Incident
	seen := make(map[string]bool)

	for _, inc := range incidents {
		key := inc.Title

		if !seen[key] {
			result = append(result, inc)
			seen[key] = true
		}
	}

	return result
}

func detectMixedRisk(errorFindings []Finding, securityFindings []Finding) []Incident {
	if len(errorFindings) > 0 && len(securityFindings) > 0 {
		return []Incident{
			{
				Title:       "Multiple issue categories detected",
				Description: "application errors and security signals were found together",
				Severity:    "HIGH",
			},
		}
	}

	return nil
}

func detectErrorSpike(errorFindings []Finding) []Incident {
	totalErrors := 0

	for _, f := range errorFindings {
		totalErrors += f.Count
	}

	if totalErrors >= 10 {
		return []Incident{
			{
				Title:       "Application error spike",
				Description: fmt.Sprintf("%d total errors detected", totalErrors),
				Severity:    "CRITICAL",
			},
		}
	}

	return nil
}

func detectErrorBurst(errorFindings []Finding) []Incident {
	var incidents []Incident

	for _, f := range errorFindings {
		if f.Count >= 5 {
			incidents = append(incidents, Incident{
				Title:       "Repeated application error",
				Description: fmt.Sprintf("%dx %s", f.Count, f.Message),
				Severity:    "HIGH",
			})
		}
	}

	return incidents
}

func detectAggregatedBruteForce(securityFindings []Finding) []Incident {
	totalFailedLogins := 0
	distinctFailedLoginMessages := 0

	for _, f := range securityFindings {
		lower := strings.ToLower(f.Message)

		if strings.Contains(lower, "login failed") {
			totalFailedLogins += f.Count
			distinctFailedLoginMessages++
		}
	}

	if totalFailedLogins >= 5 && distinctFailedLoginMessages >= 2 {
		return []Incident{
			{
				Title:       "Aggregated brute force pattern",
				Description: fmt.Sprintf("%d failed login attempts across %d different log entries", totalFailedLogins, distinctFailedLoginMessages),
				Severity:    "HIGH",
			},
		}
	}

	return nil
}

func detectBruteForce(securityFindings []Finding) []Incident {
	var incidents []Incident

	for _, f := range securityFindings {
		lower := strings.ToLower(f.Message)

		if strings.Contains(lower, "login failed") && f.Count >= 5 {
			incidents = append(incidents, Incident{
				Title:       "Possible brute force attack",
				Description: fmt.Sprintf("%dx %s", f.Count, f.Message),
				Severity:    "HIGH",
			})
		}
	}

	return incidents
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
		errorFindings := mapToSortedSlice(errorMap)
		warnFindings := mapToSortedSlice(warningMap)
		secFindings := mapToSortedSlice(securityMap)

		incidents := []Incident{}
		incidents = append(incidents, detectErrorBurst(errorFindings)...)
		incidents = append(incidents, detectBruteForce(secFindings)...)
		incidents = append(incidents, detectAggregatedBruteForce(secFindings)...)
		incidents = append(incidents, detectErrorSpike(errorFindings)...)
		incidents = append(incidents, detectMixedRisk(errorFindings, secFindings)...)
		incidents = deduplicateIncidents(incidents)

		fmt.Println("\nAppSentinel Report")
		fmt.Println("------------------")

		fmt.Println("\nCRITICAL")
		for _, f := range errorFindings {
			fmt.Printf("- [%s] %dx %s\n", f.Severity, f.Count, f.Message)
		}

		fmt.Println("\nWARNING")
		for _, f := range warnFindings {
			fmt.Printf("- [%s] %dx %s\n", f.Severity, f.Count, f.Message)
		}

		fmt.Println("\nSECURITY")
		for _, f := range secFindings {
			fmt.Printf("- [%s] %dx %s\n", f.Severity, f.Count, f.Message)
		}

		fmt.Println("\nINCIDENTS")
		if len(incidents) == 0 {
			fmt.Println("- No incidents detected")
		} else {
			for _, incident := range incidents {
				fmt.Printf("- [%s] %s: %s\n", incident.Severity, incident.Title, incident.Description)
			}
		}

		return
	}

	fmt.Println("Unknown command:", command)

}
