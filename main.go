package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

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
			if strings.Contains(lowerLine, "login failed") {
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
		for msg, count := range errorMap {
			fmt.Printf("- %dx %s\n", count, msg)
		}

		fmt.Println("\nWARNING")
		for msg, count := range warningMap {
			fmt.Printf("- %dx %s\n", count, msg)
		}

		fmt.Println("\nSECURITY")
		for msg, count := range securityMap {
			fmt.Printf("- %dx %s\n\n", count, msg)
		}

		return
	}

	fmt.Println("Unknown command:", command)

}
