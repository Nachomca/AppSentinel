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

	if command == "analyze" {
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

		errorCount := 0

		for scanner.Scan() {
			line := scanner.Text()

			if strings.Contains(line, "ERROR") {
				errorCount++
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading file:", err)
			return
		}

		fmt.Println("AppSentinel Report")
		fmt.Println("------------------")
		fmt.Println("")
		fmt.Println("Error found:", errorCount)

		return
	}

	fmt.Println("Unknown command:", command)

}
