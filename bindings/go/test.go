package main

import (
	"fmt"
)

func main() {
	fmt.Println("Testing Go bindings for Path Security:")
	fmt.Println()

	// Create PathSecurity instance
	ps := NewPathSecurity()

	// Test ValidatePath
	validPath := "/usr/local/bin/app"
	invalidPath := "../../../etc/passwd"

	fmt.Printf("Validating \"%s\": ", validPath)
	result, err := ps.ValidatePath(validPath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Result: %s\n", result)
	}

	fmt.Printf("Validating \"%s\": ", invalidPath)
	result, err = ps.ValidatePath(invalidPath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Result: %s\n", result)
	}

	// Test DetectTraversal
	fmt.Printf("\nDetecting traversal in \"%s\": ", invalidPath)
	hasTraversal, err := ps.DetectTraversal(invalidPath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("%t\n", hasTraversal)
	}

	fmt.Printf("Detecting traversal in \"%s\": ", validPath)
	hasTraversal, err = ps.DetectTraversal(validPath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("%t\n", hasTraversal)
	}

	// Test SanitizePath
	dirtyPath := "/var/www/html/../app/config.json"
	fmt.Printf("\nSanitizing \"%s\": ", dirtyPath)
	sanitized, err := ps.SanitizePath(dirtyPath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("\"%s\"\n", sanitized)
	}

	// Test with safe path
	safePath := "/home/user/documents/file.txt"
	fmt.Printf("Sanitizing \"%s\": ", safePath)
	sanitized, err = ps.SanitizePath(safePath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("\"%s\"\n", sanitized)
	}

	// Test with complex traversal
	complexPath := "/app/../../etc/passwd"
	fmt.Printf("\nDetecting traversal in \"%s\": ", complexPath)
	hasTraversal, err = ps.DetectTraversal(complexPath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("%t\n", hasTraversal)
	}

	fmt.Printf("Sanitizing \"%s\": ", complexPath)
	sanitized, err = ps.SanitizePath(complexPath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("\"%s\"\n", sanitized)
	}
}
