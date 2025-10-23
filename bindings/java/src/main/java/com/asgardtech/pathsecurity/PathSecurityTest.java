package com.asgardtech.pathsecurity;

/**
 * Test class for Path Security Java bindings
 */
public class PathSecurityTest {
    
    public static void main(String[] args) {
        System.out.println("Testing Java bindings for Path Security:");
        System.out.println();
        
        PathSecurity ps = new PathSecurity();
        
        // Test ValidatePath
        String validPath = "/usr/local/bin/app";
        String invalidPath = "../../../etc/passwd";
        
        System.out.printf("Validating \"%s\": ", validPath);
        try {
            String result = ps.validatePath(validPath);
            System.out.printf("Result: %s%n", result);
        } catch (PathSecurity.PathSecurityException e) {
            System.out.printf("Error: %s%n", e.getMessage());
        }
        
        System.out.printf("Validating \"%s\": ", invalidPath);
        try {
            String result = ps.validatePath(invalidPath);
            System.out.printf("Result: %s%n", result);
        } catch (PathSecurity.PathSecurityException e) {
            System.out.printf("Error: %s%n", e.getMessage());
        }
        
        // Test DetectTraversal
        System.out.printf("%nDetecting traversal in \"%s\": ", invalidPath);
        try {
            boolean hasTraversal = ps.detectTraversal(invalidPath);
            System.out.printf("%b%n", hasTraversal);
        } catch (PathSecurity.PathSecurityException e) {
            System.out.printf("Error: %s%n", e.getMessage());
        }
        
        System.out.printf("Detecting traversal in \"%s\": ", validPath);
        try {
            boolean hasTraversal = ps.detectTraversal(validPath);
            System.out.printf("%b%n", hasTraversal);
        } catch (PathSecurity.PathSecurityException e) {
            System.out.printf("Error: %s%n", e.getMessage());
        }
        
        // Test SanitizePath
        String dirtyPath = "/var/www/html/../app/config.json";
        System.out.printf("%nSanitizing \"%s\": ", dirtyPath);
        try {
            String sanitized = ps.sanitizePath(dirtyPath);
            System.out.printf("\"%s\"%n", sanitized);
        } catch (PathSecurity.PathSecurityException e) {
            System.out.printf("Error: %s%n", e.getMessage());
        }
        
        // Test with safe path
        String safePath = "/home/user/documents/file.txt";
        System.out.printf("Sanitizing \"%s\": ", safePath);
        try {
            String sanitized = ps.sanitizePath(safePath);
            System.out.printf("\"%s\"%n", sanitized);
        } catch (PathSecurity.PathSecurityException e) {
            System.out.printf("Error: %s%n", e.getMessage());
        }
        
        // Test with complex traversal
        String complexPath = "/app/../../etc/passwd";
        System.out.printf("%nDetecting traversal in \"%s\": ", complexPath);
        try {
            boolean hasTraversal = ps.detectTraversal(complexPath);
            System.out.printf("%b%n", hasTraversal);
        } catch (PathSecurity.PathSecurityException e) {
            System.out.printf("Error: %s%n", e.getMessage());
        }
        
        System.out.printf("Sanitizing \"%s\": ", complexPath);
        try {
            String sanitized = ps.sanitizePath(complexPath);
            System.out.printf("\"%s\"%n", sanitized);
        } catch (PathSecurity.PathSecurityException e) {
            System.out.printf("Error: %s%n", e.getMessage());
        }
    }
}
