package com.asgardtech.pathsecurity;

/**
 * Java bindings for Path Security library
 * Provides secure path validation and sanitization
 */
public class PathSecurity {
    
    static {
        System.loadLibrary("path_security_jni");
    }
    
    /**
     * Validates a file path for security issues
     * @param path The path to validate
     * @return Validation result as JSON string
     * @throws PathSecurityException if validation fails
     */
    public native String validatePath(String path) throws PathSecurityException;
    
    /**
     * Detects if a path contains traversal patterns
     * @param path The path to check
     * @return true if traversal detected, false otherwise
     * @throws PathSecurityException if detection fails
     */
    public native boolean detectTraversal(String path) throws PathSecurityException;
    
    /**
     * Sanitizes a path by removing dangerous patterns
     * @param path The path to sanitize
     * @return Sanitized path
     * @throws PathSecurityException if sanitization fails
     */
    public native String sanitizePath(String path) throws PathSecurityException;
    
    /**
     * Custom exception for Path Security operations
     */
    public static class PathSecurityException extends Exception {
        public PathSecurityException(String message) {
            super(message);
        }
        
        public PathSecurityException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
