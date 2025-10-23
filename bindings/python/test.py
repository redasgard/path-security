#!/usr/bin/env python3
"""
Test script for Path Security Python bindings
"""

import os
import json
from path_security_python import PathSecurity

def test_path_security():
    print("Testing Path Security Python bindings:")
    print("======================================")
    
    # Create validator instance
    validator = PathSecurity()
    
    # Test safe paths
    print("\n1. Testing safe paths:")
    safe_paths = [
        "/safe/path/to/file.txt",
        "C:\\Windows\\System32\\file.txt",
        "/usr/local/bin/script.sh"
    ]
    
    for path in safe_paths:
        result = json.loads(validator.validate_path(path))
        print(f"Safe path '{path}' -> Valid: {result['valid']}")
    
    # Test dangerous paths
    print("\n2. Testing dangerous paths:")
    dangerous_paths = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    ]
    
    for path in dangerous_paths:
        traversal_result = json.loads(validator.detect_traversal(path))
        sanitized_result = json.loads(validator.sanitize_path(path))
        print(f"Dangerous path '{path}' -> Traversal: {traversal_result['is_traversal']}, Sanitized: {sanitized_result['sanitized']}")
    
    # Test filename sanitization
    print("\n3. Testing filename sanitization:")
    filenames = [
        'file/name?with*bad|chars.txt',
        'my_document.pdf',
        'script<script>alert(1)</script>.js'
    ]
    
    for filename in filenames:
        result = json.loads(validator.sanitize_filename(filename))
        print(f"Filename '{filename}' -> Sanitized: '{result['sanitized']}'")
    
    # Test project name validation
    print("\n4. Testing project name validation:")
    project_names = [
        'my-safe-project',
        '../malicious-project',
        'valid_project_123'
    ]
    
    for name in project_names:
        result = json.loads(validator.validate_project_name(name))
        print(f"Project name '{name}' -> Valid: {result['valid']}")
    
    print("\nPython bindings test completed!")

if __name__ == "__main__":
    test_path_security()
