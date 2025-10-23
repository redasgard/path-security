package main

/*
#cgo LDFLAGS: -L. -lpath_security_c
#include "path_security.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// PathSecurity provides Go bindings for Path Security
type PathSecurity struct{}

// NewPathSecurity creates a new PathSecurity instance
func NewPathSecurity() *PathSecurity {
	return &PathSecurity{}
}

// ValidatePath validates a file path for security issues
func (ps *PathSecurity) ValidatePath(path string) (string, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	result := make([]byte, 256)
	ret := C.path_security_validate_path(cPath, (*C.char)(unsafe.Pointer(&result[0])), C.size_t(len(result)))

	if ret != 0 {
		return "", fmt.Errorf("path validation failed with code: %d", ret)
	}

	return C.GoString((*C.char)(unsafe.Pointer(&result[0]))), nil
}

// DetectTraversal detects if a path contains traversal patterns
func (ps *PathSecurity) DetectTraversal(path string) (bool, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	ret := C.path_security_detect_traversal(cPath)

	if ret < 0 {
		return false, fmt.Errorf("traversal detection failed with code: %d", ret)
	}

	return ret == 1, nil
}

// SanitizePath sanitizes a path by removing dangerous patterns
func (ps *PathSecurity) SanitizePath(path string) (string, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	result := make([]byte, 256)
	ret := C.path_security_sanitize_path(cPath, (*C.char)(unsafe.Pointer(&result[0])), C.size_t(len(result)))

	if ret != 0 {
		return "", fmt.Errorf("path sanitization failed with code: %d", ret)
	}

	return C.GoString((*C.char)(unsafe.Pointer(&result[0]))), nil
}
