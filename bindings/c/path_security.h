#ifndef PATH_SECURITY_H
#define PATH_SECURITY_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Validate a file path for security issues
 * @param path Input path to validate
 * @param result Buffer to store validated path
 * @param result_len Size of result buffer
 * @return 0 on success, negative on error
 */
int path_security_validate_path(const char* path, char* result, size_t result_len);

/**
 * Detect if a path contains traversal patterns
 * @param path Input path to check
 * @return 1 if traversal detected, 0 if safe, negative on error
 */
int path_security_detect_traversal(const char* path);

/**
 * Sanitize a path by removing dangerous patterns
 * @param path Input path to sanitize
 * @param result Buffer to store sanitized path
 * @param result_len Size of result buffer
 * @return 0 on success, negative on error
 */
int path_security_sanitize_path(const char* path, char* result, size_t result_len);

/**
 * Sanitize a filename by removing dangerous characters
 * @param filename Input filename to sanitize
 * @param result Buffer to store sanitized filename
 * @param result_len Size of result buffer
 * @return 0 on success, negative on error
 */
int path_security_sanitize_filename(const char* filename, char* result, size_t result_len);

/**
 * Validate a project name for security issues
 * @param name Input project name to validate
 * @param result Buffer to store validation results
 * @param result_len Size of result buffer
 * @return 0 on success, negative on error
 */
int path_security_validate_project_name(const char* name, char* result, size_t result_len);

#ifdef __cplusplus
}
#endif

#endif // PATH_SECURITY_H
