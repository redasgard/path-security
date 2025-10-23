use pyo3::prelude::*;
use path_security::{PathValidator, PathSanitizer, ValidationResult};
use serde_json;

#[pyclass]
struct PathSecurity {
    validator: PathValidator,
}

#[pymethods]
impl PathSecurity {
    #[new]
    fn new() -> Self {
        Self {
            validator: PathValidator::new()
                .with_traversal_detection(true)
                .with_encoding_detection(true)
                .with_unicode_detection(true),
        }
    }

    fn validate_path(&self, path: &str) -> PyResult<String> {
        match self.validator.validate_path(path) {
            Ok(validated_path) => {
                let result = serde_json::json!({
                    "valid": true,
                    "path": validated_path,
                    "sanitized": true
                });
                Ok(result.to_string())
            }
            Err(error) => {
                let result = serde_json::json!({
                    "valid": false,
                    "error": error.to_string(),
                    "path": path
                });
                Ok(result.to_string())
            }
        }
    }

    fn detect_traversal(&self, path: &str) -> PyResult<String> {
        let is_traversal = self.validator.validate_path(path).is_err();
        
        let result = serde_json::json!({
            "is_traversal": is_traversal,
            "path": path,
            "detected": is_traversal
        });
        
        Ok(result.to_string())
    }

    fn sanitize_path(&self, path: &str) -> PyResult<String> {
        let sanitizer = PathSanitizer::new()
            .with_traversal_removal(true)
            .with_encoding_normalization(true)
            .with_unicode_normalization(true);
        
        let sanitized = sanitizer.sanitize_path(path);
        
        let result = serde_json::json!({
            "original": path,
            "sanitized": sanitized,
            "changed": path != sanitized
        });
        
        Ok(result.to_string())
    }

    fn sanitize_filename(&self, filename: &str) -> PyResult<String> {
        let sanitized = PathSanitizer::sanitize_filename(filename);
        
        let result = serde_json::json!({
            "original": filename,
            "sanitized": sanitized,
            "changed": filename != sanitized
        });
        
        Ok(result.to_string())
    }

    fn validate_project_name(&self, name: &str) -> PyResult<String> {
        let validator = PathValidator::new()
            .with_project_name_validation(true)
            .with_traversal_detection(true)
            .with_encoding_detection(true);
        
        match validator.validate_project_name(name) {
            Ok(validated_name) => {
                let result = serde_json::json!({
                    "valid": true,
                    "name": validated_name,
                    "sanitized": true
                });
                Ok(result.to_string())
            }
            Err(error) => {
                let result = serde_json::json!({
                    "valid": false,
                    "error": error.to_string(),
                    "name": name
                });
                Ok(result.to_string())
            }
        }
    }
}

#[pymodule]
fn path_security_python(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PathSecurity>()?;
    Ok(())
}
