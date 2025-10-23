use neon::prelude::*;
use path_security::{PathValidator, PathSanitizer, ValidationResult};
use serde_json;

// Node.js bindings for Path Security
pub fn validate_path(mut cx: FunctionContext) -> JsResult<JsString> {
    let path = cx.argument::<JsString>(0)?.value(&mut cx);
    
    let validator = PathValidator::new()
        .with_traversal_detection(true)
        .with_encoding_detection(true)
        .with_unicode_detection(true);
    
    match validator.validate_path(&path) {
        Ok(validated_path) => {
            let result = serde_json::json!({
                "valid": true,
                "path": validated_path,
                "sanitized": true
            });
            Ok(cx.string(result.to_string()))
        }
        Err(error) => {
            let result = serde_json::json!({
                "valid": false,
                "error": error.to_string(),
                "path": path
            });
            Ok(cx.string(result.to_string()))
        }
    }
}

pub fn detect_traversal(mut cx: FunctionContext) -> JsResult<JsString> {
    let path = cx.argument::<JsString>(0)?.value(&mut cx);
    
    let validator = PathValidator::new()
        .with_traversal_detection(true)
        .with_encoding_detection(true)
        .with_unicode_detection(true);
    
    let is_traversal = validator.validate_path(&path).is_err();
    
    let result = serde_json::json!({
        "is_traversal": is_traversal,
        "path": path,
        "detected": is_traversal
    });
    
    Ok(cx.string(result.to_string()))
}

pub fn sanitize_path(mut cx: FunctionContext) -> JsResult<JsString> {
    let path = cx.argument::<JsString>(0)?.value(&mut cx);
    
    let sanitizer = PathSanitizer::new()
        .with_traversal_removal(true)
        .with_encoding_normalization(true)
        .with_unicode_normalization(true);
    
    let sanitized = sanitizer.sanitize_path(&path);
    
    let result = serde_json::json!({
        "original": path,
        "sanitized": sanitized,
        "changed": path != sanitized
    });
    
    Ok(cx.string(result.to_string()))
}

pub fn sanitize_filename(mut cx: FunctionContext) -> JsResult<JsString> {
    let filename = cx.argument::<JsString>(0)?.value(&mut cx);
    let sanitized = PathSanitizer::sanitize_filename(&filename);
    
    let result = serde_json::json!({
        "original": filename,
        "sanitized": sanitized,
        "changed": filename != sanitized
    });
    
    Ok(cx.string(result.to_string()))
}

pub fn validate_project_name(mut cx: FunctionContext) -> JsResult<JsString> {
    let name = cx.argument::<JsString>(0)?.value(&mut cx);
    
    let validator = PathValidator::new()
        .with_project_name_validation(true)
        .with_traversal_detection(true)
        .with_encoding_detection(true);
    
    match validator.validate_project_name(&name) {
        Ok(validated_name) => {
            let result = serde_json::json!({
                "valid": true,
                "name": validated_name,
                "sanitized": true
            });
            Ok(cx.string(result.to_string()))
        }
        Err(error) => {
            let result = serde_json::json!({
                "valid": false,
                "error": error.to_string(),
                "name": name
            });
            Ok(cx.string(result.to_string()))
        }
    }
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("validatePath", validate_path)?;
    cx.export_function("detectTraversal", detect_traversal)?;
    cx.export_function("sanitizePath", sanitize_path)?;
    cx.export_function("sanitizeFilename", sanitize_filename)?;
    cx.export_function("validateProjectName", validate_project_name)?;
    Ok(())
}
