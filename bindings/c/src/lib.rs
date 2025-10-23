use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use path_security::{PathValidator, PathSanitizer, ValidationResult};
use serde_json;

#[no_mangle]
pub extern "C" fn path_security_validate_path(
    path: *const c_char,
    result: *mut c_char,
    result_len: usize,
) -> i32 {
    if path.is_null() || result.is_null() {
        return -1;
    }

    let path_str = unsafe {
        match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => return -2,
        }
    };

    let validator = PathValidator::new()
        .with_traversal_detection(true)
        .with_encoding_detection(true)
        .with_unicode_detection(true);

    let json_result = match validator.validate_path(path_str) {
        Ok(validated_path) => {
            serde_json::json!({
                "valid": true,
                "path": validated_path,
                "sanitized": true
            })
        }
        Err(error) => {
            serde_json::json!({
                "valid": false,
                "error": error.to_string(),
                "path": path_str
            })
        }
    };
    
    let json_string = json_result.to_string();
    let c_string = match CString::new(json_string) {
        Ok(s) => s,
        Err(_) => return -3,
    };
    
    let bytes = c_string.as_bytes_with_nul();
    if bytes.len() > result_len {
        return -4; // Buffer too small
    }
    
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), result as *mut u8, bytes.len());
    }
    0
}

#[no_mangle]
pub extern "C" fn path_security_detect_traversal(path: *const c_char) -> i32 {
    if path.is_null() {
        return -1;
    }

    let path_str = unsafe {
        match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => return -2,
        }
    };

    let validator = PathValidator::new()
        .with_traversal_detection(true);

    if validator.validate_path(path_str).is_err() {
        1 // Traversal detected
    } else {
        0 // No traversal
    }
}

#[no_mangle]
pub extern "C" fn path_security_sanitize_path(
    path: *const c_char,
    result: *mut c_char,
    result_len: usize,
) -> i32 {
    if path.is_null() || result.is_null() {
        return -1;
    }

    let path_str = unsafe {
        match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => return -2,
        }
    };

    let sanitizer = PathSanitizer::new()
        .with_traversal_removal(true)
        .with_encoding_normalization(true)
        .with_unicode_normalization(true);
    
    let sanitized = sanitizer.sanitize_path(path_str);
    
    let json_result = serde_json::json!({
        "original": path_str,
        "sanitized": sanitized,
        "changed": path_str != sanitized
    });
    
    let json_string = json_result.to_string();
    let c_string = match CString::new(json_string) {
        Ok(s) => s,
        Err(_) => return -3,
    };
    
    let bytes = c_string.as_bytes_with_nul();
    if bytes.len() > result_len {
        return -4; // Buffer too small
    }
    
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), result as *mut u8, bytes.len());
    }
    0
}

#[no_mangle]
pub extern "C" fn path_security_sanitize_filename(
    filename: *const c_char,
    result: *mut c_char,
    result_len: usize,
) -> i32 {
    if filename.is_null() || result.is_null() {
        return -1;
    }

    let filename_str = unsafe {
        match CStr::from_ptr(filename).to_str() {
            Ok(s) => s,
            Err(_) => return -2,
        }
    };

    let sanitized = PathSanitizer::sanitize_filename(filename_str);
    
    let json_result = serde_json::json!({
        "original": filename_str,
        "sanitized": sanitized,
        "changed": filename_str != sanitized
    });
    
    let json_string = json_result.to_string();
    let c_string = match CString::new(json_string) {
        Ok(s) => s,
        Err(_) => return -3,
    };
    
    let bytes = c_string.as_bytes_with_nul();
    if bytes.len() > result_len {
        return -4; // Buffer too small
    }
    
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), result as *mut u8, bytes.len());
    }
    0
}

#[no_mangle]
pub extern "C" fn path_security_validate_project_name(
    name: *const c_char,
    result: *mut c_char,
    result_len: usize,
) -> i32 {
    if name.is_null() || result.is_null() {
        return -1;
    }

    let name_str = unsafe {
        match CStr::from_ptr(name).to_str() {
            Ok(s) => s,
            Err(_) => return -2,
        }
    };

    let validator = PathValidator::new()
        .with_project_name_validation(true)
        .with_traversal_detection(true)
        .with_encoding_detection(true);
    
    let json_result = match validator.validate_project_name(name_str) {
        Ok(validated_name) => {
            serde_json::json!({
                "valid": true,
                "name": validated_name,
                "sanitized": true
            })
        }
        Err(error) => {
            serde_json::json!({
                "valid": false,
                "error": error.to_string(),
                "name": name_str
            })
        }
    };
    
    let json_string = json_result.to_string();
    let c_string = match CString::new(json_string) {
        Ok(s) => s,
        Err(_) => return -3,
    };
    
    let bytes = c_string.as_bytes_with_nul();
    if bytes.len() > result_len {
        return -4; // Buffer too small
    }
    
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), result as *mut u8, bytes.len());
    }
    0
}