#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include "path_security.h"

JNIEXPORT jstring JNICALL
Java_com_asgardtech_pathsecurity_PathSecurity_validatePath(JNIEnv *env, jobject obj, jstring path) {
    const char *pathStr = (*env)->GetStringUTFChars(env, path, NULL);
    if (pathStr == NULL) {
        return NULL;
    }
    
    char result[256];
    int ret = path_security_validate_path(pathStr, result, sizeof(result));
    
    (*env)->ReleaseStringUTFChars(env, path, pathStr);
    
    if (ret != 0) {
        jclass exceptionClass = (*env)->FindClass(env, "com/asgardtech/pathsecurity/PathSecurity$PathSecurityException");
        (*env)->ThrowNew(env, exceptionClass, "Path validation failed");
        return NULL;
    }
    
    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jboolean JNICALL
Java_com_asgardtech_pathsecurity_PathSecurity_detectTraversal(JNIEnv *env, jobject obj, jstring path) {
    const char *pathStr = (*env)->GetStringUTFChars(env, path, NULL);
    if (pathStr == NULL) {
        return JNI_FALSE;
    }
    
    int ret = path_security_detect_traversal(pathStr);
    
    (*env)->ReleaseStringUTFChars(env, path, pathStr);
    
    if (ret < 0) {
        jclass exceptionClass = (*env)->FindClass(env, "com/asgardtech/pathsecurity/PathSecurity$PathSecurityException");
        (*env)->ThrowNew(env, exceptionClass, "Traversal detection failed");
        return JNI_FALSE;
    }
    
    return ret == 1 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_asgardtech_pathsecurity_PathSecurity_sanitizePath(JNIEnv *env, jobject obj, jstring path) {
    const char *pathStr = (*env)->GetStringUTFChars(env, path, NULL);
    if (pathStr == NULL) {
        return NULL;
    }
    
    char result[256];
    int ret = path_security_sanitize_path(pathStr, result, sizeof(result));
    
    (*env)->ReleaseStringUTFChars(env, path, pathStr);
    
    if (ret != 0) {
        jclass exceptionClass = (*env)->FindClass(env, "com/asgardtech/pathsecurity/PathSecurity$PathSecurityException");
        (*env)->ThrowNew(env, exceptionClass, "Path sanitization failed");
        return NULL;
    }
    
    return (*env)->NewStringUTF(env, result);
}
