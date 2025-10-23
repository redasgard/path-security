# Makefile for Path Security JNI bindings

# Compiler and flags
CC = gcc
JAVA_HOME ?= /usr/lib/jvm/default-java
JNI_INCLUDES = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux
CFLAGS = -fPIC -shared $(JNI_INCLUDES) -O2

# Source and target
SRC = path_security_jni.c
TARGET = libpath_security_jni.so

# Path Security library
PATH_SECURITY_LIB = ../../c/target/release/libpath_security_c.so

# Build target
$(TARGET): $(SRC) $(PATH_SECURITY_LIB)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) -L../../c/target/release -lpath_security_c

# Clean
clean:
	rm -f $(TARGET)

# Install
install: $(TARGET)
	cp $(TARGET) /usr/local/lib/
	ldconfig

.PHONY: clean install
