# Basic Makefile for tests

CXX = g++
# Add -g for debugging symbols
# Add OpenCL Target Version to CXXFLAGS_TEST
CXXFLAGS_TEST = -std=c++11 -g -I$(PARENT_SRC_DIR) -Wall -Wextra -DCL_TARGET_OPENCL_VERSION=120

# Relative path to the parent source directory (src/) from src/tests/
PARENT_SRC_DIR = ..

# Test executables
TESTS = test_password_dictionary test_crypto

all: $(TESTS)

test_password_dictionary: test_password_dictionary.cpp $(PARENT_SRC_DIR)/PasswordDictionary.cpp $(PARENT_SRC_DIR)/util.cpp $(PARENT_SRC_DIR)/core-decrypt.h
	$(CXX) $(CXXFLAGS_TEST) -o $@ test_password_dictionary.cpp $(PARENT_SRC_DIR)/PasswordDictionary.cpp $(PARENT_SRC_DIR)/util.cpp

test_crypto: test_crypto.cpp $(PARENT_SRC_DIR)/aes.cpp $(PARENT_SRC_DIR)/sha512.cpp $(PARENT_SRC_DIR)/hash.cpp $(PARENT_SRC_DIR)/util.cpp $(PARENT_SRC_DIR)/core-decrypt.h
	$(CXX) $(CXXFLAGS_TEST) -o $@ test_crypto.cpp $(PARENT_SRC_DIR)/aes.cpp $(PARENT_SRC_DIR)/sha512.cpp $(PARENT_SRC_DIR)/hash.cpp $(PARENT_SRC_DIR)/util.cpp

# Target to run all tests
run: all
	@echo "Running PasswordDictionary tests..."
	./test_password_dictionary
	@echo "\nRunning Crypto tests..."
	./test_crypto
	@echo "\nAll tests execution finished."

clean:
	rm -f $(TESTS) *.o *.txt # Removes executables, object files, and temp text files

.PHONY: all run clean
