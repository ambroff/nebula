# Nebula C++ Port Makefile

# Compiler settings
CXX := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -O2 -g -pthread
LDFLAGS := -pthread

# Feature detection
HAVE_BOOST := $(shell ls /usr/include/boost 2>/dev/null && echo 1 || echo 0)
HAVE_OPENSSL := $(shell pkg-config --exists openssl && echo 1 || echo 0)
HAVE_PROTOBUF := $(shell pkg-config --exists protobuf && echo 1 || echo 0)

# Check dependencies
ifeq ($(HAVE_BOOST),0)
$(error "Boost is required but not found. Please install libboost-dev")
endif
ifeq ($(HAVE_OPENSSL),0)
# Try alternative detection
HAVE_OPENSSL := $(shell ls /usr/include/openssl 2>/dev/null && echo 1 || echo 0)
ifeq ($(HAVE_OPENSSL),0)
$(error "OpenSSL is required but not found. Please install libssl-dev")
endif
endif
ifeq ($(HAVE_PROTOBUF),0)
$(warning "Protobuf not found. Certificate v1 support will be disabled")
CXXFLAGS += -DNO_PROTOBUF
endif

# Include paths and libraries
ifeq ($(shell pkg-config --exists openssl && echo 1 || echo 0),1)
CXXFLAGS += $(shell pkg-config --cflags openssl)
LDFLAGS += $(shell pkg-config --libs openssl)
else
LDFLAGS += -lssl -lcrypto
endif
LDFLAGS += -lboost_system -lboost_thread -lboost_json

ifeq ($(HAVE_PROTOBUF),1)
CXXFLAGS += $(shell pkg-config --cflags protobuf)
LDFLAGS += $(shell pkg-config --libs protobuf)
endif

# Platform detection
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    # Check if platform file exists, otherwise skip for now
    ifneq ($(wildcard src/tun/tun_linux.cpp),)
        PLATFORM_SOURCES := src/tun/tun_linux.cpp
    endif
    CXXFLAGS += -DPLATFORM_LINUX
    LDFLAGS += -lrt
endif
ifeq ($(UNAME_S),Darwin)
    # Check if platform file exists, otherwise skip for now
    ifneq ($(wildcard src/tun/tun_darwin.cpp),)
        PLATFORM_SOURCES := src/tun/tun_darwin.cpp
    endif
    CXXFLAGS += -DPLATFORM_DARWIN
endif

# Directories
BUILD_DIR := build
SRC_DIR := src
INCLUDE_DIR := include

# Source files
SOURCES := $(wildcard $(SRC_DIR)/*.cpp) \
           $(wildcard $(SRC_DIR)/cert/*.cpp)
ifneq ($(PLATFORM_SOURCES),)
    SOURCES += $(PLATFORM_SOURCES)
endif
OBJECTS := $(SOURCES:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)
DEPS := $(OBJECTS:.o=.d)

# Executable
TARGET := nebula

# Default target
all: $(TARGET)

# Link executable
$(TARGET): $(OBJECTS)
	@echo "Linking $@..."
	@$(CXX) $(OBJECTS) $(LDFLAGS) -o $@

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	@echo "Compiling $<..."
	@$(CXX) $(CXXFLAGS) -I$(INCLUDE_DIR) -MMD -MP -c $< -o $@

# Include dependency files
-include $(DEPS)

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR) $(TARGET)

# Install target
install: $(TARGET)
	@echo "Installing to /usr/local/bin..."
	@install -m 755 $(TARGET) /usr/local/bin/

# Development targets
.PHONY: format
format:
	@echo "Formatting code..."
	@find $(SRC_DIR) $(INCLUDE_DIR) -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i

.PHONY: check
check:
	@echo "Running static analysis..."
	@cppcheck --enable=all --suppress=missingIncludeSystem -I$(INCLUDE_DIR) $(SRC_DIR)

# Test target (placeholder)
.PHONY: test
test: $(TARGET)
	@echo "Running tests..."
	@echo "TODO: Implement test suite"

# Debug build
.PHONY: debug
debug: CXXFLAGS += -DDEBUG -O0 -g3
debug: clean $(TARGET)

# Release build
.PHONY: release
release: CXXFLAGS += -DNDEBUG -O3 -march=native
release: clean $(TARGET)

# Help
.PHONY: help
help:
	@echo "Nebula C++ Port Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build nebula executable (default)"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to /usr/local/bin"
	@echo "  debug    - Build with debug symbols"
	@echo "  release  - Build optimized release"
	@echo "  test     - Run test suite"
	@echo "  format   - Format source code"
	@echo "  check    - Run static analysis"
	@echo ""
	@echo "Variables:"
	@echo "  CXX      - C++ compiler (default: g++)"
	@echo "  CXXFLAGS - Compiler flags"
	@echo "  LDFLAGS  - Linker flags"

.PHONY: all clean install debug release test format check help