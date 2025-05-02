# Project Configuration
BUILD_DIR=build
IOS_ARTIFACT=$(BUILD_DIR)/Xraywrapper.xcframework
PACKAGE_PATH=xray-ios/xraywrapper
LDFLAGS="-s -w"
GO_MODULE=xray-ios

# Build targets
.PHONY: all init_env go_deps build_apple clean

all: init_env build_apple

init_env: clean go_deps
	@echo "Environment initialized"

go_deps:
	@echo "Installing dependencies..."
	go mod download
	go install golang.org/x/mobile/cmd/gomobile@latest
	gomobile init -v
	go get -d golang.org/x/mobile/bind
	go get -d golang.org/x/mobile/bind/objc
	@echo "Dependencies installed"

build_apple:
	@echo "Building Xray framework..."
	@mkdir -p $(BUILD_DIR)
	gomobile bind -a -v \
		-ldflags $(LDFLAGS) \
		-target=ios,iossimulator,macos \
		-o $(IOS_ARTIFACT) \
		$(PACKAGE_PATH)
	@echo "Build complete: $(IOS_ARTIFACT)"

build_ios_only:
	@echo "Building iOS-only framework..."
	@mkdir -p $(BUILD_DIR)
	gomobile bind -v \
		-ldflags $(LDFLAGS) \
		-target=ios \
		-o $(IOS_ARTIFACT) \
		$(PACKAGE_PATH)

build_m1:
	@echo "Building for Apple Silicon..."
	@mkdir -p $(BUILD_DIR)
	gomobile bind -v \
		-ldflags $(LDFLAGS) \
		-target=ios/arm64 \
		-o $(IOS_ARTIFACT) \
		$(PACKAGE_PATH)

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@go clean -cache
	@go clean -modcache
	@echo "Clean complete"

test_deps:
	@echo "Verifying dependencies..."
	@which gomobile || (echo "gomobile not found" && exit 1)
	@[ -d "$(shell go env GOPATH)/pkg/mod/golang.org/x/mobile@latest" ] || (echo "mobile bind packages missing" && exit 1)
	@echo "All dependencies verified"

help:
	@echo "Available targets:"
	@echo "  all          - Initialize and build everything (default)"
	@echo "  init_env     - Clean and install dependencies"
	@echo "  go_deps      - Install Go dependencies"
	@echo "  build_apple  - Build universal framework (iOS, simulator, macOS)"
	@echo "  build_ios    - Build iOS-only framework"
	@echo "  build_m1     - Build for Apple Silicon only"
	@echo "  clean        - Remove all build artifacts"
	@echo "  test_deps    - Verify all dependencies are installed"