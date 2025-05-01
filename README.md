# Xray iOS Wrapper

A Go-mobile wrapper for Xray-core with support for:
- VMESS
- Shadowsocks
- VLESS
- Trojan protocols

## Features
- Multi-protocol support
- Apple Silicon (M1/M2) compatible
- Clean Swift API

## Installation
```bash
# Standard build (recommended)
make

# Clean and rebuild
make clean all

# Build for Apple Silicon only
make build_m1

# Verify dependencies
make test_deps
```

## Usage
```swift
let manager = V2RayManager()
try manager.start(config: "vmess://...")
```