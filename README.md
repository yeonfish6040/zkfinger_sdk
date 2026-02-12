# zkfinger (SLR20R/Live20R)

This repo contains a reverse‑engineered fingerprint stack for ZKTeco USB sensors (VID `0x1B55`, PID `0x0120`).
It includes:

- `zkfp` shared library: ZKFPM API + libusb sensor backend
- `zkfinger10` shared library: BIOKEY algorithm wrapper (requires external `IEngine_*` implementation)
- `zkfp_capture_test` CLI: capture a raw image and save as PGM

> Notes
> - The current USB protocol implementation was derived from `silkidcap` (mcp5) and uses libusb control + bulk.
> - The algorithm layer (`zkfinger10`) depends on `IEngine_*` symbols which are **not** included here.

---

## Build

### macOS (Apple Silicon)

Requirements:
- `libusb`
- (Optional) `pkg-config`

Install:
```bash
brew install libusb
# optional
brew install pkg-config
```

Build:
```bash
cmake -S . -B build
cmake --build build
```

If CMake can’t find libusb:
```bash
cmake -S . -B build -DLIBUSB_ROOT=/opt/homebrew/opt/libusb
```

### ARM Linux

Requirements:
- `libusb-1.0-0-dev`
- `pkg-config`

Install:
```bash
sudo apt-get install -y libusb-1.0-0-dev pkg-config
```

Build:
```bash
cmake -S . -B build
cmake --build build
```

---

## Test Capture

Run the test program (defaults to 300x400, output to `test/capture.pgm`):
```bash
./build/zkfp_capture_test
```

Specify output path / resolution / DPI:
```bash
./build/zkfp_capture_test test/out.pgm 300 400 500
```

### Useful Environment Variables

- `ZKFP_USB_DEBUG=1` — enable USB debug prints
- `ZKFP_RAW_WIDTH` / `ZKFP_RAW_HEIGHT` — override raw sensor frame size (if different)

Example:
```bash
export ZKFP_USB_DEBUG=1
export ZKFP_RAW_WIDTH=300
export ZKFP_RAW_HEIGHT=400
./build/zkfp_capture_test
```

---

## Troubleshooting

### Link errors for `IEngine_*`
`zkfinger10` depends on an external algorithm library that provides `IEngine_*` symbols.
If you don’t have that library, you can still build **only** `zkfp` and the capture test by disabling `zkfinger10`.

Options:
- Provide and link the real `IEngine` library.
- Or temporarily remove `zkfinger10` from the build in `CMakeLists.txt`.

### Device not found
- Check VID/PID:
  - `Vendor ID: 0x1B55`
  - `Product ID: 0x0120`
- Ensure permissions (Linux udev rules may be needed).

---

## Files

- `src/zkfp.cpp` — ZKFPM API implementation
- `src/sensor_libusb.cpp` — libusb backend (control/bulk)
- `src/zkfinger10.cpp` — BIOKEY wrapper (needs `IEngine_*`)
- `test/capture_image.cpp` — capture test CLI
- `include/` — public headers

