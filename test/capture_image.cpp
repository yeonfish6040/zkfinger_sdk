#include "libzkfp.h"
#include "libzkfperrdef.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <system_error>
#include <vector>

namespace {

const char *ErrToString(int code) {
  switch (code) {
    case ZKFP_ERR_OK:
      return "OK";
    case ZKFP_ERR_ALREADY_INIT:
      return "ALREADY_INIT";
    case ZKFP_ERR_INITLIB:
      return "INITLIB";
    case ZKFP_ERR_INIT:
      return "INIT";
    case ZKFP_ERR_NO_DEVICE:
      return "NO_DEVICE";
    case ZKFP_ERR_NOT_SUPPORT:
      return "NOT_SUPPORT";
    case ZKFP_ERR_INVALID_PARAM:
      return "INVALID_PARAM";
    case ZKFP_ERR_OPEN:
      return "OPEN";
    case ZKFP_ERR_INVALID_HANDLE:
      return "INVALID_HANDLE";
    case ZKFP_ERR_CAPTURE:
      return "CAPTURE";
    case ZKFP_ERR_EXTRACT_FP:
      return "EXTRACT_FP";
    case ZKFP_ERR_ABSORT:
      return "ABSORT";
    case ZKFP_ERR_MEMORY_NOT_ENOUGH:
      return "MEMORY_NOT_ENOUGH";
    case ZKFP_ERR_BUSY:
      return "BUSY";
    case ZKFP_ERR_ADD_FINGER:
      return "ADD_FINGER";
    case ZKFP_ERR_DEL_FINGER:
      return "DEL_FINGER";
    case ZKFP_ERR_FAIL:
      return "FAIL";
    case ZKFP_ERR_CANCEL:
      return "CANCEL";
    case ZKFP_ERR_VERIFY_FP:
      return "VERIFY_FP";
    case ZKFP_ERR_MERGE:
      return "MERGE";
    case ZKFP_ERR_NOT_OPENED:
      return "NOT_OPENED";
    case ZKFP_ERR_NOT_INIT:
      return "NOT_INIT";
    case ZKFP_ERR_ALREADY_OPENED:
      return "ALREADY_OPENED";
    case ZKFP_ERR_LOADIMAGE:
      return "LOADIMAGE";
    case ZKFP_ERR_ANALYSE_IMG:
      return "ANALYSE_IMG";
    case ZKFP_ERR_TIMEOUT:
      return "TIMEOUT";
    default:
      return "UNKNOWN";
  }
}

bool WritePgm(const std::string &path, const std::vector<unsigned char> &image, unsigned int width,
              unsigned int height) {
  std::filesystem::path out_path(path);
  if (out_path.has_parent_path()) {
    std::error_code ec;
    std::filesystem::create_directories(out_path.parent_path(), ec);
  }

  std::ofstream out(path, std::ios::binary);
  if (!out) {
    return false;
  }
  out << "P5\n" << width << " " << height << "\n255\n";
  out.write(reinterpret_cast<const char *>(image.data()), static_cast<std::streamsize>(image.size()));
  return static_cast<bool>(out);
}

int SetParam(HANDLE dev, int code, int value) {
  unsigned int v = static_cast<unsigned int>(value);
  return ZKFPM_SetParameters(dev, code, reinterpret_cast<unsigned char *>(&v), sizeof(v));
}

} // namespace

int main(int argc, char **argv) {
  std::string out_path = "test/capture.pgm";
  int width_override = 0;
  int height_override = 0;
  int dpi_override = 0;

  if (argc > 1) {
    out_path = argv[1];
  }
  if (argc > 3) {
    width_override = std::atoi(argv[2]);
    height_override = std::atoi(argv[3]);
  }
  if (argc > 4) {
    dpi_override = std::atoi(argv[4]);
  }

  int ret = ZKFPM_Init();
  if (ret != ZKFP_ERR_OK) {
    std::cerr << "ZKFPM_Init failed: " << ret << " (" << ErrToString(ret) << ")\n";
    return 1;
  }

  int count = ZKFPM_GetDeviceCount();
  if (count <= 0) {
    std::cerr << "No devices found (count=" << count << ")\n";
    ZKFPM_Terminate();
    return 1;
  }

  HANDLE dev = ZKFPM_OpenDevice(0);
  if (!dev) {
    std::cerr << "ZKFPM_OpenDevice failed\n";
    ZKFPM_Terminate();
    return 1;
  }

  if (width_override > 0 && height_override > 0) {
    SetParam(dev, 1, width_override);
    SetParam(dev, 2, height_override);
    if (dpi_override <= 0) {
      dpi_override = 500;
    }
    SetParam(dev, 3, dpi_override);
  }

  TZKFPCapParams params{};
  ret = ZKFPM_GetCaptureParams(dev, &params);
  if (ret != ZKFP_ERR_OK || params.imgWidth == 0 || params.imgHeight == 0) {
    if (width_override > 0 && height_override > 0) {
      params.imgWidth = static_cast<unsigned int>(width_override);
      params.imgHeight = static_cast<unsigned int>(height_override);
      params.nDPI = static_cast<unsigned int>(dpi_override > 0 ? dpi_override : 500);
    } else {
      params.imgWidth = 300;
      params.imgHeight = 400;
      params.nDPI = 500;
    }
  }

  const size_t image_size = static_cast<size_t>(params.imgWidth) * static_cast<size_t>(params.imgHeight);
  std::vector<unsigned char> image(image_size);

  ret = ZKFPM_AcquireFingerprintImage(dev, image.data(), static_cast<unsigned int>(image.size()));
  if (ret != ZKFP_ERR_OK) {
    std::cerr << "Capture failed: " << ret << " (" << ErrToString(ret) << ")\n";
    ZKFPM_CloseDevice(dev);
    ZKFPM_Terminate();
    return 1;
  }

  if (!WritePgm(out_path, image, params.imgWidth, params.imgHeight)) {
    std::cerr << "Failed to write image: " << out_path << "\n";
    ZKFPM_CloseDevice(dev);
    ZKFPM_Terminate();
    return 1;
  }

  std::cout << "Saved " << out_path << " (" << params.imgWidth << "x" << params.imgHeight << ")\n";

  ZKFPM_CloseDevice(dev);
  ZKFPM_Terminate();
  return 0;
}
