#include "zkinterface.h"

#include <libusb-1.0/libusb.h>

#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <vector>

namespace {

constexpr uint16_t kVendorId = 0x1B55;
constexpr uint16_t kProductId = 0x0120;
constexpr int kDefaultWidth = 300;
constexpr int kDefaultHeight = 400;
constexpr int kDefaultDpi = 500;
constexpr unsigned int kDefaultTimeoutMs = 2000;

struct SensorHandle {
  libusb_device *dev = nullptr;
  libusb_device_handle *handle = nullptr;
  uint8_t iface = 0;
  uint8_t ep_in = 0;
  uint8_t ep_out = 0;
  int width = kDefaultWidth;
  int height = kDefaultHeight;
  int dpi = kDefaultDpi;
  int raw_width = 0;
  int raw_height = 0;
  bool det_mode = false;
  int last_quality = 0;
  std::mutex lock;
};

libusb_context *g_ctx = nullptr;
bool g_debug = false;

bool EnvFlag(const char *name) {
  const char *val = std::getenv(name);
  if (!val) {
    return false;
  }
  return std::strcmp(val, "1") == 0 || std::strcmp(val, "true") == 0 || std::strcmp(val, "TRUE") == 0 ||
         std::strcmp(val, "yes") == 0 || std::strcmp(val, "YES") == 0;
}

int EnvInt(const char *name, int fallback) {
  const char *val = std::getenv(name);
  if (!val || !*val) {
    return fallback;
  }
  char *end = nullptr;
  long parsed = std::strtol(val, &end, 10);
  if (!end || *end != '\0') {
    return fallback;
  }
  return static_cast<int>(parsed);
}

unsigned int EnvUInt(const char *name, unsigned int fallback) {
  const char *val = std::getenv(name);
  if (!val || !*val) {
    return fallback;
  }
  char *end = nullptr;
  unsigned long parsed = std::strtoul(val, &end, 10);
  if (!end || *end != '\0') {
    return fallback;
  }
  return static_cast<unsigned int>(parsed);
}

void Debugf(const char *fmt, ...) {
  if (!g_debug) {
    return;
  }
  va_list args;
  va_start(args, fmt);
  std::vfprintf(stderr, fmt, args);
  std::fprintf(stderr, "\n");
  va_end(args);
}

bool MatchDevice(libusb_device *dev) {
  libusb_device_descriptor desc{};
  if (libusb_get_device_descriptor(dev, &desc) != 0) {
    return false;
  }
  return desc.idVendor == kVendorId && desc.idProduct == kProductId;
}

bool PickInterfaceAndEndpoints(libusb_device *dev, SensorHandle *out) {
  libusb_config_descriptor *config = nullptr;
  if (libusb_get_active_config_descriptor(dev, &config) != 0 || !config) {
    return false;
  }

  bool found = false;
  for (uint8_t i = 0; i < config->bNumInterfaces && !found; ++i) {
    const libusb_interface &iface = config->interface[i];
    for (int a = 0; a < iface.num_altsetting && !found; ++a) {
      const libusb_interface_descriptor &alt = iface.altsetting[a];
      uint8_t ep_in = 0;
      uint8_t ep_out = 0;
      for (uint8_t e = 0; e < alt.bNumEndpoints; ++e) {
        const libusb_endpoint_descriptor &ep = alt.endpoint[e];
        uint8_t type = ep.bmAttributes & LIBUSB_TRANSFER_TYPE_MASK;
        if (type != LIBUSB_TRANSFER_TYPE_BULK) {
          continue;
        }
        if ((ep.bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN) {
          if (!ep_in) {
            ep_in = ep.bEndpointAddress;
          }
        } else {
          if (!ep_out) {
            ep_out = ep.bEndpointAddress;
          }
        }
      }
      if (ep_in) {
        out->iface = alt.bInterfaceNumber;
        out->ep_in = ep_in;
        out->ep_out = ep_out;
        found = true;
      }
    }
  }

  libusb_free_config_descriptor(config);
  return found;
}

int ControlTransfer(libusb_device_handle *handle, uint8_t bm, uint8_t req, uint16_t value, uint16_t index,
                    unsigned char *data, uint16_t length, unsigned int timeout_ms) {
  if (!handle) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }
  return libusb_control_transfer(handle, bm, req, value, index, data, length, timeout_ms);
}

int BulkRead(SensorHandle *handle, unsigned char *buf, unsigned int size, unsigned int timeout_ms) {
  if (!handle || !handle->handle || !handle->ep_in) {
    return LIBUSB_ERROR_INVALID_PARAM;
  }
  int transferred = 0;
  int res = libusb_bulk_transfer(handle->handle, handle->ep_in, buf, static_cast<int>(size), &transferred,
                                 timeout_ms);
  if (res == LIBUSB_ERROR_TIMEOUT) {
    return 0;
  }
  if (res != 0) {
    Debugf("bulk read failed: %d", res);
    return res;
  }
  return transferred;
}

int ZKFPI_SetGPIO(SensorHandle *handle, uint8_t gpio, int value) {
  if (!handle || !handle->handle) {
    return -19;
  }
  return ControlTransfer(handle->handle, 0x40, 0xE1, static_cast<uint16_t>(value), gpio, nullptr, 0,
                         kDefaultTimeoutMs);
}

int ZKFPI_GetGPIO(SensorHandle *handle, uint8_t gpio, unsigned char *data, int len) {
  if (!handle || !handle->handle) {
    return -19;
  }
  int res = ControlTransfer(handle->handle, 0xC0, 0xE2, 0, gpio, data, static_cast<uint16_t>(len),
                            kDefaultTimeoutMs);
  if (res == len) {
    return 0;
  }
  return res;
}

int ZKFPI_ReadCamera(SensorHandle *handle, uint8_t reg, unsigned char *data) {
  if (!handle || !handle->handle) {
    return -19;
  }
  int res = ControlTransfer(handle->handle, 0xC0, 0xE4, 0, reg, data, 2, kDefaultTimeoutMs);
  if (res == 2) {
    return 0;
  }
  return res;
}

int ZKFPI_WriteCamera(SensorHandle *handle, uint8_t reg, uint8_t value) {
  if (!handle || !handle->handle) {
    return -19;
  }
  return ControlTransfer(handle->handle, 0x40, 0xE3, value, reg, nullptr, 0, kDefaultTimeoutMs);
}

int ZKFPI_ReadEeprom(SensorHandle *handle, uint8_t addr, unsigned char *out) {
  if (!handle || !handle->handle) {
    return -19;
  }
  int res = ControlTransfer(handle->handle, 0xC0, 0xE7, 0, addr, out, 1, kDefaultTimeoutMs);
  if (res == 1) {
    return 0;
  }
  return res;
}

int ZKFPI_ReadEEPROM2(SensorHandle *handle, int addr, int len, unsigned char *out) {
  if (len <= 0) {
    return len;
  }
  int end = addr + len;
  while (addr < end) {
    unsigned char val = 0;
    if (ZKFPI_ReadEeprom(handle, static_cast<uint8_t>(addr), &val) != 0) {
      return 0;
    }
    *out++ = val;
    ++addr;
  }
  return len;
}

int ZKFPI_GetImage(SensorHandle *handle, unsigned char *out, unsigned int size) {
  if (!handle || !handle->handle) {
    return -19;
  }
  int res = ControlTransfer(handle->handle, 0x40, 0xE5, 0, 0, nullptr, 0, kDefaultTimeoutMs);
  if (res < 0) {
    return res;
  }
  return BulkRead(handle, out, size, kDefaultTimeoutMs);
}

int ZKFPI_DetImage(SensorHandle *handle, unsigned char *out, unsigned int size) {
  if (!handle || !handle->handle) {
    return -19;
  }
  unsigned char status = 0;
  int res = ControlTransfer(handle->handle, 0xC0, 0xEA, 0, 0, &status, 1, kDefaultTimeoutMs);
  if (res < 0) {
    return res;
  }
  if (status == 1) {
    return BulkRead(handle, out, size, kDefaultTimeoutMs);
  }
  return 0;
}

int ZKFPI_GetModel(SensorHandle *handle, unsigned char *out, uint8_t len) {
  if (!handle || !handle->handle || !handle->dev) {
    return -19;
  }
  libusb_device_descriptor desc{};
  if (libusb_get_device_descriptor(handle->dev, &desc) != 0) {
    return -19;
  }
  if (desc.iProduct == 0) {
    return -19;
  }
  return libusb_get_string_descriptor_ascii(handle->handle, desc.iProduct, out, len);
}

int ZKFPI_GetManufacturer(SensorHandle *handle, unsigned char *out, uint8_t len) {
  if (!handle || !handle->handle || !handle->dev) {
    return -19;
  }
  libusb_device_descriptor desc{};
  if (libusb_get_device_descriptor(handle->dev, &desc) != 0) {
    return -19;
  }
  if (desc.iManufacturer == 0) {
    return -19;
  }
  return libusb_get_string_descriptor_ascii(handle->handle, desc.iManufacturer, out, len);
}

int ZKFPI_GetVID_PID_REV(SensorHandle *handle, int *vid, int *pid, int *rev) {
  if (!handle || !handle->dev) {
    return -19;
  }
  libusb_device_descriptor desc{};
  if (libusb_get_device_descriptor(handle->dev, &desc) != 0) {
    return -19;
  }
  if (vid) {
    *vid = desc.idVendor;
  }
  if (pid) {
    *pid = desc.idProduct;
  }
  if (rev) {
    *rev = desc.bcdDevice;
  }
  return 0;
}

SensorHandle *ZKFPI_OpenByIndex(unsigned int index) {
  if (!g_ctx) {
    return nullptr;
  }
  libusb_device **list = nullptr;
  ssize_t count = libusb_get_device_list(g_ctx, &list);
  if (count < 0) {
    return nullptr;
  }

  libusb_device *picked = nullptr;
  unsigned int found = 0;
  for (ssize_t i = 0; i < count; ++i) {
    if (!MatchDevice(list[i])) {
      continue;
    }
    if (found == index) {
      picked = list[i];
      break;
    }
    ++found;
  }

  SensorHandle *handle = nullptr;
  if (picked) {
    libusb_device_handle *dev_handle = nullptr;
    if (libusb_open(picked, &dev_handle) == 0 && dev_handle) {
      libusb_set_auto_detach_kernel_driver(dev_handle, 1);
      handle = new SensorHandle();
      handle->dev = picked;
      handle->handle = dev_handle;
      libusb_ref_device(picked);
      if (!PickInterfaceAndEndpoints(picked, handle)) {
        Debugf("no suitable interface/endpoints found");
      } else {
        if (libusb_claim_interface(dev_handle, handle->iface) != 0) {
          Debugf("failed to claim interface %u", handle->iface);
        }
      }
      int res = ControlTransfer(dev_handle, 0x40, 0xE0, 0, 0, nullptr, 0, kDefaultTimeoutMs);
      if (res < 0) {
        Debugf("open init control transfer failed: %d", res);
      }
    }
  }

  libusb_free_device_list(list, 1);
  return handle;
}

void ZKFPI_Close(SensorHandle *handle) {
  if (!handle) {
    return;
  }
  if (handle->handle) {
    libusb_release_interface(handle->handle, handle->iface);
    libusb_close(handle->handle);
  }
  if (handle->dev) {
    libusb_unref_device(handle->dev);
  }
  delete handle;
}

} // namespace

extern "C" {

int sensorInit() {
  if (g_ctx) {
    return 0;
  }
  g_debug = EnvFlag("ZKFP_USB_DEBUG");
  int res = libusb_init(&g_ctx);
  if (res != 0) {
    g_ctx = nullptr;
    return res;
  }
  return 0;
}

int sensorFree() {
  if (g_ctx) {
    libusb_exit(g_ctx);
    g_ctx = nullptr;
  }
  return 0;
}

int sensorGetCount() {
  if (!g_ctx) {
    return 0;
  }
  libusb_device **list = nullptr;
  ssize_t count = libusb_get_device_list(g_ctx, &list);
  if (count < 0) {
    return 0;
  }
  int matched = 0;
  for (ssize_t i = 0; i < count; ++i) {
    if (MatchDevice(list[i])) {
      ++matched;
    }
  }
  libusb_free_device_list(list, 1);
  return matched;
}

void *sensorOpen(unsigned int index) {
  SensorHandle *handle = ZKFPI_OpenByIndex(index);
  if (!handle || !handle->handle) {
    ZKFPI_Close(handle);
    return nullptr;
  }

  handle->width = EnvInt("ZKFP_WIDTH", kDefaultWidth);
  handle->height = EnvInt("ZKFP_HEIGHT", kDefaultHeight);
  handle->dpi = EnvInt("ZKFP_DPI", kDefaultDpi);
  handle->raw_width = EnvInt("ZKFP_RAW_WIDTH", 0);
  handle->raw_height = EnvInt("ZKFP_RAW_HEIGHT", 0);

  unsigned char gpio_vals[2] = {0, 0};
  if (ZKFPI_GetGPIO(handle, 0x55, gpio_vals, 2) == 0) {
    handle->det_mode = gpio_vals[0] > 4 || gpio_vals[1] > 1;
  }

  ZKFPI_SetGPIO(handle, 6, 32769);
  ZKFPI_SetGPIO(handle, 7, 32769);

  return handle;
}

int sensorClose(void *handle) {
  auto *h = static_cast<SensorHandle *>(handle);
  if (!h) {
    return 0;
  }
  ZKFPI_Close(h);
  return 0;
}

int sensorCapture(void *handle, unsigned char *image, unsigned int size) {
  auto *h = static_cast<SensorHandle *>(handle);
  if (!h || !image) {
    return -2;
  }

  std::lock_guard<std::mutex> guard(h->lock);

  int raw_width = h->raw_width > 0 ? h->raw_width : h->width;
  int raw_height = h->raw_height > 0 ? h->raw_height : h->height;
  unsigned int raw_size = static_cast<unsigned int>(raw_width * raw_height);

  if (raw_size == 0) {
    return -2;
  }

  std::vector<unsigned char> temp;
  unsigned char *dst = image;
  if (raw_size != size) {
    temp.resize(raw_size);
    dst = temp.data();
  }

  int res = 0;
  if (h->det_mode) {
    res = ZKFPI_DetImage(h, dst, raw_size);
  } else {
    res = ZKFPI_GetImage(h, dst, raw_size);
  }

  if (res <= 0) {
    return res;
  }

  if (dst != image) {
    unsigned int copy_size = size < raw_size ? size : raw_size;
    std::memcpy(image, dst, copy_size);
    return static_cast<int>(copy_size);
  }

  return res;
}

int sensorSetParameterEx(void *handle, int paramCode, unsigned char *paramValue, unsigned int cbParamValue) {
  auto *h = static_cast<SensorHandle *>(handle);
  if (!h || !paramValue || cbParamValue < sizeof(uint32_t)) {
    return -2;
  }
  uint32_t val = *reinterpret_cast<uint32_t *>(paramValue);
  if (paramCode == 1) {
    h->width = static_cast<int>(val);
    return 0;
  }
  if (paramCode == 2) {
    h->height = static_cast<int>(val);
    return 0;
  }
  if (paramCode == 3) {
    h->dpi = static_cast<int>(val);
    return 0;
  }
  return -5;
}

int sensorGetParameterEx(void *handle, int paramCode, unsigned char *paramValue, unsigned int *cbParamValue) {
  auto *h = static_cast<SensorHandle *>(handle);
  if (!h || !paramValue || !cbParamValue || *cbParamValue < sizeof(uint32_t)) {
    return -2;
  }
  uint32_t val = 0;
  if (paramCode == 1) {
    val = static_cast<uint32_t>(h->width);
  } else if (paramCode == 2) {
    val = static_cast<uint32_t>(h->height);
  } else if (paramCode == 3) {
    val = static_cast<uint32_t>(h->dpi);
  } else {
    return -5;
  }
  std::memcpy(paramValue, &val, sizeof(val));
  *cbParamValue = sizeof(val);
  return 0;
}

int sensorGetParameter(void *handle, int paramCode) {
  auto *h = static_cast<SensorHandle *>(handle);
  if (!h) {
    return -2;
  }
  if (paramCode == 1) {
    return h->width;
  }
  if (paramCode == 2) {
    return h->height;
  }
  if (paramCode == 3) {
    return h->dpi;
  }
  return -5;
}

int sensorSetParameter(void *handle, int paramCode, int value) {
  auto *h = static_cast<SensorHandle *>(handle);
  if (!h) {
    return -2;
  }
  if (paramCode == 1) {
    h->width = value;
    return 0;
  }
  if (paramCode == 2) {
    h->height = value;
    return 0;
  }
  if (paramCode == 3) {
    h->dpi = value;
    return 0;
  }
  return -5;
}

int sensorCheckLic(void *, unsigned int v1, void *) {
  return static_cast<int>((100u * v1) ^ 0x85948B9Au);
}

} // extern "C"
