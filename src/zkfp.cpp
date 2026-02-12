#include "libzkfp.h"
#include "libzkfperrdef.h"

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <sys/time.h>

extern "C" {
int sensorInit();
int sensorFree();
int sensorGetCount();
void *sensorOpen(unsigned int index);
int sensorClose(void *handle);
int sensorCapture(void *handle, unsigned char *image, unsigned int size);
int sensorSetParameterEx(void *handle, int paramCode, unsigned char *paramValue, unsigned int cbParamValue);
int sensorGetParameterEx(void *handle, int paramCode, unsigned char *paramValue, unsigned int *cbParamValue);
int sensorGetParameter(void *handle, int paramCode);
int sensorCheckLic(void *handle, unsigned int v1, void *v2);

void *BIOKEY_INIT(long a1, const void *cfg, long a3, long a4, long a5);
int BIOKEY_CLOSE();
int BIOKEY_SET_CHECK_CALLBACK(int (*cb)(unsigned int, void *), void *user);
int BIOKEY_SET_PARAMETER(void *db, long code, long value);
int BIOKEY_GET_PARAMETER(void *db, long code, long value, int *out);
int BIOKEY_MATCHINGPARAM(void *db, long type, unsigned int value);
int BIOKEY_DB_CLEAR(void *db);
int BIOKEY_DB_ADD(void *db, unsigned int fid, unsigned int size, unsigned char *templ);
int BIOKEY_DB_DEL(void *db, unsigned int fid);
int BIOKEY_VERIFY(void *db, const unsigned char *t1, const unsigned char *t2);
int BIOKEY_VERIFYBYID(void *db, unsigned int fid, const unsigned char *templ);
int BIOKEY_GENTEMPLATE_SP(void *db, const unsigned char *t1, const unsigned char *t2, const unsigned char *t3,
                          int count, unsigned char *out);
int BIOKEY_EXTRACT_GRAYSCALEDATA(void *db, const unsigned char *image, unsigned int width, unsigned int height,
                                 unsigned char *out, unsigned int outLen, int flag);
int BIOKEY_IDENTIFYTEMP(void *db, const unsigned char *templ, unsigned int size, unsigned int *fid);
int BIOKEY_GETLASTERROR();
}

namespace {

constexpr uint32_t kDeviceMagic = 0x12345678u;

struct DeviceHandle {
  uint32_t magic;
  uint32_t reserved0;
  void *sensor;
  uint32_t reserved1;
  uint32_t width;
  uint32_t height;
  uint32_t dpi;
};
static_assert(sizeof(DeviceHandle) == 0x20, "DeviceHandle size");

struct DBCacheHandle {
  void *db;
  uint32_t count;
  uint32_t threshold_1;
  uint32_t threshold_n;
  uint32_t reserved0;
  void *last_img;
  uint32_t last_w;
  uint32_t last_h;
  uint64_t param_10001;
};
static_assert(sizeof(DBCacheHandle) == 0x30, "DBCacheHandle size");

static int g_bInited = 0;
static void *g_hDevice = nullptr;
static DBCacheHandle g_DBCacheHandle{};

static int CheckValue(unsigned int v1, void *v2) {
  return sensorCheckLic(g_hDevice, v1, v2);
}

static unsigned int GetTickCount() {
  timeval tv{};
  gettimeofday(&tv, nullptr);
  return static_cast<unsigned int>(tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

static void InitFP(int width, int height) {
  if (g_DBCacheHandle.db) {
    return;
  }

  BIOKEY_SET_PARAMETER(nullptr, 5007, 2);
  BIOKEY_SET_CHECK_CALLBACK(CheckValue, nullptr);
  std::memset(&g_DBCacheHandle, 0, sizeof(g_DBCacheHandle));

  uint16_t cfg[36] = {0};
  cfg[20] = static_cast<uint16_t>(width);
  cfg[21] = static_cast<uint16_t>(height);
  cfg[0] = static_cast<uint16_t>(width);
  cfg[1] = static_cast<uint16_t>(height);

  g_DBCacheHandle.db = BIOKEY_INIT(0, cfg, 0, 0, 128);
  if (g_DBCacheHandle.db) {
    g_DBCacheHandle.threshold_1 = 35;
    g_DBCacheHandle.threshold_n = 55;
    BIOKEY_SET_PARAMETER(g_DBCacheHandle.db, 4, 180);
    BIOKEY_MATCHINGPARAM(g_DBCacheHandle.db, 0, g_DBCacheHandle.threshold_n);
  }
}

static bool IsValidDeviceHandle(const DeviceHandle *dev) {
  return dev && dev->magic == kDeviceMagic;
}

static bool IsValidDBHandle(const void *handle) {
  return handle && handle == &g_DBCacheHandle;
}

static std::string Base64Encode(const uint8_t *data, size_t len) {
  static const char kB64[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  for (size_t i = 0; i < len; i += 3) {
    uint32_t v = data[i] << 16;
    if (i + 1 < len) v |= data[i + 1] << 8;
    if (i + 2 < len) v |= data[i + 2];

    out.push_back(kB64[(v >> 18) & 0x3F]);
    out.push_back(kB64[(v >> 12) & 0x3F]);
    out.push_back(i + 1 < len ? kB64[(v >> 6) & 0x3F] : '=');
    out.push_back(i + 2 < len ? kB64[v & 0x3F] : '=');
  }
  return out;
}

static bool IsBase64Char(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

static bool Base64Decode(const char *input, std::vector<uint8_t> &out) {
  auto decode_val = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
  };

  size_t len = std::strlen(input);
  if ((len & 3) != 0) {
    return false;
  }
  for (size_t i = 0; i < len; ++i) {
    if (!IsBase64Char(input[i])) {
      return false;
    }
  }

  out.clear();
  out.reserve((len / 4) * 3);

  for (size_t i = 0; i < len; i += 4) {
    int v0 = decode_val(input[i]);
    int v1 = decode_val(input[i + 1]);
    if (v0 < 0 || v1 < 0) return false;
    int v2 = input[i + 2] == '=' ? -1 : decode_val(input[i + 2]);
    int v3 = input[i + 3] == '=' ? -1 : decode_val(input[i + 3]);
    if ((v2 < 0 && input[i + 2] != '=') || (v3 < 0 && input[i + 3] != '=')) {
      return false;
    }

    uint32_t triple = (v0 << 18) | (v1 << 12) | ((v2 < 0 ? 0 : v2) << 6) | (v3 < 0 ? 0 : v3);
    out.push_back((triple >> 16) & 0xFF);
    if (input[i + 2] != '=') out.push_back((triple >> 8) & 0xFF);
    if (input[i + 3] != '=') out.push_back(triple & 0xFF);
  }

  return true;
}

} // namespace

extern "C" {

int APICALL ZKFPM_Init() {
  if (g_bInited) {
    return ZKFP_ERR_ALREADY_INIT;
  }
  unsigned int ret = sensorInit();
  if (ret) {
    return ZKFP_ERR_INIT;
  }
  if (sensorGetCount() <= 0) {
    sensorFree();
    return ZKFP_ERR_NO_DEVICE;
  }
  g_bInited = 1;
  return static_cast<int>(ret);
}

int APICALL ZKFPM_Terminate() {
  if (g_bInited) {
    if (g_DBCacheHandle.db) {
      BIOKEY_CLOSE();
    }
    std::memset(&g_DBCacheHandle, 0, sizeof(g_DBCacheHandle));
    sensorFree();
    g_bInited = 0;
  }
  return ZKFP_ERR_OK;
}

int APICALL ZKFPM_GetDeviceCount() {
  if (!g_bInited) {
    return ZKFP_ERR_INIT;
  }
  return sensorGetCount();
}

HANDLE APICALL ZKFPM_OpenDevice(int index) {
  if (!g_bInited) {
    return nullptr;
  }
  if (index < 0 || sensorGetCount() <= index) {
    return nullptr;
  }

  void *sensor = sensorOpen(static_cast<unsigned int>(index));
  if (!sensor) {
    return nullptr;
  }

  auto *dev = static_cast<DeviceHandle *>(operator new(sizeof(DeviceHandle)));
  std::memset(dev, 0, sizeof(DeviceHandle));
  dev->magic = kDeviceMagic;
  dev->sensor = sensor;
  dev->width = static_cast<uint32_t>(sensorGetParameter(sensor, 1));
  dev->height = static_cast<uint32_t>(sensorGetParameter(sensor, 2));

  g_hDevice = sensor;
  InitFP(static_cast<int>(dev->width), static_cast<int>(dev->height));
  if (g_DBCacheHandle.db) {
    return dev;
  }

  std::puts("Init zkfinger10 failed");
  operator delete(dev);
  return nullptr;
}

int APICALL ZKFPM_CloseDevice(HANDLE hDevice) {
  auto *dev = static_cast<DeviceHandle *>(hDevice);
  if (!dev) {
    return ZKFP_ERR_INVALID_PARAM;
  }
  if (!IsValidDeviceHandle(dev)) {
    return ZKFP_ERR_INVALID_HANDLE;
  }
  if (!g_bInited) {
    return ZKFP_ERR_INIT;
  }

  sensorClose(dev->sensor);
  operator delete(dev);
  return ZKFP_ERR_OK;
}

int APICALL ZKFPM_SetParameters(HANDLE hDevice, int nParamCode, unsigned char *paramValue, unsigned int cbParamValue) {
  auto *dev = static_cast<DeviceHandle *>(hDevice);
  if (!dev) {
    return ZKFP_ERR_INVALID_PARAM;
  }
  if (!IsValidDeviceHandle(dev)) {
    return ZKFP_ERR_INVALID_HANDLE;
  }
  if (!g_bInited) {
    return ZKFP_ERR_INIT;
  }

  if (nParamCode == 10001) {
    if (cbParamValue <= 3 || !paramValue) {
      return ZKFP_ERR_INVALID_PARAM;
    }
    uint32_t val = *reinterpret_cast<uint32_t *>(paramValue);
    if (val == 1) {
      g_DBCacheHandle.param_10001 = 1;
    } else {
      g_DBCacheHandle.param_10001 = 0;
      val = 0;
    }
    BIOKEY_SET_PARAMETER(g_DBCacheHandle.db, 5010, val);
    return ZKFP_ERR_OK;
  }

  int ret = sensorSetParameterEx(dev->sensor, nParamCode, paramValue, cbParamValue);
  if (ret == 0 && nParamCode == 3) {
    dev->width = static_cast<uint32_t>(sensorGetParameter(dev->sensor, 1));
    dev->height = static_cast<uint32_t>(sensorGetParameter(dev->sensor, 2));
    dev->dpi = static_cast<uint32_t>(sensorGetParameter(dev->sensor, 3));
  }
  return ret;
}

int APICALL ZKFPM_GetParameters(HANDLE hDevice, int nParamCode, unsigned char *paramValue, unsigned int *cbParamValue) {
  auto *dev = static_cast<DeviceHandle *>(hDevice);
  if (!dev) {
    return ZKFP_ERR_INVALID_PARAM;
  }
  if (!IsValidDeviceHandle(dev)) {
    return ZKFP_ERR_INVALID_HANDLE;
  }
  if (!g_bInited) {
    return ZKFP_ERR_INIT;
  }

  if (nParamCode == 10001) {
    if (!cbParamValue || *cbParamValue <= 3 || !paramValue) {
      return ZKFP_ERR_INVALID_PARAM;
    }
    *reinterpret_cast<uint32_t *>(paramValue) = static_cast<uint32_t>(g_DBCacheHandle.param_10001);
    *cbParamValue = 4;
    return ZKFP_ERR_OK;
  }

  return sensorGetParameterEx(dev->sensor, nParamCode, paramValue, cbParamValue);
}

int APICALL ZKFPM_GetCaptureParams(HANDLE hDevice, TZKFPCapParams *params) {
  auto *dev = static_cast<DeviceHandle *>(hDevice);
  if (!dev || !params) {
    return ZKFP_ERR_INVALID_PARAM;
  }
  if (!IsValidDeviceHandle(dev)) {
    return ZKFP_ERR_INVALID_HANDLE;
  }
  if (!g_bInited) {
    return ZKFP_ERR_INIT;
  }

  params->imgWidth = dev->width;
  params->imgHeight = dev->height;
  params->nDPI = dev->dpi;
  return ZKFP_ERR_OK;
}

int APICALL ZKFPM_GetCaptureParamsEx(HANDLE hDevice, unsigned int *width, unsigned int *height, unsigned int *dpi) {
  TZKFPCapParams params{};
  int ret = ZKFPM_GetCaptureParams(hDevice, &params);
  if (ret == ZKFP_ERR_OK) {
    if (width) *width = params.imgWidth;
    if (height) *height = params.imgHeight;
    if (dpi) *dpi = params.nDPI;
  }
  return ret;
}

int APICALL ZKFPM_AcquireFingerprintImage(HANDLE hDevice, unsigned char *fpImage, unsigned int cbFPImage) {
  auto *dev = static_cast<DeviceHandle *>(hDevice);
  if (!dev || !fpImage) {
    return ZKFP_ERR_INVALID_PARAM;
  }
  if (!IsValidDeviceHandle(dev)) {
    return ZKFP_ERR_INVALID_HANDLE;
  }
  if (dev->width * dev->height > cbFPImage) {
    return ZKFP_ERR_INVALID_PARAM;
  }
  if (!g_bInited) {
    return ZKFP_ERR_INIT;
  }

  std::memset(fpImage, 0, cbFPImage);
  unsigned int start = GetTickCount();
  while (sensorCapture(dev->sensor, fpImage, cbFPImage) <= 0) {
    if (GetTickCount() - start > 0x1F4) {
      return ZKFP_ERR_CAPTURE;
    }
  }
  return ZKFP_ERR_OK;
}

int APICALL ZKFPM_AcquireFingerprint(HANDLE hDevice, unsigned char *fpImage, unsigned int cbFPImage,
                                    unsigned char *fpTemplate, unsigned int *cbTemplate) {
  auto *dev = static_cast<DeviceHandle *>(hDevice);
  if (!dev || !fpImage || !fpTemplate || !cbTemplate || *cbTemplate <= 0) {
    return ZKFP_ERR_INVALID_PARAM;
  }
  if (!IsValidDeviceHandle(dev)) {
    return ZKFP_ERR_INVALID_HANDLE;
  }
  if (!g_bInited) {
    return ZKFP_ERR_INIT;
  }

  if (sensorCapture(dev->sensor, fpImage, cbFPImage) <= 0) {
    return ZKFP_ERR_CAPTURE;
  }

  unsigned char tmp[2048] = {0};
  int len = BIOKEY_EXTRACT_GRAYSCALEDATA(g_DBCacheHandle.db, fpImage, dev->width, dev->height,
                                        tmp, 2048, 0);
  if (len <= 0) {
    return ZKFP_ERR_EXTRACT_FP;
  }
  if (len > static_cast<int>(*cbTemplate)) {
    return ZKFP_ERR_MEMORY_NOT_ENOUGH;
  }
  std::memcpy(fpTemplate, tmp, static_cast<size_t>(len));
  *cbTemplate = static_cast<unsigned int>(len);
  return ZKFP_ERR_OK;
}

HANDLE APICALL ZKFPM_DBInit() {
  return ZKFPM_CreateDBCache();
}

int APICALL ZKFPM_DBFree(HANDLE hDBCache) {
  return ZKFPM_CloseDBCache(hDBCache);
}

int APICALL ZKFPM_DBSetParameter(HANDLE, int, unsigned char *, unsigned int) {
  return ZKFP_ERR_NOT_SUPPORT;
}

int APICALL ZKFPM_DBGetParameter(HANDLE, int, unsigned char *, unsigned int) {
  return ZKFP_ERR_NOT_SUPPORT;
}

int APICALL ZKFPM_DBMerge(HANDLE hDBCache, unsigned char *temp1, unsigned char *temp2, unsigned char *temp3,
                          unsigned char *regTemp, unsigned int *cbRegTemp) {
  return ZKFPM_GenRegTemplate(hDBCache, temp1, temp2, temp3, regTemp, cbRegTemp);
}

int APICALL ZKFPM_DBAdd(HANDLE hDBCache, unsigned int fid, unsigned char *fpTemplate, unsigned int cbTemplate) {
  return ZKFPM_AddRegTemplateToDBCache(hDBCache, fid, fpTemplate, cbTemplate);
}

int APICALL ZKFPM_DBDel(HANDLE hDBCache, unsigned int fid) {
  return ZKFPM_DelRegTemplateFromDBCache(hDBCache, fid);
}

int APICALL ZKFPM_DBClear(HANDLE hDBCache) {
  return ZKFPM_ClearDBCache(hDBCache);
}

int APICALL ZKFPM_DBCount(HANDLE hDBCache, unsigned int *fpCount) {
  return ZKFPM_GetDBCacheCount(hDBCache, fpCount);
}

int APICALL ZKFPM_DBIdentify(HANDLE hDBCache, unsigned char *fpTemplate, unsigned int cbTemplate,
                             unsigned int *FID, unsigned int *score) {
  return ZKFPM_Identify(hDBCache, fpTemplate, cbTemplate, FID, score);
}

int APICALL ZKFPM_DBMatch(HANDLE hDBCache, unsigned char *template1, unsigned int cbTemplate1,
                          unsigned char *template2, unsigned int cbTemplate2) {
  return ZKFPM_MatchFinger(hDBCache, template1, cbTemplate1, template2, cbTemplate2);
}

int APICALL ZKFPM_ExtractFromImage(HANDLE, const char *, unsigned int, unsigned char *, unsigned int *) {
  return ZKFP_ERR_NOT_SUPPORT;
}

HANDLE APICALL ZKFPM_CreateDBCache() {
  return &g_DBCacheHandle;
}

int APICALL ZKFPM_CloseDBCache(HANDLE hDBCache) {
  if (!IsValidDBHandle(hDBCache)) {
    return ZKFP_ERR_INVALID_HANDLE;
  }
  BIOKEY_DB_CLEAR(g_DBCacheHandle.db);
  g_DBCacheHandle.count = 0;
  return ZKFP_ERR_OK;
}

int APICALL ZKFPM_ClearDBCache(HANDLE hDBCache) {
  if (!IsValidDBHandle(hDBCache)) {
    return ZKFP_ERR_INVALID_HANDLE;
  }
  BIOKEY_DB_CLEAR(g_DBCacheHandle.db);
  g_DBCacheHandle.count = 0;
  return ZKFP_ERR_OK;
}

int APICALL ZKFPM_GetDBCacheCount(HANDLE hDBCache, unsigned int *fpCount) {
  if (!IsValidDBHandle(hDBCache)) {
    return ZKFP_ERR_INVALID_HANDLE;
  }
  if (!fpCount) {
    return ZKFP_ERR_INVALID_PARAM;
  }
  *fpCount = g_DBCacheHandle.count;
  return ZKFP_ERR_OK;
}

int APICALL ZKFPM_AddRegTemplateToDBCache(HANDLE hDBCache, unsigned int fid, unsigned char *fpTemplate,
                                         unsigned int cbTemplate) {
  if (!IsValidDBHandle(hDBCache)) {
    return ZKFP_ERR_INVALID_HANDLE;
  }
  if (!fid || !fpTemplate || cbTemplate == 0) {
    return ZKFP_ERR_INVALID_PARAM;
  }

  int ret = BIOKEY_DB_ADD(g_DBCacheHandle.db, fid, cbTemplate, fpTemplate);
  BIOKEY_GETLASTERROR();
  if (ret <= 0) {
    return ZKFP_ERR_ADD_FINGER;
  }
  g_DBCacheHandle.count += 1;
  return ZKFP_ERR_OK;
}

int APICALL ZKFPM_DelRegTemplateFromDBCache(HANDLE hDBCache, unsigned int fid) {
  if (!IsValidDBHandle(hDBCache)) {
    return ZKFP_ERR_INVALID_HANDLE;
  }
  BIOKEY_DB_DEL(g_DBCacheHandle.db, fid);
  g_DBCacheHandle.count -= 1;
  return ZKFP_ERR_OK;
}

int APICALL ZKFPM_GenRegTemplate(HANDLE hDBCache, unsigned char *temp1, unsigned char *temp2,
                                unsigned char *temp3, unsigned char *regTemp, unsigned int *cbRegTemp) {
  if (!IsValidDBHandle(hDBCache)) {
    return ZKFP_ERR_INVALID_HANDLE;
  }
  if (!temp1 || !temp2 || !temp3 || !regTemp || !cbRegTemp) {
    return ZKFP_ERR_INVALID_PARAM;
  }

  unsigned char tmp[2048] = {0};
  int len = BIOKEY_GENTEMPLATE_SP(g_DBCacheHandle.db, temp1, temp2, temp3, 3, tmp);
  if (len <= 0) {
    return ZKFP_ERR_MERGE;
  }
  if (len > static_cast<int>(*cbRegTemp)) {
    return ZKFP_ERR_MEMORY_NOT_ENOUGH;
  }
  std::memcpy(regTemp, tmp, static_cast<size_t>(len));
  *cbRegTemp = static_cast<unsigned int>(len);
  return ZKFP_ERR_OK;
}

int APICALL ZKFPM_Identify(HANDLE hDBCache, unsigned char *fpTemplate, unsigned int cbTemplate,
                           unsigned int *FID, unsigned int *score) {
  if (!IsValidDBHandle(hDBCache)) {
    return ZKFP_ERR_INVALID_HANDLE;
  }
  if (!fpTemplate || !cbTemplate) {
    return ZKFP_ERR_INVALID_PARAM;
  }
  if (!FID) {
    return ZKFP_ERR_INVALID_PARAM;
  }

  int ret = BIOKEY_IDENTIFYTEMP(g_DBCacheHandle.db, fpTemplate, cbTemplate, FID);
  if (ret > 0) {
    if (*FID == 0) {
      return ZKFP_ERR_FAIL;
    }
    if (score) {
      *score = static_cast<unsigned int>(ret);
    }
    return ZKFP_ERR_OK;
  }
  return ZKFP_ERR_FAIL;
}

int APICALL ZKFPM_MatchFinger(HANDLE hDBCache, unsigned char *template1, unsigned int cbTemplate1,
                              unsigned char *template2, unsigned int cbTemplate2) {
  if (!IsValidDBHandle(hDBCache)) {
    return ZKFP_ERR_INVALID_HANDLE;
  }
  if (!template1 || !cbTemplate1 || !template2 || !cbTemplate2) {
    return ZKFP_ERR_INVALID_PARAM;
  }

  BIOKEY_MATCHINGPARAM(g_DBCacheHandle.db, 0, g_DBCacheHandle.threshold_1);
  int score = BIOKEY_VERIFY(g_DBCacheHandle.db, template1, template2);
  BIOKEY_MATCHINGPARAM(g_DBCacheHandle.db, 0, g_DBCacheHandle.threshold_n);
  return score;
}

int APICALL ZKFPM_VerifyByID(HANDLE hDBCache, unsigned int fid, unsigned char *fpTemplate,
                             unsigned int cbTemplate) {
  if (!IsValidDBHandle(hDBCache)) {
    return ZKFP_ERR_INVALID_HANDLE;
  }
  if (!fpTemplate || !cbTemplate) {
    return ZKFP_ERR_INVALID_PARAM;
  }

  BIOKEY_MATCHINGPARAM(g_DBCacheHandle.db, 0, g_DBCacheHandle.threshold_1);
  int score = BIOKEY_VERIFYBYID(g_DBCacheHandle.db, fid, fpTemplate);
  BIOKEY_MATCHINGPARAM(g_DBCacheHandle.db, 0, g_DBCacheHandle.threshold_n);
  return score;
}

int APICALL ZKFPM_GetLastExtractImage() {
  return 0;
}

int APICALL ZKFPM_Base64ToBlob(const char *base64, void *outBlob, unsigned int outLen) {
  if (!base64 || !outBlob || !outLen) {
    return ZKFP_ERR_INVALID_PARAM;
  }
  if ((std::strlen(base64) & 3) != 0) {
    return ZKFP_ERR_INVALID_PARAM;
  }

  std::vector<uint8_t> decoded;
  if (!Base64Decode(base64, decoded)) {
    return ZKFP_ERR_INVALID_PARAM;
  }
  if (outLen < decoded.size()) {
    return ZKFP_ERR_MEMORY_NOT_ENOUGH;
  }
  std::memcpy(outBlob, decoded.data(), decoded.size());
  return static_cast<int>(decoded.size());
}

int APICALL ZKFPM_BlobToBase64(const void *blob, int blobLen, char *outBase64, unsigned int outLen) {
  if (!blob || blobLen <= 0 || !outBase64 || !outLen) {
    return ZKFP_ERR_INVALID_PARAM;
  }

  const auto *data = static_cast<const uint8_t *>(blob);
  std::string encoded = Base64Encode(data, static_cast<size_t>(blobLen));
  if (outLen < encoded.size() + 1) {
    return ZKFP_ERR_MEMORY_NOT_ENOUGH;
  }
  std::memcpy(outBase64, encoded.data(), encoded.size());
  outBase64[encoded.size()] = '\0';
  return static_cast<int>(encoded.size());
}

} // extern "C"
