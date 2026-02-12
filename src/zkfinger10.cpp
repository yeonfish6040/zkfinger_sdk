#include "zkinterface.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sys/time.h>
#include <string>
#include <vector>

using _DWORD = unsigned int;
using _QWORD = uint64_t;
using _BOOL8 = int;

extern "C" {
int IEngine_SetParameter(long code, long value);
int IEngine_GetUserLimit(int *out);
void IEngine_GetVersionInfo(unsigned int *out);
int IEngine_InitModule();
int IEngine_TerminateModule();
int IEngine_InitWithLicense(const void *license, long len);
int IEngine_Connect(const char *conn, const char *param);
void *IEngine_InitUser();
int IEngine_FreeUser(void *user);
int IEngine_ClearUser(void *user);
int IEngine_ClearDatabase();
int IEngine_AddFingerprint(void *user, long index, void *bmp);
int IEngine_ExportUserTemplate(void *user, long index, void *out, int *len);
int IEngine_GetFingerprintQuality(void *user, long index, int *out);
int IEngine_ImportUserTemplate(void *user, long index, void *templ);
int IEngine_MatchUsers(void *user1, void *user2, int *score);
int IEngine_MatchUser(void *user, unsigned int uid, int *score, void *reserved);
int IEngine_MatchFingerprints(void *user1, long idx1, void *user2, long idx2, int *score);
int IEngine_FindUser(void *user, int *uid, int *score);
int IEngine_FindUserByQuery(void *user, const char *query, int *uid, int *score);
int IEngine_GetFingerprintCount(void *user, int *count);
int IEngine_GetUserCount(int *count);
int IEngine_GetUserIDs(int *ids, int count);
int IEngine_GetUser(void *user, unsigned int uid);
int IEngine_RegisterUserAs(void *user, unsigned int uid);
int IEngine_RemoveUser(unsigned int uid);
int IEngine_SetCustomData(void *user, const void *data, unsigned int len);
int IEngine_GetCustomData(void *user, void *data, void *len);
int IEngine_UpdateUser(void *user, unsigned int uid);
int IEngine_SetStringTag(void *user, const char *key, const char *value);
int IEngine_ConvertRawImage2Bmp(const void *raw, int w, int h, void *bmp, int *len);
}

namespace {

struct BioKeyHandle {
  uint32_t field0;
  uint32_t buf_total;
  uint32_t merge_mode;
  uint32_t img_buf_size;
  uint32_t raw_size;
  uint32_t field5;
  void *buf_base;
  void *buf_ptr;
  void *buf_base2;
  void *buf_tail;
  uint32_t field14;
  uint32_t field15;
};
static_assert(sizeof(BioKeyHandle) == 0x40, "BioKeyHandle size");

static int g_last_error = 0;
static int g_last_quality = 0;
static int g_thresh_base = 0;
static int g_thresh_step = 0;
static int g_thresh_mul = 0;
static int g_thresh_mode = 0;

static int g_width = 0;
static int g_height = 0;
static int g_ext_width = 0;
static int g_ext_height = 0;

static int g_use_extended = 0;
static uint64_t g_ext_qw[5] = {0};
static uint32_t g_ext_dw = 0;

static void *g_user_primary = nullptr;
static void *g_user_secondary = nullptr;
static void *g_user_temp = nullptr;

static int (*g_check_cb)(unsigned int, void *) = nullptr;
static void *g_check_user = nullptr;

static char g_db_name[32] = {0};
static int g_is_memory_db = 0;

static uint8_t g_buf_a[0x8000];
static uint8_t g_buf_b[0x8000];
static uint8_t g_buf_c[0x8000];

static const uint8_t g_license_blob[196] = {
    0x49, 0x43, 0x5f, 0x4c, 0x03, 0x00, 0x44, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x49, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x31, 0x37, 0x00, 0x00, 0x00, 0x00, 0x5a, 0x4b,
    0x53, 0x4f, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0xc3, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x7f, 0xf7, 0x06,
    0x1e, 0xd3, 0x15, 0x6b, 0x87, 0x49, 0xdc, 0xb9, 0xfa, 0xdb, 0x6c, 0x41,
    0x72, 0xff, 0x0c, 0xce, 0xbe, 0x73, 0xec, 0xa4, 0x23, 0xe2, 0xb5, 0x77,
    0x51, 0x70, 0xa6, 0x07, 0x21, 0xa4, 0xc2, 0x8e, 0x1d, 0xdd, 0xd2, 0x20,
    0xc5, 0xf2, 0x2d, 0x04, 0xcc, 0x0f, 0x01, 0x8e, 0x78, 0x40, 0xdc, 0x67,
    0xf9, 0x17, 0xde, 0xed, 0xc3, 0x90, 0x14, 0x4d, 0x18, 0x0e, 0x2c, 0xbd,
    0x83, 0x75, 0x76, 0x44, 0xe8, 0xfb, 0xd3, 0xfc, 0x52, 0xc3, 0x5e, 0x3c,
    0x79, 0xdf, 0x33, 0x4e, 0x14, 0x14, 0xe2, 0x47, 0x8d, 0x35, 0xc4, 0x23,
    0x1f, 0xe9, 0x51, 0xa6, 0xe6, 0x0f, 0x48, 0xbb, 0x90, 0xe1, 0x52, 0x55,
    0x4b, 0xfc, 0x33, 0x51, 0x48, 0xc7, 0x36, 0xe0, 0xe6, 0x74, 0xb1, 0x79,
    0x4e, 0x67, 0x6b, 0x75, 0xe5, 0x7e, 0x57, 0x14, 0x9a, 0x87, 0xdb, 0x63,
    0x4c, 0xb9, 0x8b, 0x8f};

static unsigned int BiokeyInterGetTemplateLen(const void *templ) {
  const auto *p = static_cast<const uint8_t *>(templ);
  return static_cast<unsigned int>(p[9]) + (static_cast<unsigned int>(p[8]) << 8);
}

static int DecodeDataWithMaxLen(void *templ, int max_len) {
  if (!templ) {
    return 0;
  }

  uint64_t key = 0;
  uint16_t key2 = 0;

  if (!std::memcmp(templ, "ICRS2", 5)) {
    std::printf("no need decode,[%x][%x][%x][%x]\n",
                static_cast<unsigned int>(static_cast<uint8_t *>(templ)[5]),
                static_cast<unsigned int>(static_cast<uint8_t *>(templ)[6]),
                static_cast<unsigned int>(static_cast<uint8_t *>(templ)[7]),
                static_cast<unsigned int>(static_cast<uint8_t *>(templ)[8]));
    return 1;
  }

  int templ_len = static_cast<int>(BiokeyInterGetTemplateLen(templ));
  if (templ_len <= 49 || templ_len > max_len) {
    return 0;
  }

  key = *reinterpret_cast<uint64_t *>(static_cast<uint8_t *>(templ) + 8);
  key2 = *reinterpret_cast<uint16_t *>(static_cast<uint8_t *>(templ) + 16);

  uint8_t *kptr = reinterpret_cast<uint8_t *>(&key) + 2;
  int idx = 2;
  while (true) {
    uint8_t v = *(kptr - 1) ^ static_cast<uint8_t>(idx++);
    *kptr ^= static_cast<uint8_t>(v + (v % 5));
    if (idx == 10) {
      break;
    }
    ++kptr;
  }

  int hdr = *reinterpret_cast<int *>(templ);
  const char *magic = "ICRS2";
  int i = 0;
  int last_i = 0;
  while (true) {
    last_i = i;
    if (-reinterpret_cast<intptr_t>(templ) == i) {
      break;
    }
    if (i == 4) {
      if (std::memcmp(templ, magic, 5)) {
        *reinterpret_cast<int *>(templ) = hdr;
        return 0;
      }
    }
    static_cast<uint8_t *>(templ)[i] ^= reinterpret_cast<uint8_t *>(&key)[i % 10];
    if (++i >= templ_len) {
      *reinterpret_cast<uint64_t *>(static_cast<uint8_t *>(templ) + 8) = key;
      *reinterpret_cast<uint16_t *>(static_cast<uint8_t *>(templ) + 16) = key2;
      break;
    }
  }

  if (std::memcmp(templ, "ICRS2", 5)) {
    if (last_i == 4) {
      *reinterpret_cast<int *>(templ) = hdr;
    }
    return 0;
  }

  return 1;
}

static int bio_DecodeData(void *templ) {
  return DecodeDataWithMaxLen(templ, 0x680);
}

static int bio_EncodeData(void *templ) {
  if (std::memcmp(templ, "ICRS2", 5)) {
    return 0;
  }
  unsigned int templ_len = BiokeyInterGetTemplateLen(templ);
  if (templ_len > 0x680) {
    return 0;
  }

  uint64_t key = *reinterpret_cast<uint64_t *>(static_cast<uint8_t *>(templ) + 8);
  uint16_t key2 = *reinterpret_cast<uint16_t *>(static_cast<uint8_t *>(templ) + 16);

  for (unsigned int i = 0; i < templ_len; ++i) {
    static_cast<uint8_t *>(templ)[i] ^= reinterpret_cast<uint8_t *>(&key)[i % 10];
  }

  uint64_t key_copy = key;
  uint16_t key2_copy = key2;
  uint8_t *kptr = reinterpret_cast<uint8_t *>(&key_copy) + 2;
  for (int i = 2; i != 10; ++i) {
    *kptr ^= static_cast<uint8_t>((*(reinterpret_cast<uint8_t *>(&key_copy) + i) ^ i) +
                                  ((*(reinterpret_cast<uint8_t *>(&key_copy) + i) ^ i) % 5));
    ++kptr;
  }

  *reinterpret_cast<uint64_t *>(static_cast<uint8_t *>(templ) + 8) = key_copy;
  *reinterpret_cast<uint16_t *>(static_cast<uint8_t *>(templ) + 16) = key2_copy;
  return 1;
}

static uint64_t sub_39B0(const void *src, void *dst, int src_w, int src_h, int out_w, int out_h) {
  int v6 = src_h;
  uint64_t result = static_cast<unsigned int>(src_w - out_w);
  int v8 = (src_h - out_h) / 2;
  int v9 = v8 + out_h;
  int v10 = v8;
  int v11 = (src_w - out_w) / 2;
  if (v8 >= 0) {
    v6 = v9;
  }
  if (v8 < v6) {
    int v13 = 0;
    size_t v19 = src_w;
    result = out_w;
    int v14 = src_w * v8;
    size_t n = out_w;
    do {
      if (v10 >= 0) {
        const char *row = static_cast<const char *>(src) + v14;
        if (v11 >= 0) {
          result = reinterpret_cast<uint64_t>(std::memcpy(static_cast<char *>(dst) + v13, row + v11, n));
        } else {
          result = reinterpret_cast<uint64_t>(std::memcpy(static_cast<char *>(dst) - v11 + v13, row, v19));
        }
      }
      ++v10;
      v13 += out_w;
      v14 += src_w;
    } while (v6 != v10);
  }
  return result;
}

static int biokey_LoadBmp2Cache(const char *path, void *buf, int *len) {
  FILE *fp = std::fopen(path, "rb");
  if (!fp) {
    return 0;
  }
  std::fseek(fp, 0, SEEK_END);
  int sz = std::ftell(fp);
  std::fseek(fp, 0, SEEK_SET);
  if (*len <= sz) {
    sz = *len;
  }
  std::fread(buf, sz, 1, fp);
  *len = sz;
  std::fclose(fp);
  return 1;
}

static void biokey_WriteBitmapToMemory(const void *src, int width, int height, void *out) {
  uint8_t header[0x500] = {0};
  header[0] = 0x42;
  header[1] = 0x4d;

  int stride = width + 6;
  *reinterpret_cast<uint32_t *>(header + 0x06) = 0x436;
  *reinterpret_cast<uint32_t *>(header + 0x0A) = width;
  *reinterpret_cast<uint32_t *>(header + 0x0E) = height;
  *reinterpret_cast<uint32_t *>(header + 0x12) = 0x28;
  *reinterpret_cast<uint32_t *>(header + 0x1A) = 0x00010001;
  if (width + 3 >= 0) {
    stride = width + 3;
  }
  *reinterpret_cast<uint32_t *>(header + 0x22) = height * (stride & 0xFFFFFFFC);
  *reinterpret_cast<uint32_t *>(header + 0x02) = *reinterpret_cast<uint32_t *>(header + 0x22) + 0x436;
  *reinterpret_cast<uint16_t *>(header + 0x1E) = 8;

  for (int i = 1; i != 256; ++i) {
    header[0x36 + i * 4 + 0] = static_cast<uint8_t>(i);
    header[0x36 + i * 4 + 1] = static_cast<uint8_t>(i);
    header[0x36 + i * 4 + 2] = static_cast<uint8_t>(i);
  }

  std::memcpy(out, header, 0x436);
  std::memcpy(static_cast<uint8_t *>(out) + 0x436, src, static_cast<size_t>(height) * width);
}

static void biokey_ConvertBmp(char *bmp, void *out, int out_w, int out_h, int rotate) {
  std::vector<uint8_t> header(0x500);
  std::memcpy(header.data(), bmp, header.size());

  int bmp_w = *reinterpret_cast<int *>(header.data() + 0x12);
  int bmp_h = *reinterpret_cast<int *>(header.data() + 0x16);
  char *bmp_data = bmp + 0x436;

  int x_offset = (bmp_h - out_h) / 2;
  int x_end = out_h + x_offset;
  if (x_offset >= 0) {
    bmp_h = x_end;
  }

  std::vector<uint8_t> tmp(static_cast<size_t>(out_w) * out_h + 1024);
  if (x_offset < bmp_h) {
    int v9 = -1;
    int y_offset = (bmp_w - out_w) / -2;
    int y_shift = (bmp_w - out_w) / 2;
    int v11 = x_end;
    int row_in = x_offset * bmp_w;
    int out_off = 0;
    int x_cursor = (bmp_h - out_h) / 2;
    int y_cursor = y_shift;
    do {
      if (x_cursor >= 0) {
        ++v9;
        const char *row_src = rotate ? (bmp_data + bmp_w * (v11 - v9 - 1)) : (bmp_data + row_in);
        if (y_cursor < 0) {
          std::memcpy(tmp.data() + y_offset + out_off, row_src, bmp_w);
        } else {
          std::memcpy(tmp.data() + out_off, row_src + y_cursor, out_w);
        }
      }
      ++x_cursor;
      out_off += out_w;
      row_in += bmp_w;
    } while (v11 != x_cursor);
  }

  biokey_WriteBitmapToMemory(tmp.data(), out_w, out_h, out);
}

static int biokey_WriteBitmapToFile(const void *img, int width, int height, const char *path) {
  int stride = width + 6;
  std::vector<uint8_t> header(0x500);

  *reinterpret_cast<uint16_t *>(header.data()) = 19778;
  *reinterpret_cast<uint32_t *>(header.data() + 0x0A) = 0x436;
  *reinterpret_cast<uint32_t *>(header.data() + 0x0E) = 40;
  *reinterpret_cast<uint32_t *>(header.data() + 0x12) = width;
  *reinterpret_cast<uint32_t *>(header.data() + 0x16) = height;
  *reinterpret_cast<uint16_t *>(header.data() + 0x1A) = 1;
  if (width + 3 >= 0) {
    stride = width + 3;
  }
  unsigned int stride_aligned = stride & 0xFFFFFFFC;
  *reinterpret_cast<uint32_t *>(header.data() + 0x22) = height * stride_aligned;
  *reinterpret_cast<uint32_t *>(header.data() + 0x02) = height * stride_aligned + 0x436;
  *reinterpret_cast<uint16_t *>(header.data() + 0x1C) = 8;

  FILE *fp = std::fopen(path, "wb");
  if (!fp) {
    return 0;
  }
  for (int i = 1; i != 256; ++i) {
    header[0x36 + i * 4 + 0] = static_cast<uint8_t>(i);
    header[0x36 + i * 4 + 1] = static_cast<uint8_t>(i);
    header[0x36 + i * 4 + 2] = static_cast<uint8_t>(i);
  }
  std::fwrite(header.data(), 0x436, 1, fp);

  const uint8_t *row = static_cast<const uint8_t *>(img) + static_cast<size_t>(width) * (height - 1);
  for (int y = 0; y < height; ++y) {
    std::fwrite(row, width, 1, fp);
    if (width != static_cast<int>(stride_aligned)) {
      std::fwrite(row, stride_aligned - width, 1, fp);
    }
    row -= width;
  }
  std::fclose(fp);
  return width + width * (height - 1);
}

static int biokey_write_bitmap(const char *path, const void *img, unsigned int w, unsigned int h) {
  FILE *fp = std::fopen(path, "w+b");
  if (!fp) {
    return std::printf("cannot open %s\n", path);
  }

  std::vector<uint32_t> hdr(0x428 / 4);
  hdr[0] = 40;
  hdr[1] = w;
  hdr[2] = h;
  reinterpret_cast<uint16_t *>(hdr.data())[6] = 1;
  reinterpret_cast<uint16_t *>(hdr.data())[7] = 8;
  hdr[4] = 0;
  hdr[5] = 0;
  hdr[6] = 0;
  hdr[7] = 0;
  hdr[8] = 256;
  hdr[9] = 256;

  uint32_t *pal = hdr.data() + 10;
  for (int i = 0; i != 256; ++i) {
    reinterpret_cast<uint8_t *>(pal)[2] = static_cast<uint8_t>(i);
    reinterpret_cast<uint8_t *>(pal)[1] = static_cast<uint8_t>(i);
    reinterpret_cast<uint8_t *>(pal)[0] = static_cast<uint8_t>(i);
    reinterpret_cast<uint8_t *>(pal)[3] = 0;
    ++pal;
  }

  uint64_t file_hdr = 19778;
  uint16_t extra[24] = {0};
  *reinterpret_cast<uint32_t *>(reinterpret_cast<uint8_t *>(&file_hdr) + 2) =
      4 * ((8 * w + 31) >> 5) * h + 1078;
  extra[0] = 0;
  *reinterpret_cast<uint32_t *>(&extra[1]) = 1078;

  std::fwrite(&file_hdr, 0x0E, 1, fp);
  std::fwrite(hdr.data(), 4 * hdr[8] + 40, 1, fp);
  std::fwrite(img, *reinterpret_cast<uint32_t *>(reinterpret_cast<uint8_t *>(&file_hdr) + 2) - 54 - 4 * hdr[8], 1, fp);
  std::fclose(fp);
  return 0;
}

static int biokey_WriteFile(const char *path, const void *buf, int len) {
  FILE *fp = std::fopen(path, "w+b");
  if (!fp) {
    std::printf("cannot open %s\n", path);
    return -1;
  }
  unsigned int ok = (len == static_cast<int>(std::fwrite(buf, 1, len, fp))) ? 1u : 0u;
  std::fclose(fp);
  return ok ? 1 : -1;
}

static int ReverseImage(uint8_t *data, int w, int h) {
  int total = w * h;
  uint8_t *end = data + total;
  while (data < end) {
    *data = static_cast<uint8_t>(~*data);
    ++data;
  }
  return reinterpret_cast<intptr_t>(end);
}

static int CorrectFingerLinear(const uint8_t *src, uint8_t *dst, uint16_t *a3, unsigned int a4) {
  int v6 = static_cast<int16_t>(a3[3]);
  if (a3[3] == a3[5] && (static_cast<int16_t>(a3[7]) == a3[9])) {
    int v28 = static_cast<int16_t>(a3[7]);
    int v55 = 0;
    int v49 = 0;
    if (a4 & 2) {
      v55 = a3[0];
      v49 = a3[1];
    } else {
      v49 = a3[0];
      v55 = a3[1];
    }

    int v29 = a3[21];
    if (a3[21]) {
      int v50 = 0;
      int v53 = a4 & 1;
      while (1) {
        int v30 = static_cast<int16_t>(a3[6]);
        int v31 = static_cast<int16_t>(a3[4]);
        int v54 = static_cast<int16_t>(a3[2]);
        int v32 = v54 - v31;
        int v33 = static_cast<int16_t>(a3[8]) - v30;
        int v34 = (v54 - v31) * -v29;
        int v35 = v34 + v50 * (v33 + v54 - v31);
        int v36 = (v35 / 2 + v28 * v34 + v50 * (v33 * v6 + v28 * (v54 - v31))) / v35;
        int v51 = v36;
        if (v55 <= v36 || v36 < 0) {
          if (a3[20]) {
            for (int i = 0; i < a3[20]; ++i) {
              *dst++ = 0xFF;
            }
            v29 = a3[21];
          }
        } else {
          int v37 = static_cast<int16_t>(a3[8]) * v54 - v30 * v31;
          int v38 = a3[20];
          int v39 = v50 * v37;
          int v40 = a3[20];
          if (v40) {
            uint8_t *v41 = dst;
            int v42 = 0;
            while (1) {
              int v46 = (v35 / 2 + v39 - v32 * (v30 + (v42 + (v40 >> 1)) / v38) * v29) / v35;
              if (v49 <= v46 || v46 < 0) {
                *v41 = 0xFF;
              } else {
                int v43 = a3[0];
                int v44 = (a4 & 2) ? v51 + v43 * v46 : v51 * v43 + v46;
                uint8_t v45 = src[v44];
                if (v53) {
                  v45 = static_cast<uint8_t>(~v45);
                }
                *v41 = v45;
              }
              v38 = a3[20];
              ++v41;
              v42 += v33;
              v40 = a3[20];
              if (v38 <= (v41 - dst)) {
                break;
              }
              v29 = a3[21];
              v30 = static_cast<int16_t>(a3[6]);
            }
            v29 = a3[21];
            dst = v41;
          }
        }
        if (++v50 >= v29) {
          break;
        }
        v28 = static_cast<int16_t>(a3[7]);
        v6 = static_cast<int16_t>(a3[3]);
      }
    }
    return a4;
  }

  int v7 = a3[21];
  int v8 = a3[20];
  int v9 = v7 * v8;
  int v48 = (v7 * v8) >> 1;
  if (a3[21]) {
    int v11 = 0;
    while (1) {
      int v12 = a3[2];
      int v13 = a3[6];
      int v14 = v12 - v11 * (v12 - v13) / v7;
      int v15 = a3[4] - v12;
      int v16 = a3[3];
      int v17 = v7 * v15 - v11 * (v15 + v13 - a3[8]);
      int v18 = a3[7];
      int v19 = v16 - v11 * (v16 - v18) / v7;
      int v20 = v7 * (a3[5] - v16) - v11 * (a3[5] - v16 + v18 - a3[9]);
      if (static_cast<uint16_t>(v8)) {
        int v21 = v48;
        int v22 = 0;
        int v23 = v48;
        do {
          ++v22;
          int v25 = v21 >> 31;
          int v24 = v21;
          ++dst;
          v21 += v20;
          int v26 = static_cast<int>(a3[0] * (v19 + static_cast<int64_t>(static_cast<uint64_t>(v24) | (static_cast<uint64_t>(v25) << 32)) / v9));
          int v27 = v23;
          v23 += v17;
          dst[-1] = src[v26 + v14 + v27 / v9];
        } while (a3[20] > v22);
        v7 = a3[21];
      }
      if (v7 <= ++v11) {
        break;
      }
      v8 = a3[20];
    }
  }
  return v7 * v8;
}

} // namespace

extern "C" {

ZKINTERFACE void APICALL BIOKEY_SET_CHECK_CALLBACK(int64_t (*cb)(_QWORD, _QWORD), int64_t user) {
  g_check_cb = reinterpret_cast<int (*)(unsigned int, void *)>(cb);
  g_check_user = reinterpret_cast<void *>(user);
}

ZKINTERFACE int64_t APICALL BIOKEY_GETVERSION(_DWORD *a1, _DWORD *a2) {
  *a1 = 10;
  *a2 = 13;
  return 1;
}

ZKINTERFACE int64_t APICALL BIOKEY_GETLASTERROR() { return g_last_error; }

ZKINTERFACE int64_t APICALL BIOKEY_GETLASTQUALITY() { return static_cast<unsigned int>(g_last_quality); }

ZKINTERFACE int64_t APICALL BIOKEY_INIT_SIMPLE(int64_t, int width, int height, int, int64_t);

ZKINTERFACE _BOOL8 APICALL BIOKEY_SET_PARAMETER(void *ctx, unsigned int code, unsigned int value) {
  g_last_error = 0;
  switch (code) {
    case 0x138D:
      if (!ctx) {
        g_last_error = 1116;
        return 0;
      }
      if (value - 1 > 1) {
        g_last_error = 1101;
        return 0;
      }
      reinterpret_cast<BioKeyHandle *>(ctx)->merge_mode = value;
      return 1;
    case 0x138E: {
      if (!value) {
        g_last_error = 1101;
        return 0;
      }
      const char *name = reinterpret_cast<const char *>(static_cast<uintptr_t>(value));
      size_t len = std::strlen(name);
      if (len > 0x1F) {
        g_last_error = 1101;
        return 0;
      }
      std::memcpy(g_db_name, name, len);
      g_db_name[len] = '\0';
      return 1;
    }
    case 0x138F:
      g_last_error = 1101;
      return 0;
    case 0x1391:
    case 0x1393:
      return 1;
    case 0x1394:
      if (!ctx) {
        g_last_error = 1116;
        return 0;
      }
      reinterpret_cast<BioKeyHandle *>(ctx)->field14 = value;
      return 1;
    default:
      if (!ctx) {
        g_last_error = 1116;
        return 0;
      }
      g_last_error = IEngine_SetParameter(code, value);
      return g_last_error == 0;
  }
}

ZKINTERFACE int64_t APICALL BIOKEY_GET_PARAMETER(void *ctx, int code, int *out) {
  if (!ctx) {
    return 0;
  }

  switch (code) {
    case 5001:
      return static_cast<unsigned int>(IEngine_GetUserCount(out)) == 0;
    case 5002: {
      int tmp = 0;
      IEngine_GetUserCount(&tmp);
      return static_cast<unsigned int>(IEngine_GetUserIDs(out, tmp)) == 0;
    }
    case 5003: {
      int tmp = 0;
      int ret = IEngine_GetUserCount(&tmp);
      if (!ret) {
        *out = tmp;
        return ret == 0;
      }
      g_last_error = ret;
      return ret == 0;
    }
    case 5004: {
      IEngine_ClearUser(g_user_primary);
      g_last_error = IEngine_GetUser(g_user_primary, static_cast<unsigned int>(*out));
      if (g_last_error) {
        *out = 0;
        return 0;
      }
      int count = 0;
      int ret = IEngine_GetFingerprintCount(g_user_primary, &count);
      g_last_error = ret;
      if (ret) {
        *out = 0;
      } else {
        *out = count;
      }
      return ret == 0;
    }
    case 5005:
    case 5006:
    case 5007:
      return 1;
    case 5008: {
      int v5 = *out;
      unsigned int v6 = 0;
      int v7 = 0;
      do {
        while (true) {
          int tmp = 0;
          IEngine_ClearUser(g_user_primary);
          g_last_error = IEngine_GetUser(g_user_primary, v5 | v6);
          if (!g_last_error) {
            tmp = 0;
            g_last_error = IEngine_GetFingerprintCount(g_user_primary, &tmp);
            if (!g_last_error) {
              v6 += 0x10000;
              v7 += tmp;
              break;
            }
          }
          v6 += 0x10000;
          if (v6 == 0x100000) {
            *out = v7;
            return 1;
          }
        }
      } while (v6 != 0x100000);
      *out = v7;
      return 1;
    }
    default:
      return 1;
  }
}

ZKINTERFACE _BOOL8 APICALL BIOKEY_MATCHINGPARAM(void *ctx, int64_t, int val) {
  if (!ctx) {
    return 0;
  }
  if (val > 100) {
    val = 100;
  }
  int v = 0;
  if (g_thresh_mode == 1) {
    v = g_thresh_mul * (val - 35);
  } else {
    v = g_thresh_mul * val;
  }
  int p = v + g_thresh_step;
  if (g_thresh_step >= p) {
    p = g_thresh_step;
  }
  return static_cast<unsigned int>(IEngine_SetParameter(1, p)) == 0;
}

ZKINTERFACE int64_t APICALL BIOKEY_INIT(int64_t a1, uint16_t *cfg, int64_t, int64_t, int64_t a5) {
  unsigned int v6 = 0;
  unsigned int v8 = 0;
  if (cfg) {
    v6 = cfg[20];
    bool flag = static_cast<uint32_t>(a5) == 128;
    a5 = static_cast<uint32_t>(a5 - 128);
    v8 = cfg[21];
    g_ext_height = *cfg;
    g_ext_width = cfg[1];
    g_height = v8;
    g_width = v6;
    if (!flag) {
      g_use_extended = 1;
      g_ext_qw[0] = *reinterpret_cast<uint64_t *>(cfg);
      g_ext_qw[1] = *(reinterpret_cast<uint64_t *>(cfg) + 1);
      g_ext_qw[2] = *(reinterpret_cast<uint64_t *>(cfg) + 2);
      g_ext_qw[3] = *(reinterpret_cast<uint64_t *>(cfg) + 3);
      g_ext_qw[4] = *(reinterpret_cast<uint64_t *>(cfg) + 4);
      g_ext_dw = *(reinterpret_cast<uint32_t *>(cfg) + 10);
    }
  } else {
    v8 = static_cast<unsigned int>(g_height);
    v6 = static_cast<unsigned int>(g_width);
  }
  return BIOKEY_INIT_SIMPLE(a1, v6, v8, 0, a5);
}

ZKINTERFACE int64_t APICALL BIOKEY_INIT_SIMPLE(int64_t, int width, int height, int, int64_t) {
  int user_limit = 0;
  unsigned int ver_info[2] = {0};

  IEngine_SetParameter(8, -1);
  IEngine_GetUserLimit(&user_limit);
  IEngine_GetVersionInfo(ver_info);
  std::printf("10 Algorithm Version:%d.%d, Limit:%d\n", ver_info[0], ver_info[1], user_limit);

  int inited = IEngine_InitModule();
  unsigned int v5 = 0;
  if (ver_info[0] > 2) {
    g_thresh_mode = 1;
    g_thresh_base = 85;
    v5 = 4;
    g_thresh_step = 40;
    g_thresh_mul = 5;
  } else if (ver_info[1] > 0x45) {
    g_thresh_mode = 1;
    g_thresh_base = 220;
    v5 = 7;
    g_thresh_step = 120;
    g_thresh_mul = 5;
  } else {
    g_thresh_base = 12300;
    g_thresh_step = 8000;
    g_thresh_mul = 100;
    v5 = 7;
  }

  if (inited) {
    if (!g_check_cb) {
      g_last_error = inited;
      return 0;
    }
    timeval tv{};
    gettimeofday(&tv, nullptr);
    std::srand(tv.tv_usec);
    unsigned int v17 =
        static_cast<unsigned int>((static_cast<double>(std::rand()) * 300.0 * 4.656612873077393e-10) + 1);
    if (static_cast<unsigned int>(g_check_cb(v17, g_check_user)) != ((100 * v17) ^ 0x85948B9A)) {
      g_last_error = inited;
      return 0;
    }

    int v18 = IEngine_InitWithLicense(g_license_blob, sizeof(g_license_blob));
    if (v18) {
      g_last_error = v18;
      return 0;
    }
  }

  auto *ctx = static_cast<BioKeyHandle *>(std::calloc(0x40, 1));
  ctx->field0 = 0;
  ctx->merge_mode = 1;

  g_width = width;
  g_height = height;

  IEngine_SetParameter(4, 180);
  IEngine_SetParameter(6, v5);
  IEngine_SetParameter(5, 0);
  IEngine_SetParameter(1, g_thresh_base);
  IEngine_SetParameter(10, 1664);
  IEngine_SetParameter(8, -1);
  IEngine_SetParameter(16, 21);

  const char *p = g_db_name;
  bool is_memory = g_db_name[0] == '\0';
  if (!is_memory) {
    const char *cmp = "memory";
    int n = 7;
    const char *cursor = p;
    bool eq = true;
    while (n--) {
      if (*cursor++ != *cmp++) {
        eq = false;
        break;
      }
    }
    if (!eq) {
      int ret = IEngine_Connect(g_db_name, cursor);
      g_is_memory_db = 0;
      if (ret) {
        g_last_error = ret;
        std::free(ctx);
        return 0;
      }
    } else {
      int ret = IEngine_Connect("type=memory", cursor);
      g_is_memory_db = 1;
      if (ret) {
        g_last_error = ret;
        std::free(ctx);
        return 0;
      }
    }
  } else {
    int ret = IEngine_Connect("type=memory", p);
    g_is_memory_db = 1;
    if (ret) {
      g_last_error = ret;
      std::free(ctx);
      return 0;
    }
  }

  g_user_primary = IEngine_InitUser();
  g_user_secondary = IEngine_InitUser();
  g_user_temp = IEngine_InitUser();

  int raw_size = g_height * g_width;
  ctx->img_buf_size = 100800;
  ctx->raw_size = raw_size;
  int total = raw_size + 111040;
  ctx->buf_total = total;
  if (raw_size + 111040 <= 203647) {
    ctx->buf_total = 211840;
    total = 211840;
  }

  if (g_use_extended) {
    int v19 = g_ext_width * g_ext_height + total;
    int v20 = g_ext_width * g_ext_height;
    ctx->buf_total = v19;
    void *mem = std::calloc(v19, 1);
    ctx->buf_base = mem;
    ctx->buf_base2 = mem;
    uint8_t *ptr = static_cast<uint8_t *>(std::memset(mem, 0xFF, 0x189C0));
    ctx->buf_ptr = ptr + 100800;
    ctx->buf_tail = ptr + (v19 - v20);
  } else {
    void *mem = std::calloc(total, 1);
    ctx->buf_base = mem;
    ctx->buf_base2 = mem;
    ctx->buf_ptr = static_cast<uint8_t *>(std::memset(mem, 0xFF, 0x189C0)) + 100800;
  }

  g_last_error = 0;
  return reinterpret_cast<int64_t>(ctx);
}

ZKINTERFACE int64_t APICALL BIOKEY_CLOSE(BioKeyHandle *ctx) {
  if (!ctx) {
    return 1;
  }
  IEngine_FreeUser(g_user_primary);
  IEngine_FreeUser(g_user_secondary);
  IEngine_FreeUser(g_user_temp);
  if (ctx->buf_base) {
    std::free(ctx->buf_base);
  }
  std::free(ctx);
  IEngine_TerminateModule();
  return 1;
}

ZKINTERFACE int64_t APICALL BIOKEY_GETPARAM(BioKeyHandle *ctx, _DWORD *a2, _DWORD *a3, _DWORD *a4) {
  if (!ctx) {
    return 0;
  }
  *a2 = 500;
  *a3 = 280;
  *a4 = 360;
  return 1;
}

ZKINTERFACE int64_t APICALL BIOKEY_EXTRACT(BioKeyHandle *ctx, const void *raw, void *out) {
  unsigned int result = 0;
  int quality = 0;
  int tmp[11] = {0};

  if (!ctx) {
    return result;
  }

  int v5 = static_cast<int>(ctx->img_buf_size);
  int v6 = static_cast<int>(ctx->buf_total);
  void *buf = ctx->buf_base2;

  tmp[0] = v6 - v5;
  std::memset(buf, 0xFF, v5);
  sub_39B0(raw, ctx->buf_base2, g_width, g_height, 280, 360);

  if (IEngine_ConvertRawImage2Bmp(ctx->buf_base2, 280, 360, ctx->buf_ptr, tmp)) {
    g_last_error = 0;
    std::printf("Convert rawimage failed\n:%d", 0);
    return 0;
  }

  result = IEngine_ClearUser(g_user_primary);
  if (!result) {
    int v9 = IEngine_AddFingerprint(g_user_primary, 0, ctx->buf_ptr);
    if (v9) {
      g_last_error = v9;
      std::printf("AddFingerprint failed\n:%d", v9);
      return result;
    }
  }

  tmp[0] = 2048;
  int v10 = IEngine_ExportUserTemplate(g_user_primary, 1, out, tmp);
  result = tmp[0];
  g_last_error = v10;
  unsigned int v12 = tmp[0] - 1;
  if (v10 == 0) {
    if (v12 <= 0x67E) {
      bio_EncodeData(out);
      IEngine_GetFingerprintQuality(g_user_primary, 0, &quality);
      result = tmp[0];
      g_last_quality = quality;
    }
    return result;
  }
  if (v12 > 0x67E) {
    return result;
  }
  std::printf("template size invalid :%d\n", tmp[0]);
  return 0;
}

ZKINTERFACE int64_t APICALL BIOKEY_EXTRACT_SIMPLE(BioKeyHandle *ctx, const void *raw, void *out) {
  return BIOKEY_EXTRACT(ctx, raw, out);
}

ZKINTERFACE int64_t APICALL BIOKEY_EXTRACT_SP(BioKeyHandle *ctx, const void *raw, void *out) {
  return BIOKEY_EXTRACT(ctx, raw, out);
}

ZKINTERFACE int64_t APICALL BIOKEY_EXTRACT_BY_FORMAT(BioKeyHandle *ctx, const void *raw, void *out, int out_len, unsigned int fmt) {
  unsigned int result = 0;
  int quality = 0;
  int tmp[11] = {0};

  if (!ctx) {
    return result;
  }

  int v6 = static_cast<int>(ctx->img_buf_size);
  int v8 = static_cast<int>(ctx->buf_total);
  void *buf = ctx->buf_base2;
  tmp[0] = v8 - v6;
  std::memset(buf, 0xFF, v6);
  sub_39B0(raw, ctx->buf_base2, g_width, g_height, 280, 360);
  result = IEngine_ConvertRawImage2Bmp(ctx->buf_base2, 280, 360, ctx->buf_ptr, tmp);
  if (result) {
    result = 0;
    g_last_error = 0;
    std::printf("Convert rawimage failed\n:%d", 0);
  } else if (!IEngine_ClearUser(g_user_primary) && (IEngine_AddFingerprint(g_user_primary, 0, ctx->buf_ptr) != 0)) {
    g_last_error = 0;
  } else {
    tmp[0] = out_len;
    g_last_error = IEngine_ExportUserTemplate(g_user_primary, fmt, out, tmp);
    if (g_last_error) {
      if (tmp[0] <= 0) {
        return tmp[0];
      }
      std::printf("template size invalid :%d\n", tmp[0]);
    } else {
      result = tmp[0];
      if (tmp[0] > 0) {
        IEngine_GetFingerprintQuality(g_user_primary, 0, &quality);
        result = tmp[0];
        g_last_quality = quality;
      }
    }
  }
  return result;
}

ZKINTERFACE int64_t APICALL BIOKEY_EXTRACT_GRAYSCALEDATA(
    BioKeyHandle *ctx, const void *raw, unsigned int w, unsigned int h, void *out, int out_len) {
  int quality = 0;
  if (!ctx) {
    return 0;
  }

  int alloc_len = static_cast<int>(h * w + 2048);
  void *tmp = std::malloc(alloc_len);
  if (!tmp) {
    return 0;
  }

  int info = alloc_len;
  std::memset(tmp, 0xFF, alloc_len);
  unsigned int v12 = IEngine_ConvertRawImage2Bmp(raw, w, h, tmp, &info);
  if (v12) {
    g_last_error = 0;
    std::free(tmp);
    return 0;
  }

  if (!IEngine_ClearUser(g_user_primary)) {
    int add_ret = IEngine_AddFingerprint(g_user_primary, 0, tmp);
    if (add_ret != 0) {
      g_last_error = add_ret;
      std::free(tmp);
      return 0;
    }
  }

  info = out_len;
  g_last_error = IEngine_ExportUserTemplate(g_user_primary, 1, out, &info);
  if (g_last_error) {
    if ((unsigned int)(info - 1) >= 0x67F) {
      v12 = info;
    }
  } else {
    v12 = info;
    if ((unsigned int)(info - 1) <= 0x67E) {
      bio_EncodeData(out);
      IEngine_GetFingerprintQuality(g_user_primary, 0, &quality);
      v12 = info;
      g_last_quality = quality;
    }
  }
  std::free(tmp);
  return v12;
}

ZKINTERFACE int64_t APICALL BIOKEY_EXTRACT_BMP(BioKeyHandle *ctx, const char *path, void *out) {
  unsigned int result = 0;
  int quality = 0;

  if (!ctx) {
    return result;
  }

  std::vector<uint8_t> bmp_cache(0x25800);
  int len = 153600;
  biokey_LoadBmp2Cache(path, bmp_cache.data(), &len);

  std::vector<uint8_t> raw(111040);
  std::memset(raw.data(), 0xFF, raw.size());
  biokey_ConvertBmp(reinterpret_cast<char *>(bmp_cache.data()), raw.data(), 280, 360, 0);

  result = IEngine_ClearUser(g_user_primary);
  if (!result) {
    int v5 = IEngine_AddFingerprint(g_user_primary, 0, raw.data());
    if (v5 != 0) {
      g_last_error = v5;
      std::printf("AddFingerprint failed\n:%d", v5);
      return 0;
    }
  }

  int tmp_len = 2048;
  int ret = IEngine_ExportUserTemplate(g_user_primary, 1, out, &tmp_len);
  result = tmp_len;
  g_last_error = ret;
  unsigned int v8 = tmp_len - 1;
  if (ret == 0) {
    if (v8 <= 0x67E) {
      bio_EncodeData(out);
      IEngine_GetFingerprintQuality(g_user_primary, 0, &quality);
      result = tmp_len;
      g_last_quality = quality;
    }
  } else if (v8 <= 0x67E) {
    result = 0;
    std::printf("template size invalid :%d\n", tmp_len);
  }

  return result;
}

ZKINTERFACE int64_t APICALL BIOKEY_GENTEMPLATE(void *ctx, uint64_t *temps, int count, void *out) {
  int v34 = 0;
  int v35 = 0;
  int v36[2] = {0, 0};
  int v37 = 0;
  void *v38 = nullptr;
  void *v39 = nullptr;
  void *v40 = nullptr;

  if (count <= 0 || !ctx) {
    return 0;
  }

  if (count == 1) {
    int len = static_cast<int>(BiokeyInterGetTemplateLen(reinterpret_cast<void *>(temps[0])));
    std::memcpy(out, reinterpret_cast<void *>(temps[0]), len);
    v34 = len;
    return 1;
  }

  if (count != 3) {
    return 0;
  }

  int ret = IEngine_ClearUser(g_user_primary);
  g_last_error = ret;
  if (ret) {
    return 0;
  }

  int len1 = static_cast<int>(BiokeyInterGetTemplateLen(reinterpret_cast<void *>(temps[0])));
  v38 = g_buf_a;
  std::memcpy(g_buf_a, reinterpret_cast<void *>(temps[0]), len1);
  bio_DecodeData(g_buf_a);
  int r1 = IEngine_ImportUserTemplate(g_user_primary, 1, g_buf_a);
  IEngine_GetFingerprintQuality(g_user_primary, 0, &v36[0]);
  g_last_error = r1;
  if (r1) {
    std::puts("import fingerprint 1 failed");
  } else {
    ret = 1;
  }

  int len2 = static_cast<int>(BiokeyInterGetTemplateLen(reinterpret_cast<void *>(temps[1])));
  v39 = g_buf_b;
  std::memcpy(g_buf_b, reinterpret_cast<void *>(temps[1]), len2);
  bio_DecodeData(g_buf_b);
  int r2 = IEngine_ImportUserTemplate(g_user_primary, 1, g_buf_b);
  IEngine_GetFingerprintQuality(g_user_primary, 1, &v36[1]);
  g_last_error = r2;
  if (r2) {
    std::puts("import fingerprint 2 failed");
    int len3 = static_cast<int>(BiokeyInterGetTemplateLen(reinterpret_cast<void *>(temps[2])));
    v40 = g_buf_c;
    std::memcpy(g_buf_c, reinterpret_cast<void *>(temps[2]), len3);
    bio_DecodeData(g_buf_c);
    int r3 = IEngine_ImportUserTemplate(g_user_primary, 1, g_buf_c);
    IEngine_GetFingerprintQuality(g_user_primary, 2, &v37);
    g_last_error = r3;
    if (r3) {
      std::puts("import fingerprint 3 failed");
      if (g_last_error) {
        return 0;
      }
    }
  } else {
    int len3 = static_cast<int>(BiokeyInterGetTemplateLen(reinterpret_cast<void *>(temps[2])));
    v40 = g_buf_c;
    std::memcpy(g_buf_c, reinterpret_cast<void *>(temps[2]), len3);
    bio_DecodeData(g_buf_c);
    int r3 = IEngine_ImportUserTemplate(g_user_primary, 1, g_buf_c);
    IEngine_GetFingerprintQuality(g_user_primary, 2, &v37);
    g_last_error = r3;
    if (r3) {
      std::puts("import fingerprint 3 failed");
      if (g_last_error) {
        return 0;
      }
    }
  }

  if (!ret) {
    int res = v34;
    if (res < 0) {
      return 0;
    }
    return res;
  }

  int score = 0;
  int matched = IEngine_MatchFingerprints(g_user_primary, 0, g_user_primary, 2, &score);
  std::printf("index %d, score %d, errorcode:%d\n", 2, score, matched);
  if (score <= 0) {
    return 0;
  }
  matched = IEngine_MatchFingerprints(g_user_primary, 0, g_user_primary, 1, &score);
  std::printf("index %d, score %d, errorcode:%d\n", 1, score, matched);
  if (score <= 0) {
    return 0;
  }

  int v23 = (v36[0] <= v36[1]) ? 1 : 0;
  if (v36[v23] <= v37) {
    v23 = 2;
  }
  int v24 = (v36[0] >= v36[1]) ? 1 : 0;
  if (v37 <= v36[v24]) {
    v24 = 2;
  }

  g_last_error = IEngine_ClearUser(g_user_primary);
  if (g_last_error) {
    return 0;
  }

  void *templ_bufs[3] = {v38, v39, v40};
  if (reinterpret_cast<BioKeyHandle *>(ctx)->merge_mode == 1) {
    IEngine_ImportUserTemplate(g_user_primary, 1, templ_bufs[v23]);
  } else {
    for (int i = 0; i != 3; ++i) {
      if (v24 != i) {
        IEngine_ImportUserTemplate(g_user_primary, 1, templ_bufs[i]);
      }
    }
  }

  int chosen_quality = (v23 == 2) ? v37 : v36[v23];
  v34 = 2048;
  g_last_quality = chosen_quality;
  g_last_error = IEngine_ExportUserTemplate(g_user_primary, 1, out, &v34);
  if (g_last_error) {
    return 0;
  }
  int result = v34;
  if (v34 > 0) {
    bio_EncodeData(out);
  }
  if (result < 0) {
    return 0;
  }
  return result;
}

ZKINTERFACE int64_t APICALL BIOKEY_GENTEMPLATE_SP(void *ctx, void *t1, void *t2, void *t3, unsigned int count, void *out) {
  uint64_t temps[3] = {reinterpret_cast<uint64_t>(t1), reinterpret_cast<uint64_t>(t2), reinterpret_cast<uint64_t>(t3)};
  return BIOKEY_GENTEMPLATE(ctx, temps, static_cast<int>(count), out);
}

ZKINTERFACE int64_t APICALL BIOKEY_VERIFY(void *ctx, const char *t1, const char *t2) {
  int score = 0;
  if (!ctx) {
    return 0;
  }

  if (IEngine_ClearUser(g_user_primary) || IEngine_ClearUser(g_user_secondary)) {
    g_last_error = 0;
    return 0;
  }

  unsigned int len1 = BiokeyInterGetTemplateLen(t1);
  unsigned int len2 = BiokeyInterGetTemplateLen(t2);
  if (len1 - 50 > 0x64E || len2 - 50 > 0x64E) {
    g_last_error = 1135;
    std::printf("1:1 fp template len error, 1:%d, 2:%d\n", len1, len2);
    return 0;
  }

  std::memcpy(g_buf_b, t1, len1);
  std::memcpy(g_buf_c, t2, len2);
  bio_DecodeData(g_buf_b);
  bio_DecodeData(g_buf_c);

  unsigned int matched = IEngine_ImportUserTemplate(g_user_primary, 1, g_buf_b);
  g_last_error = matched;
  if (matched || ((matched = IEngine_ImportUserTemplate(g_user_secondary, 1, g_buf_c)), (g_last_error = matched) != 0)) {
    std::printf("import fingerprint failed,lasterror:%d\n", matched);
    if (score <= 0) {
      g_last_error = matched;
      return 0;
    }
  } else {
    matched = IEngine_MatchUsers(g_user_primary, g_user_secondary, &score);
    if (score <= 0) {
      g_last_error = matched;
      if (matched) {
        return 0;
      }
      return 0;
    }
  }

  int s = (score - g_thresh_step) / g_thresh_mul;
  if (g_thresh_mode == 1) {
    s += 35;
  }
  if (s > 100) {
    s = 100;
  }
  score = s;

  g_last_error = matched;
  if (matched) {
    return 0;
  }
  if (score >= 0) {
    return static_cast<unsigned int>(score);
  }
  return matched;
}

ZKINTERFACE int64_t APICALL BIOKEY_VERIFYBYID(int ctx, unsigned int uid, const void *templ) {
  int score = 0;
  if (!ctx) {
    return 0;
  }
  g_last_error = IEngine_ClearUser(g_user_primary);
  if (g_last_error) {
    return 0;
  }

  int len = static_cast<int>(BiokeyInterGetTemplateLen(templ));
  std::memcpy(g_buf_b, templ, len);
  bio_DecodeData(g_buf_b);

  g_last_error = IEngine_ImportUserTemplate(g_user_primary, 1, g_buf_b);
  if (g_last_error) {
    return 0;
  }

  int matched = IEngine_MatchUser(g_user_primary, uid, &score, nullptr);
  if (score > 0) {
    int s = (score - g_thresh_step) / g_thresh_mul;
    if (g_thresh_mode == 1) {
      s += 35;
    }
    if (s > 100) {
      s = 100;
    }
    score = s;
  }
  g_last_error = matched;
  if (matched) {
    return 0;
  }
  if (score >= 0) {
    return static_cast<unsigned int>(score);
  }
  return 0;
}

ZKINTERFACE int64_t APICALL BIOKEY_IDENTIFYTEMPBYTAG(void *ctx, const char *templ, int *uid, int *score, const char *tag) {
  if (!ctx) {
    return 0;
  }

  int ret = IEngine_ClearUser(g_user_primary);
  g_last_error = ret;
  unsigned int len = BiokeyInterGetTemplateLen(templ);
  if (len - 50 > 0x64E) {
    g_last_error = 1135;
    std::printf("1:N fp template len error, Len:%d\n", len);
    return 0;
  }

  std::memcpy(g_buf_a, templ, len);
  if (!bio_DecodeData(g_buf_a)) {
    std::puts("DecodeData failed");
    return 0;
  }

  if (ret) {
    if (*score > 0) {
      int s = (*score - g_thresh_step) / g_thresh_mul;
      if (g_thresh_mode == 1) {
        s += 35;
      }
      if (s > 100) {
        s = 100;
      }
      *score = s;
      return 0;
    }
    return 0;
  }

  g_last_error = IEngine_ImportUserTemplate(g_user_primary, 1, g_buf_a);
  if (g_last_error) {
    if (*score > 0) {
      int s = (*score - g_thresh_step) / g_thresh_mul;
      if (g_thresh_mode == 1) {
        s += 35;
      }
      if (s > 100) {
        s = 100;
      }
      *score = s;
      return 0;
    }
    return 0;
  }

  *uid = 0;
  *score = 0;
  int find_ret = 0;
  if (tag) {
    char query[128];
    std::snprintf(query, sizeof(query), "SELECT USERID FROM TAG_CACHE WHERE %s%s='%s'", "F", tag, tag);
    find_ret = IEngine_FindUserByQuery(g_user_primary, query, uid, score);
  } else {
    find_ret = IEngine_FindUser(g_user_primary, uid, score);
    std::printf("%s(%d), score:%d\n", "BiokeyInterIdentifyTempByTag", 2997, *score);
  }

  g_last_error = find_ret;
  if (find_ret || *uid <= 0) {
    int v = *score;
    if (*score <= 0) {
      return 0;
    }
    int s = (v - g_thresh_step) / g_thresh_mul;
    if (g_thresh_mode == 1) {
      s += 35;
    }
    if (s > 100) {
      s = 100;
    }
    *score = s;
    return 0;
  }

  int v = *score;
  if (*score <= 0) {
    return 0;
  }
  int s = (v - g_thresh_step) / g_thresh_mul;
  if (g_thresh_mode == 1) {
    s += 35;
  }
  if (s > 100) {
    s = 100;
  }
  *score = s;
  return 1;
}

ZKINTERFACE int64_t APICALL BIOKEY_IDENTIFYTEMP(void *ctx, const char *templ, int *uid, int *score) {
  return BIOKEY_IDENTIFYTEMPBYTAG(ctx, templ, uid, score, nullptr);
}

ZKINTERFACE int64_t APICALL BIOKEY_IDENTIFYTEMPBYTAG_0(void *ctx, char *templ, int *uid, int *score, const char *tag) {
  return BIOKEY_IDENTIFYTEMPBYTAG(ctx, templ, uid, score, tag);
}

ZKINTERFACE int64_t APICALL BIOKEY_IDENTIFY(BioKeyHandle *ctx, const void *raw, int *uid, int *score) {
  uint8_t buf[3112] = {0};
  int64_t ret = BIOKEY_EXTRACT(ctx, raw, buf);
  if (static_cast<int>(ret)) {
    return BIOKEY_IDENTIFYTEMP(ctx, reinterpret_cast<char *>(buf), uid, score);
  }
  return ret;
}

ZKINTERFACE int64_t APICALL BIOKEY_IDENTIFY_SP(BioKeyHandle *ctx, const void *raw, int *uid, int *score) {
  return BIOKEY_IDENTIFY(ctx, raw, uid, score);
}

ZKINTERFACE int64_t APICALL BIOKEY_IDENTIFY_SIMPLE() { return 0; }

ZKINTERFACE _BOOL8 APICALL BIOKEY_DB_ADD(void *ctx, unsigned int uid, int len, void *templ) {
  if (!ctx) {
    return 0;
  }
  unsigned int templ_len = BiokeyInterGetTemplateLen(templ);
  if (templ_len > 1664 || (templ_len > static_cast<unsigned int>(len) && (templ_len - len - 6) > 1)) {
    std::printf("template lenth failed,template len = %d,TempLength=%d\n", templ_len, len);
    return 0;
  }

  std::memcpy(g_buf_a, templ, templ_len);
  if (!bio_DecodeData(g_buf_a)) {
    std::puts("DecodeData failed");
    return 0;
  }

  g_last_error = IEngine_ClearUser(g_user_primary);
  if (g_last_error) {
    return 0;
  }
  int v13 = IEngine_ImportUserTemplate(g_user_primary, 1, g_buf_a);
  if (!v13) {
    v13 = IEngine_RegisterUserAs(g_user_primary, uid);
  }
  g_last_error = v13;
  return v13 == 0;
}

ZKINTERFACE _BOOL8 APICALL BIOKEY_DB_ADDEX(void *ctx, unsigned int uid, int len, void *templ) {
  if (!ctx) {
    return 0;
  }
  unsigned int templ_len = BiokeyInterGetTemplateLen(templ);
  if (templ_len > 1664 || (templ_len > static_cast<unsigned int>(len) && (templ_len - len - 6) > 1)) {
    std::printf("template length invalid len=%d, TempLength=%d\n", templ_len, len);
    return 0;
  }

  std::memcpy(g_buf_a, templ, templ_len);
  if (!bio_DecodeData(g_buf_a)) {
    std::puts("template decode failed");
    return 0;
  }

  IEngine_ClearUser(g_user_primary);
  int v14 = IEngine_ImportUserTemplate(g_user_primary, 1, g_buf_a);
  g_last_error = v14;
  if (v14) {
    std::printf("Import User failed,LastError=%d\n", v14);
    return 0;
  }
  g_last_error = IEngine_RegisterUserAs(g_user_primary, uid);
  return g_last_error == 0;
}

ZKINTERFACE _BOOL8 APICALL BIOKEY_DB_ADD_SP(void *ctx, unsigned int uid, int len, void *templ) {
  if (!ctx) {
    return 0;
  }
  unsigned int templ_len = BiokeyInterGetTemplateLen(templ);
  if (templ_len - 1 > 0x67F) {
    std::puts("template size invalid");
    return 0;
  }

  std::memcpy(g_buf_a, templ, templ_len);
  if (!bio_DecodeData(g_buf_a)) {
    std::printf("template format invalid, TID=%d\n", uid);
    return 0;
  }

  g_last_error = IEngine_ClearUser(g_user_primary);
  if (g_last_error) {
    return 0;
  }
  int v12 = IEngine_ImportUserTemplate(g_user_primary, 1, g_buf_a);
  if (!v12) {
    v12 = IEngine_RegisterUserAs(g_user_primary, uid);
  }
  g_last_error = v12;
  return v12 == 0;
}

ZKINTERFACE int64_t APICALL BIOKEY_DB_APPEND() { return 1; }

ZKINTERFACE _BOOL8 APICALL BIOKEY_DB_DEL(void *ctx, unsigned int uid) {
  if (!ctx) {
    return 0;
  }
  g_last_error = IEngine_RemoveUser(uid);
  return g_last_error == 0;
}

ZKINTERFACE _BOOL8 APICALL BIOKEY_DB_CLEAR(void *ctx) {
  if (!ctx) {
    return 0;
  }
  IEngine_ClearUser(g_user_temp);
  g_last_error = IEngine_ClearDatabase();
  return g_last_error == 0;
}

ZKINTERFACE _BOOL8 APICALL BIOKEY_DB_CLEAREX(void *ctx) {
  if (!ctx) {
    return 0;
  }
  g_last_error = IEngine_ClearDatabase();
  return g_last_error == 0;
}

ZKINTERFACE int64_t APICALL BIOKEY_DB_COUNT(void *ctx) {
  unsigned int out = 0;
  BIOKEY_GET_PARAMETER(ctx, 5003, reinterpret_cast<int *>(&out));
  return out;
}

ZKINTERFACE int64_t APICALL BIOKEY_DB_SAVE() { return 0; }

ZKINTERFACE int64_t APICALL BIOKEY_DB_FILTERID() { return 0; }

ZKINTERFACE int64_t APICALL BIOKEY_DB_FILTERID_ALL() { return 0; }

ZKINTERFACE int64_t APICALL BIOKEY_DB_FILTERID_NONE() { return 0; }

ZKINTERFACE _BOOL8 APICALL BIOKEY_DB_GET_TEMPLATE(int major, int minor, void *out, _DWORD *out_len) {
  unsigned int uid = static_cast<unsigned int>(major | (minor << 16));
  int len = 0;
  IEngine_ClearUser(g_user_primary);
  if (IEngine_GetUser(g_user_primary, uid)) {
    return len > 0;
  }
  IEngine_ExportUserTemplate(g_user_primary, 1, nullptr, &len);
  if (len > 0x8000) {
    std::printf("UID %d template lenth %d overflow", uid, len);
    len = 0;
  } else if (len > 0 && !IEngine_ExportUserTemplate(g_user_primary, 1, out, &len)) {
    bio_EncodeData(out);
    *out_len = len;
    return len > 0;
  }
  std::puts("Export user template failed,ret ");
  return 0;
}

ZKINTERFACE int64_t APICALL BIOKEY_GET_CUSTOMDATA(void *ctx, unsigned int uid, void *data, void *len) {
  IEngine_ClearUser(g_user_primary);
  g_last_error = IEngine_GetUser(g_user_primary, uid);
  if (!g_last_error) {
    g_last_error = IEngine_GetCustomData(g_user_primary, data, len);
    return g_last_error == 0;
  }
  return 0;
}

ZKINTERFACE int64_t APICALL BIOKEY_SET_CUSTOMDATA(void *ctx, unsigned int uid, void *data, unsigned int len) {
  IEngine_ClearUser(g_user_primary);
  int ret = IEngine_GetUser(g_user_primary, uid);
  g_last_error = ret;
  if (ret) {
    g_last_error = 1127;
  } else {
    IEngine_SetCustomData(g_user_primary, data, len);
    ret = IEngine_UpdateUser(g_user_primary, uid);
    g_last_error = ret;
  }
  return ret == 0;
}

ZKINTERFACE int64_t APICALL BIOKEY_SET_STRINGTAG(void *ctx, unsigned int uid, const char *tag) {
  if (!ctx) {
    return 0;
  }
  IEngine_ClearUser(g_user_primary);
  unsigned int ret = IEngine_GetUser(g_user_primary, uid);
  g_last_error = ret;
  if (ret) {
    g_last_error = 1127;
    return 0;
  }
  if (tag) {
    char key[128];
    std::snprintf(key, sizeof(key), "%s%s", "F", tag);
    g_last_error = IEngine_SetStringTag(g_user_primary, key, tag);
    if (!g_last_error) {
      g_last_error = IEngine_UpdateUser(g_user_primary, uid);
      return g_last_error == 0;
    }
    return ret;
  }
  return 1;
}

ZKINTERFACE int64_t APICALL BIOKEY_GETFINGERLINEAR() { return 0; }

ZKINTERFACE int64_t APICALL BIOKEY_SETTEMPLATELEN() { return 0; }

ZKINTERFACE int64_t APICALL BIOKEY_SETNOISETHRESHOLD() { return 0; }

ZKINTERFACE int64_t APICALL BIOKEY_TEMPLATELEN(void *templ, void *, void *) {
  unsigned int len = bio_DecodeData(templ);
  if (len) {
    len = BiokeyInterGetTemplateLen(templ);
    bio_EncodeData(templ);
  }
  return len;
}

ZKINTERFACE int64_t APICALL BIOKEY_MERGE_TEMPLATE(const void **temps, int count, void *out) {
  std::vector<uint8_t> s(0x4000);
  std::memset(s.data(), 0, s.size());
  std::memcpy(s.data(), "ICRS21", 6);
  s[16] = static_cast<uint8_t>(-59);
  s[18] = static_cast<uint8_t>(-59);

  if (count <= 0 || !out || !temps) {
    return 0;
  }

  for (int i = 0; i < count; ++i) {
    bio_DecodeData(const_cast<void *>(temps[i]));
  }

  const uint16_t *first = reinterpret_cast<const uint16_t *>(temps[0]);
  if (std::memcmp(temps[0], "ICRS2", 5)) {
    for (int i = 0; i < count; ++i) {
      bio_EncodeData(const_cast<void *>(temps[i]));
    }
    return 0;
  }

  int v10 = 24;
  if (count == 1) {
    v10 = (static_cast<const uint8_t *>(temps[0])[8] << 8) + static_cast<const uint8_t *>(temps[0])[9];
    bio_EncodeData(const_cast<void *>(temps[0]));
    std::memcpy(out, temps[0], v10);
    return v10;
  }

  uint8_t v26 = 0;
  int v27 = 0;
  uint16_t v30 = first[10];
  uint16_t v31 = first[11];

  const void **cur = temps;
  while (true) {
    uint8_t v25 = static_cast<const uint8_t *>(*cur)[10];
    if (v25) {
      const uint8_t *v13 = static_cast<const uint8_t *>(*cur);
      int v15 = 0;
      int v16 = 24;
      int v17 = v10;
      do {
        uint8_t *dest = s.data() + v17;
        uint8_t v19 = static_cast<uint8_t>(v15++ + v26);
        const_cast<uint8_t *>(v13)[26] = v19;
        const uint8_t *src = static_cast<const uint8_t *>(*cur) + v16;
        int v21 = (static_cast<const uint8_t *>(*cur)[8] << 8) + static_cast<const uint8_t *>(*cur)[9] - 24;
        v16 += v21;
        v17 += v21;
        std::memcpy(dest, src, v21);
      } while (v25 != v15);
      v26 += v25;
      v10 = v17;
    }
    if (++v27 >= count) {
      break;
    }
    ++cur;
    if (v30 != reinterpret_cast<const uint16_t *>(*cur)[10] || v31 != reinterpret_cast<const uint16_t *>(*cur)[11]) {
      return 0;
    }
  }

  uint16_t v22 = static_cast<uint16_t>(v10 + 255);
  s[8] = static_cast<uint8_t>(v22 >> 8);
  s[9] = static_cast<uint8_t>(v10);
  *reinterpret_cast<uint16_t *>(&s[20]) = v30;
  s[10] = v26;
  *reinterpret_cast<uint16_t *>(&s[22]) = v31;

  std::memcpy(out, s.data(), v10);
  bio_EncodeData(out);
  for (int i = 0; i < count; ++i) {
    bio_EncodeData(const_cast<void *>(temps[i]));
  }
  return v10;
}

ZKINTERFACE int64_t APICALL BIOKEY_SPLIT_TEMPLATE(unsigned char *templ, void **out, unsigned int *count, int *sizes) {
  std::vector<uint8_t> s(0x4000);
  std::memset(s.data(), 0, s.size());
  std::memcpy(s.data(), "ICRS21", 6);
  s[16] = static_cast<uint8_t>(-59);
  s[18] = static_cast<uint8_t>(-59);

  if (!templ || !out) {
    return 0;
  }

  DecodeDataWithMaxLen(templ, 0x8000);
  if (std::memcmp(templ, "ICRS2", 5)) {
    bio_EncodeData(templ);
    return 0;
  }

  uint16_t v21 = *reinterpret_cast<uint16_t *>(templ + 20);
  uint16_t v22 = *reinterpret_cast<uint16_t *>(templ + 22);
  unsigned int v23 = templ[10];
  if (v23 > 1) {
    int v6 = 24;
    int *v7 = sizes;
    void **v8 = out;
    void **end = out + v23;
    while (true) {
      uint8_t *dst = static_cast<uint8_t *>(*v8);
      uint8_t *src = templ + v6;
      unsigned int v14 = src[4] + ((src[3] & 0xF) << 8);
      if (v14 >= 8) {
        std::memcpy(dst, s.data(), 24);
        std::memcpy(dst + v14 - 8, src + v14 - 8, 8);
      } else if (v14) {
        dst[0] = src[0];
        if (v14 & 2) {
          *reinterpret_cast<uint16_t *>(dst + v14 - 2) = *reinterpret_cast<uint16_t *>(src + v14 - 2);
        }
      }
      v6 += v14;
      *reinterpret_cast<uint64_t *>(dst + 0) = *reinterpret_cast<uint64_t *>(s.data());
      *reinterpret_cast<uint64_t *>(dst + 8) = *reinterpret_cast<uint64_t *>(s.data() + 8);
      *reinterpret_cast<uint64_t *>(dst + 16) = *reinterpret_cast<uint64_t *>(s.data() + 16);
      dst[8] = static_cast<uint16_t>(v14 + 24) >> 8;
      dst[9] = static_cast<uint8_t>(v14 + 24);
      *reinterpret_cast<uint16_t *>(dst + 20) = v21;
      dst[10] = 1;
      *reinterpret_cast<uint16_t *>(dst + 22) = v22;
      dst[26] = 0;
      bio_EncodeData(dst);
      *v7 = v14 + 24;

      ++v8;
      ++v7;
      if (v8 == end) {
        *count = v23;
        return v23;
      }
    }
  }

  bio_EncodeData(templ);
  if (v23 != 1) {
    return 0;
  }

  int len = templ[9] + (templ[8] << 8);
  *sizes = len;
  std::memcpy(*out, templ, len);
  *count = 1;
  return 1;
}

ZKINTERFACE int64_t APICALL GetTmpCnt() { return 0; }

} // extern "C"
