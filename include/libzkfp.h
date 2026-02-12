#ifndef _libzkfp_h
#define _libzkfp_h

#include "libzkfptype.h"

#ifdef __cplusplus
extern "C" {
#endif

ZKINTERFACE int APICALL ZKFPM_Init();
ZKINTERFACE int APICALL ZKFPM_Terminate();
ZKINTERFACE int APICALL ZKFPM_GetDeviceCount();
ZKINTERFACE HANDLE APICALL ZKFPM_OpenDevice(int index);
ZKINTERFACE int APICALL ZKFPM_CloseDevice(HANDLE hDevice);
ZKINTERFACE int APICALL ZKFPM_SetParameters(HANDLE hDevice, int nParamCode, unsigned char *paramValue, unsigned int cbParamValue);
ZKINTERFACE int APICALL ZKFPM_GetParameters(HANDLE hDevice, int nParamCode, unsigned char *paramValue, unsigned int *cbParamValue);
ZKINTERFACE int APICALL ZKFPM_GetCaptureParams(HANDLE hDevice, TZKFPCapParams *params);
ZKINTERFACE int APICALL ZKFPM_GetCaptureParamsEx(HANDLE hDevice, unsigned int *width, unsigned int *height, unsigned int *dpi);

ZKINTERFACE int APICALL ZKFPM_AcquireFingerprint(HANDLE hDevice, unsigned char *fpImage, unsigned int cbFPImage,
                                                 unsigned char *fpTemplate, unsigned int *cbTemplate);
ZKINTERFACE int APICALL ZKFPM_AcquireFingerprintImage(HANDLE hDevice, unsigned char *fpImage, unsigned int cbFPImage);

ZKINTERFACE HANDLE APICALL ZKFPM_DBInit();
ZKINTERFACE int APICALL ZKFPM_DBFree(HANDLE hDBCache);
ZKINTERFACE int APICALL ZKFPM_DBSetParameter(HANDLE hDBCache, int nParamCode, unsigned char *paramValue, unsigned int cbParamValue);
ZKINTERFACE int APICALL ZKFPM_DBGetParameter(HANDLE hDBCache, int nParamCode, unsigned char *paramValue, unsigned int cbParamValue);
ZKINTERFACE int APICALL ZKFPM_DBMerge(HANDLE hDBCache, unsigned char *temp1, unsigned char *temp2, unsigned char *temp3,
                                      unsigned char *regTemp, unsigned int *cbRegTemp);
ZKINTERFACE int APICALL ZKFPM_DBAdd(HANDLE hDBCache, unsigned int fid, unsigned char *fpTemplate, unsigned int cbTemplate);
ZKINTERFACE int APICALL ZKFPM_DBDel(HANDLE hDBCache, unsigned int fid);
ZKINTERFACE int APICALL ZKFPM_DBClear(HANDLE hDBCache);
ZKINTERFACE int APICALL ZKFPM_DBCount(HANDLE hDBCache, unsigned int *fpCount);
ZKINTERFACE int APICALL ZKFPM_DBIdentify(HANDLE hDBCache, unsigned char *fpTemplate, unsigned int cbTemplate,
                                         unsigned int *FID, unsigned int *score);
ZKINTERFACE int APICALL ZKFPM_DBMatch(HANDLE hDBCache, unsigned char *template1, unsigned int cbTemplate1,
                                      unsigned char *template2, unsigned int cbTemplate2);
ZKINTERFACE int APICALL ZKFPM_ExtractFromImage(HANDLE hDBCache, const char *lpFilePathName, unsigned int DPI,
                                               unsigned char *fpTemplate, unsigned int *cbTemplate);

ZKINTERFACE HANDLE APICALL ZKFPM_CreateDBCache();
ZKINTERFACE int APICALL ZKFPM_CloseDBCache(HANDLE hDBCache);
ZKINTERFACE int APICALL ZKFPM_ClearDBCache(HANDLE hDBCache);
ZKINTERFACE int APICALL ZKFPM_GetDBCacheCount(HANDLE hDBCache, unsigned int *fpCount);
ZKINTERFACE int APICALL ZKFPM_AddRegTemplateToDBCache(HANDLE hDBCache, unsigned int fid, unsigned char *fpTemplate, unsigned int cbTemplate);
ZKINTERFACE int APICALL ZKFPM_DelRegTemplateFromDBCache(HANDLE hDBCache, unsigned int fid);
ZKINTERFACE int APICALL ZKFPM_GenRegTemplate(HANDLE hDBCache, unsigned char *temp1, unsigned char *temp2, unsigned char *temp3,
                                             unsigned char *regTemp, unsigned int *cbRegTemp);
ZKINTERFACE int APICALL ZKFPM_Identify(HANDLE hDBCache, unsigned char *fpTemplate, unsigned int cbTemplate,
                                       unsigned int *FID, unsigned int *score);
ZKINTERFACE int APICALL ZKFPM_MatchFinger(HANDLE hDBCache, unsigned char *template1, unsigned int cbTemplate1,
                                          unsigned char *template2, unsigned int cbTemplate2);
ZKINTERFACE int APICALL ZKFPM_VerifyByID(HANDLE hDBCache, unsigned int fid, unsigned char *fpTemplate, unsigned int cbTemplate);
ZKINTERFACE int APICALL ZKFPM_GetLastExtractImage();

ZKINTERFACE int APICALL ZKFPM_Base64ToBlob(const char *base64, void *outBlob, unsigned int outLen);
ZKINTERFACE int APICALL ZKFPM_BlobToBase64(const void *blob, int blobLen, char *outBase64, unsigned int outLen);

#ifdef __cplusplus
}
#endif

#endif
