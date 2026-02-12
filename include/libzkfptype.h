#ifndef _libzkfptype_h
#define _libzkfptype_h

#include "zkinterface.h"

#define FP_THRESHOLD_CODE  1
#define FP_MTHRESHOLD_CODE 2
#ifndef MAX_TEMPLATE_SIZE
#define MAX_TEMPLATE_SIZE 2048
#endif

#ifndef HANDLE
#define HANDLE void *
#endif

typedef struct _ZKFPCapParams {
  unsigned int imgWidth;
  unsigned int imgHeight;
  unsigned int nDPI;
} TZKFPCapParams, *PZKFPCapParams;

#endif
