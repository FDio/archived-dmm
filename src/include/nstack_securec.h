/*
*
* Copyright (c) 2018 Huawei Technologies Co.,Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at:
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef _NSTACK_SECUREC_H_
#define _NSTACK_SECUREC_H_

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
#endif

#ifndef SYSTEMC_LIB
/* use libsecurec.so as usual */
#include "securec.h"

#else
#include "stdio.h"
#include "stdarg.h"
#include "string.h"

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef errno_t
typedef int errno_t;
#endif

#ifndef EOK
#define EOK (0)
#endif

#ifndef EINVAL
#define EINVAL (22)
#endif

#ifndef EINVAL_AND_RESET
#define EINVAL_AND_RESET (22 | 0X80)
#endif

#ifndef ERANGE
#define ERANGE (34)
#endif

#ifndef ERANGE_AND_RESET
#define ERANGE_AND_RESET  (34 | 0X80)
#endif

#ifndef EOVERLAP_AND_RESET
#define EOVERLAP_AND_RESET (54 | 0X80)
#endif

#define   scanf_s         scanf
#define   wscanf_s        wscanf
#define   vscanf_s        vscanf
#define   vwscanf_s       vwscanf
#define   fscanf_s        fscanf
#define   fwscanf_s       fwscanf
#define   vfscanf_s       vfscanf
#define   vfwscanf_s      vfwscanf
#define   sscanf_s        sscanf
#define   swscanf_s       swscanf
#define   vsscanf_s       vsscanf
#define   vswscanf_s      vswscanf

#define   sprintf_s(a, b, ...)           sprintf(a, ##__VA_ARGS__)
#define   swprintf_s(a, b, c,  ...)      swprintf(a, b, c, ##__VA_ARGS__)
#define   vsprintf_s(a, b, c, d)         vsprintf(a, c, d)
#define   vswprintf_s(a, b, c, d)        vswprintf(a, b, c, d)
#define   vsnprintf_s(a, b, c, d, e)     vsnprintf(a, c, d, e)
#define   snprintf_s(a, b, c,  d, ...)   snprintf(a, c, d, ##__VA_ARGS__)

#define   wmemcpy_s(a, b, c, d)       ((NULL == wmemcpy(a, c, d)) ? EINVAL : EOK)
#define   memmove_s(a, b, c, d)       ((NULL == memmove(a, c, d)) ? EINVAL : EOK)
#define   wmemmove_s(a, b, c, d)      ((NULL == wmemmove(a, c, d)) ? EINVAL : EOK)
#define   wcscpy_s(a, b, c)           ((NULL == wcscpy(a, c)) ? EINVAL : EOK)
#define   wcsncpy_s(a, b, c, d)       ((NULL == wcsncpy(a, c, d)) ? EINVAL : EOK)
#define   wcscat_s(a, b, c)           ((NULL == wcscat(a, c)) ? EINVAL : EOK)
#define   wcsncat_s(a, b, c, d)       ((NULL == wcsncat(a, c, d)) ? EINVAL : EOK)

#define   memset_s(a, b, c, d)        ((NULL == memset(a, c, d)) ? EINVAL : EOK)
#define   memcpy_s(a, b, c, d)        ((NULL == memcpy(a, c, d)) ? EINVAL : EOK)
#define   strcpy_s(a, b, c)           ((NULL == strcpy(a, c )) ? EINVAL : EOK)
#define   strncpy_s(a, b, c, d)       ((NULL == strncpy(a, c, d)) ? EINVAL : EOK)
#define   strcat_s(a, b, c)           ((NULL == strcat(a, c)) ? EINVAL : EOK)
#define   strncat_s(a, b, c, d)       ((NULL == strncat(a, c, d)) ? EINVAL : EOK)

#define   strtok_s(a, b, c)  strtok(a, b)
#define   wcstok_s(a, b, c)  wcstok(a, b)
#define   gets_s(a, b)       gets(a)

#endif

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif
