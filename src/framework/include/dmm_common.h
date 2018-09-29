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
#ifndef _DMM_COMMON_H_
#define _DMM_COMMON_H_

#include "dmm_config.h"

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define _dmm_packed __attribute__((__packed__))
#define _dmm_aliened(a) __attribute__((__aligned__(a)))
#define _dmm_cache_aligned _dmm_aliened(DMM_CACHE_LINE_SIZE)

#define DMM_ALIGN(x, a) (((x) + ((a) - 1)) / (a) * (a))
#define dmm_align(x, a) ({ \
    typeof(x) _a = (a); \
    ((x) + (_a - 1)) / _a * _a; \
})

#ifndef offsetof
#define offsetof(type, member) ((size_t)((type *)0)->member)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({ \
    typeof( ((type *)0)->member ) *__mptr = (ptr); \
    (type *)( (char *)__mptr - offsetof(type,member) ); \
})
#endif

inline static unsigned int
dmm_align32pow2 (unsigned int v)
{
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;

  return v + 1;
}

inline static unsigned long long
dmm_align64pow2 (unsigned long long v)
{
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v |= v >> 32;

  return v + 1;
}

#endif
