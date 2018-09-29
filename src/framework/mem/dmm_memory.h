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
#ifndef _DMM_MEMORY_H_
#define _DMM_MEMORY_H_
#include <stdio.h>
#include <stdarg.h>
#include "dmm_share.h"
#include "dmm_segment.h"
#include "dmm_ring.h"

#define DMM_MEMORY_MODULE "DMM_MEMORY_MODULE"

extern struct dmm_segment *main_seg;
extern struct dmm_segment *base_seg;

inline static void
dmm_lock_map ()
{
  dmm_seg_lock (base_seg);
}

inline static void
dmm_unlock_map ()
{
  dmm_seg_unlock (base_seg);
}

inline static int
dmm_unmap (void *mem)
{
  return dmm_mem_unmap (base_seg, mem);
}

inline static void *
dmm_locked_map (size_t size, const char name[DMM_MEM_NAME_SIZE])
{
  void *mem;
  dmm_lock_map ();
  mem = dmm_mem_map (base_seg, size, name);
  dmm_unlock_map ();
  return mem;
}

inline static void *
dmm_map (size_t size, const char name[DMM_MEM_NAME_SIZE])
{
  return dmm_mem_map (base_seg, size, name);
}

inline static void *
dmm_mapv (size_t size, const char *name_fmt, ...)
{
  int len;
  char name[DMM_MEM_NAME_SIZE];
  va_list ap;

  va_start (ap, name_fmt);
  len = vsnprintf (name, DMM_MEM_NAME_SIZE, name_fmt, ap);
  va_end (ap);

  if (len >= DMM_MEM_NAME_SIZE)
    return NULL;

  return dmm_map (size, name);
}

inline static void *
dmm_lookup (const char name[DMM_MEM_NAME_SIZE])
{
  return dmm_mem_lookup (base_seg, name);
}

inline static void *
dmm_lookupv (const char *name_fmt, ...)
{
  int len;
  char name[DMM_MEM_NAME_SIZE];
  va_list ap;

  va_start (ap, name_fmt);
  len = vsnprintf (name, DMM_MEM_NAME_SIZE, name_fmt, ap);
  va_end (ap);

  if (len >= DMM_MEM_NAME_SIZE)
    return NULL;

  return dmm_mem_lookup (base_seg, name);
}

int dmm_mem_main_init ();
int dmm_mem_main_exit ();
int dmm_mem_app_init ();
int dmm_mem_app_exit ();

struct dmm_ring *dmm_create_ring (int num, int flag,
                                  const char name[DMM_MEM_NAME_SIZE]);

struct dmm_ring *dmm_attach_ring (const char name[DMM_MEM_NAME_SIZE]);

struct dmm_ring *dmm_malloc_ring (int num, int flag);

struct dmm_ring *dmm_create_pool (size_t elt_size, int num, int flag,
                                  const char name[DMM_MEM_NAME_SIZE]);

struct dmm_ring *dmm_attach_pool (const char name[DMM_MEM_NAME_SIZE]);

/* allocate pool from heap */
struct dmm_ring *dmm_malloc_pool (size_t elt_size, int num, int flag);

#endif /* _DMM_MEMORY_H_ */
