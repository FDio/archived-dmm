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

#ifndef clib_types_h
#define clib_types_h
#include <stddef.h>
#include <semaphore.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
/* Standard CLIB types. */

/* Define signed and unsigned 8, 16, 32, and 64 bit types
   and machine signed/unsigned word for all architectures. */
typedef char i8;
typedef short i16;

typedef unsigned char u8;
typedef unsigned short u16;

typedef int i32;
typedef long long i64;

typedef unsigned int u32;
typedef unsigned long long u64;

#ifndef NSTACK_MAX_U32_NUM
#define NSTACK_MAX_U32_NUM ((u32_t)0xffffffff)
#endif

#ifndef NSTACK_MAX_S32_NUM
#define NSTACK_MAX_S32_NUM ((s32_t)0x7fffffff)
#endif

#ifndef NSTACK_MAX_U64_NUM
#define NSTACK_MAX_U64_NUM ((u64_t)0xffffffffffffffff)
#endif

#ifndef NSTACK_MAX_S64_NUM
#define NSTACK_MAX_S64_NUM ((s64_t)0x7fffffffffffffff)
#endif

typedef uint64_t u64_t;
typedef int64_t s64_t;

typedef uint32_t u32_t;
typedef int32_t s32_t;

typedef uint16_t u16_t;
typedef int16_t s16_t;

typedef uint8_t u8_t;
typedef int8_t s8_t;

typedef uintptr_t mem_ptr_t;

typedef s8_t err_t;

#ifndef ns_bool
typedef unsigned char ns_bool;
#endif

#ifndef ns_false
#define ns_false 0
#endif

#ifndef ns_true
#define ns_true 1
#endif

#ifndef ns_success
#define ns_success 0
#endif

#ifndef ns_fail
#define ns_fail -1
#endif

#ifndef ns_static
#define ns_static static
#endif

#ifndef ns_uint32
typedef unsigned int ns_uint32;
#endif

#ifndef ns_int32
typedef signed int ns_int32;
#endif

#ifndef ns_char
typedef char ns_char;
#endif

#ifndef ns_uchar
typedef unsigned char ns_uchar;
#endif

#ifndef ns_int8
typedef signed char ns_int8;
#endif

#ifndef ns_uint8
typedef unsigned char ns_uint8;
#endif

#ifndef ns_uint16
typedef unsigned short ns_uint16;
#endif

#ifndef ns_int16
typedef signed short ns_int16;
#endif

#ifndef ns_uint
typedef unsigned int ns_uint;
#endif

#ifndef ns_int
typedef signed int ns_int;
#endif

#ifndef ns_ullong
typedef unsigned long long ns_ullong;
#endif

#ifndef ns_llong
typedef long long ns_llong;
#endif

#ifdef ns_slong
typedef signed long ns_slong;
#endif

#ifdef ns_ulong
typedef unsigned long ns_ulong;
#endif

#ifndef bool
#define bool int
#endif

#ifndef TRUE
#define TRUE 0x1
#endif

#ifndef true
#define true 0x1
#endif

#ifndef FALSE
#define FALSE 0x0
#endif

#ifndef false
#define false 0x0
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ( \
     \
    (type *)((char *)(ptr) - offsetof(type,member)) \
     \
    )
#endif

#define PRIMARY_ADDR

typedef struct _nsfw_res
{
    u8 alloc_flag;
    u8 u8Reserve;
    u16 chk_count;
    u32 data;
} nsfw_res;

static inline void res_alloc(nsfw_res * res)
{
    res->alloc_flag = TRUE;
    res->chk_count = 0;
    /*solve the issue that tx and app tx buf leak in upgrade process */
    res->u8Reserve = 0;
}

static inline int res_free(nsfw_res * res)
{
    if (TRUE != res->alloc_flag)
    {
        return -1;
    }
    res->chk_count = 0;
    res->alloc_flag = FALSE;
    return 0;
}

#define NSFW_THREAD __thread

#endif /*clib_types_h */
