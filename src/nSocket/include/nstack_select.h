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

#define NSTACK_SELECT_MODULE

#ifdef NSTACK_SELECT_MODULE

#ifndef __NSTACK_SELECT_H__
#define __NSTACK_SELECT_H__

/* move include files outside the extern C */
#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include "select_adapt.h"

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
#endif

typedef int (*get_select_event) (int nfds, fd_set * readfd, fd_set * writefd,
                                 fd_set * exceptfd, struct timeval * timeout);
typedef struct
{
    unsigned char *fds_bits;    // (NSTACK_SETSIZE+7)>>3
} __attribute__ ((packed)) nstack_fd_set;

#define NSTACK_FD_SET(n, p)		((p)->fds_bits[(n)>>3]|=1U<<((n)&0x07))
#define NSTACK_FD_ISSET(n,p)	(((p)->fds_bits[(n)>>3]&(1U<<((n)&0x07)))?1:0)
#define NSTACK_FD_CLR(n,p)		((p)->fds_bits[(n)>>3]&=~(1U<<((n)&0x07)))
#define NSTACK_FD_ZERO(p, mem_size)		(memset_s((void *)(p->fds_bits), mem_size,0,mem_size))
#define NSTACK_FD_OR(p1 ,p2)     {\
    int i;\
    for(i = 0; i < (NSTACK_SELECT_MAX_FD+7)>>3; i++){\
        (p1)->fds_bits[i] |= (p2)->fds_bits[i];\
    }\
}

struct select_cb_p
{
    nstack_fd_set nstack_readset;
    nstack_fd_set nstack_writeset;
    nstack_fd_set nstack_exceptset;

    fd_set readset;
    fd_set writeset;
    fd_set exceptset;

    union
    {
        i32 count;
        i32 readyset;
    };

    i32 inx;
    i32 select_errno;
};

struct select_entry_info
{
    i32 set_num;                //how many select_c_p is set
    i32 index;                  //the frist cb was set
};

struct select_entry
{
    struct select_cb_p cb[NSTACK_MAX_MODULE_NUM];
    struct select_cb_p ready;
    struct select_entry *next;
    struct select_entry *prev;
    struct select_entry_info info;
    select_sem_t sem;
};

struct select_module_info
{

    struct select_entry *entry_head;
    struct select_entry *entry_tail;
    get_select_event get_select_fun_nonblock[NSTACK_MAX_MODULE_NUM];
    get_select_event get_select_fun_block[NSTACK_MAX_MODULE_NUM];
    get_select_event default_fun;
    i32 default_mod;
    volatile i32 inited;
    select_spinlock_t lock;
    select_sem_t sem;
};

extern i32 select_cb_split_by_mod(i32 nfds,
                                  fd_set * readfd,
                                  fd_set * writefd,
                                  fd_set * exceptfd,
                                  struct select_entry *entry);
extern void entry_module_fdset(struct select_entry *entry,
                               i32 fd_size,
                               nstack_fd_set * readfd,
                               nstack_fd_set * writefd,
                               nstack_fd_set * exceptfd, i32 inx);

extern int nstack_select_processing(int nfds,
                                    fd_set * readfds,
                                    fd_set * writefds,
                                    fd_set * exceptfds,
                                    struct timeval *timeout);
extern i32 select_scan(struct select_entry *entry);
extern i32 select_add_cb(struct select_entry *entry);
extern i32 select_rm_cb(struct select_entry *entry);
extern i32 select_entry_reset(struct select_entry *entry);
extern i32 select_module_init();
extern struct select_module_info *get_select_module(void);

#define NS_FD_ISSET(fd,set) ((set) &&(FD_ISSET(fd,set)))
#define NFDS_NOT_VALID(nfds) (((nfds)>__FD_SETSIZE)||((nfds)<0))
#define TIMEVAL_NOT_VALID(time) ((time)&&(((time)->tv_sec<0)||((time)->tv_usec<0)))
#define TIMEVAL_EQUAL_ZERO(time) ((time)&&(((time)->tv_sec==0)&&((time)->tv_usec==0)))
static inline void print_select_dbg(int nfds, fd_set * readfds,
                                    fd_set * writefds, fd_set * exceptfds)
{
    int i;
    for (i = 0; i < nfds; i++)
    {

        if (NS_FD_ISSET(i, readfds))
        {
            NSSOC_LOGDBG("input readfd set=%d", i);
        }
        if (NS_FD_ISSET(i, writefds))
        {
            NSSOC_LOGDBG("input writefd set=%d", i);
        }
        if (NS_FD_ISSET(i, exceptfds))
        {
            NSSOC_LOGDBG("input exceptfds set=%d", i);
        }

    }
}

static inline bool is_select_used_as_timer(int nfds, fd_set * readfds,
                                           fd_set * writefds,
                                           fd_set * exceptfds)
{
    return ((nfds <= 0)
            || ((NULL == readfds) && (NULL == writefds)
                && (NULL == exceptfds)));
}

static inline void *select_fd_set_bits_alloc()
{
    void *addr;
    addr =
        select_alloc(sizeof(unsigned char) *
                     ((NSTACK_SELECT_MAX_FD + 7) >> 3));
    return addr;
}

static inline void select_fd_set_free(nstack_fd_set * addr)
{
    select_free(addr);
}

#define FREE_SELECT_FD_SET(readfd, writefd, exceptfd)  {\
    select_free(readfd);\
    select_free(writefd);\
    select_free(exceptfd);\
}

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif /* __NSTACK_SELECT_H__ */

#endif /* NSTACK_SELECT_MODULE */
