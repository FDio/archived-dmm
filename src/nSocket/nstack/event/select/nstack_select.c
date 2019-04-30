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

/*==============================================*
 *      include header files                    *
 *----------------------------------------------*/
#include "nstack_select.h"
#include "nstack_log.h"
#include "nsfw_base_linux_api.h"
#include "nstack.h"
#include "nstack_dmm_dfx.h"
/*==============================================*
 *      constants or macros define              *
 *----------------------------------------------*/
#ifdef NSTACK_SELECT_MODULE

#define SELECT_FREE_FD_BITS(read_set, write_set, exp_set) do{\
        select_free((read_set)->fds_bits); \
        select_free((write_set)->fds_bits); \
        select_free((exp_set)->fds_bits); \
}while(0)
/*==============================================*
 *      project-wide global variables           *
 *----------------------------------------------*/
extern void *nstack_select_thread(void *arg);
pthread_t g_select_thread_id;
/*************select module***************************/
struct select_module_info g_select_module = {
    .inited = FALSE,
};

struct select_module_info *get_select_module(void)
{
    return &g_select_module;
}

/*split comm seclet entry to child mod select*/
/*no need to check null pointer*/

i32 select_cb_split_by_mod(i32 nfds,
                           fd_set * readfd,
                           fd_set * writefd,
                           fd_set * exceptfd, struct select_entry * entry)
{
    i32 inx;
    i32 i;
    i32 fd;

    for (i = 0; i < nfds; i++)
    {
        /*not bound to any stack */
        for (inx = 0; inx < nstack_get_module_num(); inx++)
        {
            if (!((readfd && FD_ISSET(i, readfd)) ||
                  (writefd && FD_ISSET(i, writefd)) ||
                  (exceptfd && FD_ISSET(i, exceptfd))))
            {
                continue;
            }

            fd = select_get_modfd(i, inx);
            /*not create by nstack */
            if ((fd < 0) || (select_get_modindex(i) < 0))
            {
                if (inx != nstack_get_linux_mid())
                {
                    continue;
                }
                fd = i;
                nssct_create(fd, fd, inx);      /*do not need return value */
            }
            else
            {
                if (select_get_modindex(i) != inx)
                {
                    continue;
                }
            }

            NSSOC_LOGDBG("fd is  valiable i= %d fd = %d index = %d\n", i, fd,
                         inx);
            if ((readfd) && (FD_ISSET(i, readfd)))
            {
                if (inx == nstack_get_linux_mid())
                {
                    FD_SET(fd, &(entry->cb[inx].readset));
                }
                else
                {
                    NSTACK_FD_SET(fd, &(entry->cb[inx].nstack_readset));
                }
                if (entry->cb[inx].count <= fd)
                {
                    entry->cb[inx].count = fd + 1;
                }
            }

            if ((writefd) && (FD_ISSET(i, writefd)))
            {
                if (inx == nstack_get_linux_mid())
                {
                    FD_SET(fd, &(entry->cb[inx].writeset));
                }
                else
                {
                    NSTACK_FD_SET(fd, &(entry->cb[inx].nstack_writeset));
                }

                if (entry->cb[inx].count <= fd)
                {
                    entry->cb[inx].count = fd + 1;
                }
            }

            if ((exceptfd) && (FD_ISSET(i, exceptfd)))
            {
                if (inx == nstack_get_linux_mid())
                {
                    FD_SET(fd, &(entry->cb[inx].exceptset));
                }
                else
                {
                    NSTACK_FD_SET(fd, &(entry->cb[inx].nstack_exceptset));
                }

                if (entry->cb[inx].count <= fd)
                {
                    entry->cb[inx].count = fd + 1;
                }
            }
        }
    }

    for (inx = 0; inx < nstack_get_module_num(); inx++)
    {
        if (entry->cb[inx].count > 0)
        {
            entry->info.set_num++;
            entry->info.index = inx;
        }
    }
    return TRUE;
}

/*****************************************************************************
*   Prototype    : select_add_cb
*   Description  : add cb to gloab list
*   Input        : struct select_entry *entry
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*****************************************************************************/
i32 select_add_cb(struct select_entry * entry)
{

    if ((!entry))
    {

        return FALSE;
    }
    select_spin_lock(&g_select_module.lock);

    if (!g_select_module.entry_head)
    {
        g_select_module.entry_head = entry;
        g_select_module.entry_tail = entry;
        entry->next = NULL;
        entry->prev = NULL;
    }
    else
    {
        g_select_module.entry_tail->next = entry;
        entry->prev = g_select_module.entry_tail;
        g_select_module.entry_tail = entry;
        entry->next = NULL;
    }

    select_spin_unlock(&g_select_module.lock);
    select_sem_post(&g_select_module.sem);      /*do not need return value */
    return TRUE;
}

/*****************************************************************************
*   Prototype    : select_rm_cb
*   Description  : rm the cb from gloab list
*   Input        : struct select_entry *entry
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*****************************************************************************/
i32 select_rm_cb(struct select_entry * entry)
{

    if (!entry)
    {

        return FALSE;
    }

    select_spin_lock(&g_select_module.lock);

    if (g_select_module.entry_head == entry)
    {
        g_select_module.entry_head = entry->next;

    }
    else if (entry->prev)
    {
        entry->prev->next = entry->next;
    }

    if (g_select_module.entry_tail == entry)
    {
        g_select_module.entry_tail = entry->prev;
    }
    else if (entry->next)
    {
        entry->next->prev = entry->prev;
    }

    entry->next = NULL;
    entry->prev = NULL;

    select_spin_unlock(&g_select_module.lock);
    return TRUE;
}

/*get fd set from entrys*/
/*no need to check null pointer*/
/*****************************************************************************
*   Prototype    : select_thread_get_fdset
*   Description  : get module listening  fd form gloab list
*   Input        : nstack_fd_set *readfd
*                  nstack_fd_set *writefd
*                  nstack_fd_set *exceptfd
*                  struct select_module_info *module
*                  i32 inx
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*****************************************************************************/
i32 select_thread_get_fdset(nstack_fd_set * readfd,
                            nstack_fd_set * writefd,
                            nstack_fd_set * exceptfd,
                            struct select_module_info * module, i32 inx)
{

    struct select_entry *tmp;
    i32 nfds = 0;
    int retVal;

    if (!module)
    {
        return FALSE;
    }

    u32 fd_set_size =
        sizeof(unsigned char) * ((NSTACK_SELECT_MAX_FD + 7) / 8);

    /*add return value check */
    retVal = NSTACK_FD_ZERO(readfd, fd_set_size);
    retVal |= NSTACK_FD_ZERO(writefd, fd_set_size);
    retVal |= NSTACK_FD_ZERO(exceptfd, fd_set_size);
    if (EOK != retVal)
    {
        NSSOC_LOGERR("NSTACK_FD_ZERO memset_s failed]ret=%d", retVal);
        return FALSE;
    }

    select_spin_lock(&module->lock);
    for (tmp = module->entry_head; NULL != tmp; tmp = tmp->next)
    {
        if (tmp->cb[inx].count <= 0)
        {
            continue;
        }

        NSTACK_FD_OR(readfd, &tmp->cb[inx].nstack_readset);
        NSTACK_FD_OR(writefd, &tmp->cb[inx].nstack_writeset);
        NSTACK_FD_OR(exceptfd, &tmp->cb[inx].nstack_exceptset);
        if (nfds < tmp->cb[inx].count)
        {
            nfds = tmp->cb[inx].count;
        }
    }
    select_spin_unlock(&module->lock);

    return nfds;
}

/*no need to check null pointer*/

i32 select_thread_get_fdset_linux(fd_set * readfd,
                                  fd_set * writefd,
                                  fd_set * exceptfd,
                                  struct select_module_info * module, i32 inx)
{
    struct select_entry *tmp;
    i32 nfds = 0;
    int i;

    if (!module)
    {
        return 0;
    }

    FD_ZERO(readfd);
    FD_ZERO(writefd);
    FD_ZERO(exceptfd);

    select_spin_lock(&module->lock);

    for (tmp = module->entry_head; NULL != tmp; tmp = tmp->next)
    {
        if (tmp->cb[inx].count <= 0)
        {
            continue;
        }

        /*need to diff linux and daemon-stack */
        for (i = 0; i < __FD_SETSIZE; i++)
        {
            if (FD_ISSET(i, &tmp->cb[inx].readset))
            {
                FD_SET(i, readfd);
            }

            if (FD_ISSET(i, &tmp->cb[inx].writeset))
            {
                FD_SET(i, writefd);
            }

            if (FD_ISSET(i, &tmp->cb[inx].exceptset))
            {
                FD_SET(i, exceptfd);
            }
        }
        /*need to diff linux and daemon-stack */

        if (nfds < tmp->cb[inx].count)
        {
            nfds = tmp->cb[inx].count;
        }
    }

    select_spin_unlock(&module->lock);

    return nfds;
}

/*****************************************************************************
*   Prototype    : select_thread_set_fdset
*   Description  : set ready event to gloab list
*   Input        : i32 nfds
*                  nstack_fd_set *readfd
*                  nstack_fd_set *writefd
*                  nstack_fd_set *exceptfd
*                  struct select_module_info *module
*                  i32 inx
*                  i32 err
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*****************************************************************************/
i32 select_thread_set_fdset(i32 nfds,
                            nstack_fd_set * readfd,
                            nstack_fd_set * writefd,
                            nstack_fd_set * exceptfd,
                            struct select_module_info * module,
                            i32 inx, i32 err)
{

    struct select_entry *tmp;

    if (!module)
    {
        return FALSE;
    }

    select_spin_lock(&module->lock);
    for (tmp = module->entry_head; NULL != tmp; tmp = tmp->next)
    {
        if (tmp->cb[inx].count <= 0)
        {
            continue;
        }

        if (nfds < 0)
        {
            tmp->ready.readyset = nfds;
            tmp->ready.select_errno = err;
            continue;
        }
        NSSOC_LOGDBG("readyset=%d,index=%d", tmp->ready.readyset, inx);
        entry_module_fdset(tmp, nfds, readfd, writefd, exceptfd, inx);
    }
    select_spin_unlock(&module->lock);
    return TRUE;

}

NSTACK_STATIC inline void entry_mod_fdset_linux(int fd, int idx, int inx,
                                                struct select_entry *entry,
                                                fd_set * readfd,
                                                fd_set * writefd,
                                                fd_set * exceptfd)
{
    if (FD_ISSET(idx, readfd) && FD_ISSET(idx, &entry->cb[inx].readset))
    {
        FD_SET(fd, &entry->ready.readset);
        entry->ready.count++;
        NSSOC_LOGDBG("readyset is %d", entry->ready.readyset);
    }

    if (FD_ISSET(idx, writefd) && FD_ISSET(idx, &entry->cb[inx].writeset))
    {
        FD_SET(fd, &entry->ready.writeset);
        entry->ready.count++;
        NSSOC_LOGDBG("writeset is %d", entry->ready.readyset);
    }

    if (FD_ISSET(idx, exceptfd) && FD_ISSET(idx, &entry->cb[inx].exceptset))
    {
        FD_SET(fd, &entry->ready.exceptset);
        entry->ready.count++;
        NSSOC_LOGDBG("exceptset is %d", entry->ready.readyset);
    }
}

NSTACK_STATIC inline void entry_module_fdset_linux(struct select_entry
                                                   *entry, i32 fd_size,
                                                   fd_set * readfd,
                                                   fd_set * writefd,
                                                   fd_set * exceptfd, i32 inx)
{
    i32 i;
    i32 fd;

    for (i = 0; i < fd_size; i++)
    {
        fd = select_get_commfd(i, inx);
        if (fd < 0)
        {
            continue;
        }

        entry_mod_fdset_linux(fd, i, inx, entry, readfd, writefd, exceptfd);
    }
}

i32 select_thread_set_fdset_linux(i32 nfds,
                                  fd_set * readfd,
                                  fd_set * writefd,
                                  fd_set * exceptfd,
                                  struct select_module_info *module,
                                  i32 inx, i32 err)
{

    struct select_entry *tmp;

    if (!module)
    {
        return FALSE;
    }

    select_spin_lock(&module->lock);
    for (tmp = module->entry_head; NULL != tmp; tmp = tmp->next)
    {
        if (tmp->cb[inx].count <= 0)
        {
            continue;
        }

        if (nfds < 0)
        {
            tmp->ready.readyset = nfds;
            tmp->ready.select_errno = err;
            continue;
        }
        NSSOC_LOGDBG("readyset=%d,index=%d", tmp->ready.readyset, inx);
        entry_module_fdset_linux(tmp, nfds, readfd, writefd, exceptfd, inx);
    }
    select_spin_unlock(&module->lock);
    return TRUE;

}

/*no need to check null pointer*/
/*****************************************************************************
*   Prototype    : select_event_post
*   Description  : when event ready post sem to awaik nstack_select
*   Input        : struct select_module_info *module
*   Output       : None
*   Return Value : void
*   Calls        :
*   Called By    :
*****************************************************************************/
void select_event_post(struct select_module_info *module)
{
    struct select_entry *tmp;
    int inx;
    select_spin_lock(&module->lock);
    for (tmp = module->entry_head; NULL != tmp; tmp = tmp->next)
    {

        if ((tmp->ready.readyset != 0))
        {
            for (inx = 0; inx < nstack_get_module_num(); inx++)
            {
                tmp->cb[inx].count = 0;
            }
            NSSOC_LOGDBG("readyset=%d", tmp->ready.readyset);
            select_sem_post(&tmp->sem); /*do not need return value */
        }
    }
    select_spin_unlock(&module->lock);
}

/*no need to check null pointer*/

/*set select_event  function*/
i32 select_module_init()
{
    i32 i;
    i32 retval;

    if (fdmapping_init() < 0)
    {
        goto ERR_RET;
    }

    g_select_module.default_mod = nstack_get_linux_mid();
    g_select_module.default_fun = nsfw_base_select;

    /*regist select fun */
    for (i = 0; i < nstack_get_module_num(); i++)
    {
        g_select_module.get_select_fun_nonblock[i] =
            nstack_module_ops(i)->pfselect;
    }

    select_sem_init(&g_select_module.sem, 0, 0);        /*do not need return value */
    select_spin_lock_init(&g_select_module.lock);

    if (pthread_create(&g_select_thread_id, NULL, nstack_select_thread, NULL))
    {

        goto ERR_RET;
    }

    retval = pthread_setname_np(g_select_thread_id, "nstack_select");
    if (retval)
    {
        /*set thread name failed */
    }

    g_select_module.inited = TRUE;
    g_select_module.entry_head = g_select_module.entry_tail = NULL;
    return TRUE;

  ERR_RET:

    return FALSE;
}

NSTACK_STATIC inline void entry_mod_fdset_nstack(int fd, int idx, int inx,
                                                 struct select_entry *entry,
                                                 nstack_fd_set * readfd,
                                                 nstack_fd_set * writefd,
                                                 nstack_fd_set * exceptfd)
{
    if (NSTACK_FD_ISSET(idx, readfd)
        && NSTACK_FD_ISSET(idx, &entry->cb[inx].nstack_readset))
    {
        FD_SET(fd, &entry->ready.readset);
        entry->ready.count++;
        NSSOC_LOGDBG("readyset is %d", entry->ready.readyset);
    }

    if (NSTACK_FD_ISSET(idx, writefd)
        && NSTACK_FD_ISSET(idx, &entry->cb[inx].nstack_writeset))
    {
        FD_SET(fd, &entry->ready.writeset);
        entry->ready.count++;
        NSSOC_LOGDBG("writeset is %d", entry->ready.readyset);
    }

    if (NSTACK_FD_ISSET(idx, exceptfd)
        && NSTACK_FD_ISSET(idx, &entry->cb[inx].nstack_exceptset))
    {
        FD_SET(fd, &entry->ready.exceptset);
        entry->ready.count++;
        NSSOC_LOGDBG("exceptset is %d", entry->ready.readyset);
    }
}

/*no need to check null pointer*/
void entry_module_fdset(struct select_entry *entry,
                        i32 fd_size,
                        nstack_fd_set * readfd,
                        nstack_fd_set * writefd,
                        nstack_fd_set * exceptfd, i32 inx)
{
    i32 i;
    i32 fd;

    for (i = 0; i < fd_size; i++)
    {
        fd = select_get_commfd(i, inx);
        if (fd < 0)
        {
            continue;
        }

        entry_mod_fdset_nstack(fd, i, inx, entry, readfd, writefd, exceptfd);
    }
}

NSTACK_STATIC inline int nstack_fd_copy(nstack_fd_set * psrc,
                                        nstack_fd_set * pdst, u32 size)
{
    return memcpy_s(pdst->fds_bits, size, psrc->fds_bits, size);
}

NSTACK_STATIC inline int alloc_and_init_fd_set(nstack_fd_set * readfd,
                                               nstack_fd_set * writefd,
                                               nstack_fd_set * exceptfd,
                                               struct select_cb_p *select_cb)
{
    int ret = 0;
    u32 fds_bits_size =
        sizeof(unsigned char) * ((NSTACK_SELECT_MAX_FD + 7) >> 3);

    readfd->fds_bits = select_fd_set_bits_alloc();
    writefd->fds_bits = select_fd_set_bits_alloc();
    exceptfd->fds_bits = select_fd_set_bits_alloc();
    if (!readfd->fds_bits || !writefd->fds_bits || !exceptfd->fds_bits)
    {
        return -1;
    }

    ret |=
        nstack_fd_copy(&(select_cb->nstack_readset), readfd, fds_bits_size);
    ret |=
        nstack_fd_copy(&(select_cb->nstack_writeset), writefd, fds_bits_size);
    ret |=
        nstack_fd_copy(&(select_cb->nstack_exceptset), exceptfd,
                       fds_bits_size);
    if (EOK != ret)
    {
        return -1;
    }

    return 0;
}

NSTACK_STATIC inline i32 select_scan_linux(struct select_entry * entry,
                                           int inx)
{
    i32 fd_size;
    i32 ready;
    fd_set readfd;
    fd_set writefd;
    fd_set exceptfd;
    struct timeval timeout;

    fd_size = entry->cb[inx].count;
    if (!g_select_module.get_select_fun_nonblock[inx] || (fd_size <= 0))
    {
        return TRUE;
    }

    readfd = (entry->cb[inx].readset);
    writefd = (entry->cb[inx].writeset);
    exceptfd = (entry->cb[inx].exceptset);

    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    ready =
        g_select_module.get_select_fun_nonblock[inx] (fd_size, &readfd,
                                                      &writefd, &exceptfd,
                                                      &timeout);
    if (ready > 0)
    {
        entry_module_fdset_linux(entry, fd_size, &readfd, &writefd,
                                 &exceptfd, inx);
    }
    else if (ready < 0)
    {
        entry->ready.count = ready;
        entry->ready.select_errno = errno;
        NSSOC_LOGERR("select failed index = %d", inx);
        return FALSE;
    }

    return TRUE;
}

NSTACK_STATIC inline i32 select_scan_nstack(struct select_entry * entry,
                                            int inx)
{
    i32 fd_size;
    i32 ready;
    i32 ret = TRUE;
    nstack_fd_set *readfd = NULL;
    nstack_fd_set *writefd = NULL;
    nstack_fd_set *exceptfd = NULL;
    struct timeval timeout;

    fd_size = entry->cb[inx].count;
    if (!g_select_module.get_select_fun_nonblock[inx] || (fd_size <= 0))
    {
        return TRUE;
    }

    readfd = select_alloc(sizeof(nstack_fd_set));
    writefd = select_alloc(sizeof(nstack_fd_set));
    exceptfd = select_alloc(sizeof(nstack_fd_set));

    if (!readfd || !writefd || !exceptfd)
    {
        NSSOC_LOGERR("malloc fd sets failed");
        FREE_SELECT_FD_SET(readfd, writefd, exceptfd);
        return FALSE;
    }

    if (alloc_and_init_fd_set(readfd, writefd, exceptfd, &(entry->cb[inx])))
    {
        NSSOC_LOGERR("malloc fd bits failed");
        goto return_over;
        ret = FALSE;
    }

    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    ready =
        g_select_module.get_select_fun_nonblock[inx] (fd_size,
                                                      (fd_set *) readfd,
                                                      (fd_set *) writefd,
                                                      (fd_set *) exceptfd,
                                                      &timeout);
    if (ready > 0)
    {
        entry_module_fdset(entry, fd_size, readfd, writefd, exceptfd, inx);
    }
    else if (ready < 0)
    {
        entry->ready.count = ready;
        entry->ready.select_errno = errno;
        NSSOC_LOGERR("select failed index = %d", inx);
        goto return_over;
        ret = FALSE;
    }

  return_over:
    SELECT_FREE_FD_BITS(readfd, writefd, exceptfd);
    FREE_SELECT_FD_SET(readfd, writefd, exceptfd);
    return ret;
}

/*****************************************************************************
*   Prototype    : select_scan
*   Description  : scan all modules to check event ready or not
*   Input        : struct select_entry *entry
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*****************************************************************************/
i32 select_scan(struct select_entry * entry)
{
    i32 inx;
    int ret = 0;

    for (inx = 0; inx < nstack_get_module_num(); inx++)
    {
        if (inx == nstack_get_linux_mid())
        {
            ret = select_scan_linux(entry, inx);
        }
        else
        {
            ret = select_scan_nstack(entry, inx);
        }

        if (!ret)
        {
            return FALSE;
        }
    }

    return TRUE;
}

/*no need to check null pointer*/

/*try to get event form all modules */
/*****************************************************************************
*   Prototype    : nstack_select_thread
*   Description  : if gloab list not null scaning all modules ,need to think
                   about block mod
*   Input        : void *arg
*   Output       : None
*   Return Value : void *
*   Calls        :
*   Called By    :
*****************************************************************************/

void *nstack_select_thread(void *arg)
{

#define  SELECT_SLEEP_TIME  800 //us

    i32 inx;
    nstack_fd_set *readfd;
    nstack_fd_set *writefd;
    nstack_fd_set *exceptfd;
    fd_set rdfd;
    fd_set wtfd;
    fd_set expfd;
    i32 fd_size;
    i32 ready;
    i32 sleep_time = SELECT_SLEEP_TIME;
    struct timeval timeout;
    int selet_errno;

    readfd = select_alloc(sizeof(nstack_fd_set));
    writefd = select_alloc(sizeof(nstack_fd_set));
    exceptfd = select_alloc(sizeof(nstack_fd_set));
    if ((!readfd) || (!writefd) || (!exceptfd))
    {
        NSPOL_LOGERR("malloc nstack_fd_set fail");
        FREE_SELECT_FD_SET(readfd, writefd, exceptfd);
        return NULL;
    }

    readfd->fds_bits = select_fd_set_bits_alloc();
    writefd->fds_bits = select_fd_set_bits_alloc();
    exceptfd->fds_bits = select_fd_set_bits_alloc();
    if ((!readfd->fds_bits) || (!writefd->fds_bits) || (!exceptfd->fds_bits))
    {
        NSPOL_LOGERR("malloc fd_bits for nstack_fd_set fail");

        SELECT_FREE_FD_BITS(readfd, writefd, exceptfd);
        FREE_SELECT_FD_SET(readfd, writefd, exceptfd);
        return NULL;
    }

    /*used nonblock  need add block mod later */

    for (;;)
    {
        /*wait app calling select no cong cpu */
        if (!g_select_module.entry_head)
        {
            select_sem_wait(&g_select_module.sem);      /*do not need return value */
        }

        for (inx = 0; inx < nstack_get_module_num(); inx++)
        {

            if (inx == nstack_get_linux_mid())
            {
                fd_size =
                    select_thread_get_fdset_linux(&rdfd, &wtfd, &expfd,
                                                  &g_select_module, inx);
                if (fd_size <= 0)
                    continue;
                if (g_select_module.get_select_fun_nonblock[inx])
                    ready =
                        g_select_module.get_select_fun_nonblock[inx] (fd_size,
                                                                      (fd_set
                                                                       *) &
                                                                      rdfd,
                                                                      (fd_set
                                                                       *) &
                                                                      wtfd,
                                                                      (fd_set
                                                                       *) &
                                                                      expfd,
                                                                      &timeout);
                else
                    continue;

                if (ready > 0)

                    select_thread_set_fdset_linux(fd_size, &rdfd,
                                                  &wtfd, &expfd,
                                                  &g_select_module, inx, 0);
                else if (ready < 0)
                {

                    selet_errno = errno;
                    select_thread_set_fdset_linux(fd_size, &rdfd, &wtfd,
                                                  &expfd, &g_select_module,
                                                  inx, selet_errno);
                    break;
                }
            }
            else
            {
                fd_size =
                    select_thread_get_fdset(readfd, writefd, exceptfd,
                                            &g_select_module, inx);
                if (fd_size <= 0)
                    continue;
                if (g_select_module.get_select_fun_nonblock[inx])
                    ready =
                        g_select_module.get_select_fun_nonblock[inx] (fd_size,
                                                                      (fd_set
                                                                       *)
                                                                      readfd,
                                                                      (fd_set
                                                                       *)
                                                                      writefd,
                                                                      (fd_set
                                                                       *)
                                                                      exceptfd,
                                                                      &timeout);
                else
                    continue;

                if (ready > 0)
                    select_thread_set_fdset(fd_size, readfd, writefd, exceptfd, &g_select_module, inx, 0);      /*do not need return value */
                else if (ready < 0)
                {
                    selet_errno = errno;
                    select_thread_set_fdset(ready, readfd, writefd, exceptfd, &g_select_module, inx, selet_errno);      /*do not need return value */
                    break;
                }

            }

        }
        select_event_post(&g_select_module);
        timeout.tv_sec = 0;
        timeout.tv_usec = sleep_time;
        /*use linux select for timer */
        nsfw_base_select(1, NULL, NULL, NULL, &timeout);
        //sys_sleep_ns(0, sleep_time); //g_sem_sleep_time
    }
}

/*****************************************************************************
*   Prototype    : nssct_create
*   Description  : create a select record for eveny fd
*   Input        : i32 cfd
*                  i32 mfd
*                  i32 inx
*   Output       : None
*   Return Value : void
*   Calls        :
*   Called By    :
*****************************************************************************/
void nssct_create(i32 cfd, i32 mfd, i32 inx)
{
    if (g_select_module.inited != TRUE)
    {
        return;
    }
    select_set_modfd(cfd, inx, mfd);    /*do not need return value */
    select_set_commfd(mfd, inx, cfd);   /*do not need return value */
}

/*****************************************************************************
*   Prototype    : nssct_close
*   Description  : rm the record
*   Input        : i32 cfd
*                  i32 inx
*   Output       : None
*   Return Value : void
*   Calls        :
*   Called By    :
*****************************************************************************/
void nssct_close(i32 cfd, i32 inx)
{
    if (g_select_module.inited != TRUE)
    {
        return;
    }
    i32 mfd = select_get_modfd(cfd, inx);
    select_set_modfd(cfd, inx, -1);     /*do not need return value */
    select_set_commfd(mfd, inx, -1);    /*do not need return value */
    select_set_index(cfd, -1);  /*do not need return value */
}

/*****************************************************************************
*   Prototype    : nssct_set_index
*   Description  : set select fd index
*   Input        : i32 fd
*                  i32 inx
*   Output       : None
*   Return Value : void
*   Calls        :
*   Called By    :
*****************************************************************************/
void nssct_set_index(i32 fd, i32 inx)
{
    if (g_select_module.inited != TRUE)
    {
        return;
    }
    select_set_index(fd, inx);  /*do not need return value */
}

int select_scan_return_from_entry(fd_set * readfds, fd_set * writefds,
                                  fd_set * exceptfds,
                                  struct select_entry *entry)
{
    int ret;
    if (readfds)
    {
        *readfds = entry->ready.readset;
    }
    if (writefds)
    {
        *writefds = entry->ready.writeset;
    }
    if (exceptfds)
    {
        *exceptfds = entry->ready.exceptset;
    }

    ret = entry->ready.readyset;
    if (ret < 0)
    {
        errno = entry->ready.select_errno;
    }
    return ret;
}

void nstack_select_entry_free(struct select_entry *entry)
{
    int i;

    if (!entry)
        return;

    for (i = 0; i < nstack_get_module_num(); i++)
    {

        SELECT_FREE_FD_BITS(&entry->cb[i].nstack_readset,
                            &entry->cb[i].nstack_writeset,
                            &entry->cb[i].nstack_exceptset);
    }

    SELECT_FREE_FD_BITS(&entry->ready.nstack_readset,
                        &entry->ready.nstack_writeset,
                        &entry->ready.nstack_exceptset);

}

void nstack_select_entry_alloc(struct select_entry **entry)
{
    struct select_entry *tmp;
    int i;

    tmp = select_alloc(sizeof(struct select_entry));
    if (!tmp)
        return;
    for (i = 0; i < nstack_get_module_num(); i++)
    {
        tmp->cb[i].nstack_readset.fds_bits = select_fd_set_bits_alloc();
        tmp->cb[i].nstack_writeset.fds_bits = select_fd_set_bits_alloc();
        tmp->cb[i].nstack_exceptset.fds_bits = select_fd_set_bits_alloc();
        if (!tmp->cb[i].nstack_readset.fds_bits ||
            !tmp->cb[i].nstack_writeset.fds_bits ||
            !tmp->cb[i].nstack_exceptset.fds_bits)
        {
            goto err_return;
        }
    }

    tmp->ready.nstack_readset.fds_bits = select_fd_set_bits_alloc();
    tmp->ready.nstack_writeset.fds_bits = select_fd_set_bits_alloc();
    tmp->ready.nstack_exceptset.fds_bits = select_fd_set_bits_alloc();
    if (!tmp->ready.nstack_readset.fds_bits ||
        !tmp->ready.nstack_writeset.fds_bits ||
        !tmp->ready.nstack_exceptset.fds_bits)
    {
        goto err_return;
    }

    *entry = tmp;
    return;
  err_return:
    nstack_select_entry_free(tmp);
    *entry = NULL;
}

void select_fail_stat(i32 nfds,
                      fd_set * readfd, fd_set * writefd, fd_set * exceptfd)
{
    i32 i;
    i32 event_id = 0;
    nstack_fd_Inf *fdInf = NULL;

    for (i = 0; i < nfds; i++)
    {

        event_id = 0;
        if (!((readfd && FD_ISSET(i, readfd)) ||
              (writefd && FD_ISSET(i, writefd)) ||
              (exceptfd && FD_ISSET(i, exceptfd))))
        {
            continue;
        }

        fdInf = nstack_get_valid_inf(i);
        if ((NULL == fdInf) || !fdInf->ops
            || (fdInf->rmidx != MOD_INDEX_FOR_STACKPOOL))
        {
            continue;
        }
        if ((readfd) && (FD_ISSET(i, readfd)))
        {
            event_id |= EPOLLIN;
        }
        if ((writefd) && (FD_ISSET(i, writefd)))
        {
            event_id |= EPOLLOUT;
        }
        if ((exceptfd) && (FD_ISSET(i, exceptfd)))
        {
            event_id |= EPOLLERR;
        }
        nstack_dfx_state_update((u64) fdInf->rlfd, fdInf->rmidx,
                                DMM_APP_SELECT_FAIL,
                                (void *) ((u64_t) event_id));
    }
}

int nstack_select_processing(int nfds, fd_set * readfds, fd_set * writefds,
                             fd_set * exceptfds, struct timeval *timeout)
{
    int ret = -1;
    struct select_module_info *select_module = get_select_module();
    struct select_entry *entry = NULL;

    nstack_select_entry_alloc(&entry);
    if (NULL == entry)
    {
        errno = ENOMEM;
        NSSOC_LOGERR("select entry alloc fail");
        goto err_return;
    }
    /* need init sem */
    select_sem_init(&entry->sem, 0, 0); /*do not need return value */

    /* fix dead-code type */
    /*split select fd to each modules fd and save to entry */
    (void) select_cb_split_by_mod(nfds, readfds, writefds, exceptfds, entry);

    /*if all fd in default module we just calling it */
    if (entry->info.set_num <= 1)
    {

        /*adapte linux */
        if ((select_module)
            && (entry->info.index == select_module->default_mod))
        {
            if (select_module->default_fun)
            {
                ret =
                    select_module->default_fun(nfds, readfds, writefds,
                                               exceptfds, timeout);
            }
            else
            {
                ret =
                    nsfw_base_select(nfds, readfds, writefds, exceptfds,
                                     timeout);
            }
            goto err_return;
        }
    }

    /*cheching if event ready or not */
    if (FALSE == select_scan(entry))
    {
        NSSOC_LOGERR("select scan fail");
        goto err_return;
    }

    if (entry->ready.readyset != 0)
    {
        goto scan_return;
    }

    if (TIMEVAL_EQUAL_ZERO(timeout))
    {
        goto scan_return;
    }

    if (FALSE == select_add_cb(entry))
    {
        errno = ENOMEM;
        NSSOC_LOGERR("select entry add fail");
        goto err_return;
    }

    if (NULL == timeout)
    {
        select_sem_wait(&entry->sem);   /*do not need return value */
    }
    else
    {
        long time_cost = 0;
        long msec = 0;
        if (nstack_timeval2msec(timeout, &msec))
        {
            nstack_set_errno(EINVAL);
            goto err_return;
        }
        ret = nstack_sem_timedwait(&entry->sem, msec, &time_cost);
        if (ret < 0)
        {
            nstack_set_errno(EINVAL);
            goto err_return;
        }

        if (time_cost >= msec)
        {
            select_fail_stat(nfds, readfds, writefds, exceptfds);
            timeout->tv_sec = 0;
            timeout->tv_usec = 0;
        }
        else if (time_cost > 0)
        {
            msec = msec - time_cost;
            timeout->tv_sec = msec / 1000;
            timeout->tv_usec = (msec % 1000) * 1000;
        }
    }

    select_rm_cb(entry);        /*do not need return value */

  scan_return:
    ret = select_scan_return_from_entry(readfds, writefds, exceptfds, entry);

  err_return:
    if (entry)
    {
        nstack_select_entry_free(entry);
    }
    NSSOC_LOGDBG
        ("nfds=%d,readfds=%p,writefds=%p,exceptfds=%p,timeout=%p,ret=%d errno=%d",
         nfds, readfds, writefds, exceptfds, timeout, ret, errno);

    return ret;
}

#endif /* NSTACK_SELECT_MODULE */
