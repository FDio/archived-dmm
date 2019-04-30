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

#include "nstack_eventpoll.h"
#include "nsfw_mem_api.h"
#include "nstack_log.h"
#include "nstack_securec.h"
#include "nsfw_recycle_api.h"
#include "nsfw_maintain_api.h"
#include <stdio.h>
#include <stdlib.h>
//#include "nstack.h"
#include "nstack_epoll_api.h"
#include "nstack_share_res.h"
#include "dmm_spinlock.h"

nsep_epollManager_t g_epollMng = {
    .infoSockMap = NULL,
    .checkEpollFD = -1
};

extern int nsfw_ps_check_pid_nstack_status(int pid);

/* after close fd in epfd, epfd still can epoll_wait EPOLLIN event for these fd
    NOTE: 1.this func must be called in pinfo->epiLock, or else it is possible that there are multi epi in same ep ring_hd
	2. epi_addr should be local addr.
*/
int nstack_epoll_event_dequeue(void *epi_addr, int events)
{

    struct epitem *epi;
    struct epitem *tmp_epi = NULL;
    int enQueRet = 0, enQueRet_2 = 0;
    u32 queue_use_count = 0, tmp_count = 0;
    mring_handle mr_hand = NULL;
    struct spl_conn_pool *ep_spl = NULL;
    struct eventpoll *ep = NULL;
    int retVal = -1;

    epi = (struct epitem *) (epi_addr);
    if (events & epi->event.events)
        return 0;

    if (NULL != epi->ep_spl)
    {
        ep = (struct eventpoll *) SHMEM_ADDR_SHTOL(epi->ep);
        ep_spl = (struct spl_conn_pool *) SHMEM_ADDR_SHTOL(epi->ep_spl);
        mr_hand = (mring_handle) SHMEM_ADDR_SHTOL(ep_spl->ring_hd);
        /* dont clear epi successfully, it cause app coredump */
        queue_use_count = nsfw_mem_ring_using_count(mr_hand) + 4;       /* for perfring, it only add head and tail PERFRING_HEAD_INCRASE_MASK */

        while (tmp_count < queue_use_count)
        {
            enQueRet = nsfw_mem_ring_dequeue(mr_hand, (void **) &tmp_epi);
            if ((enQueRet > 0) && (epi == tmp_epi))
            {
                /* queue success */
                retVal = 0;
                epi->spl_enter_count--;
                return retVal;
            }
            else if (enQueRet > 0)
            {
                enQueRet_2 = nsfw_mem_ring_enqueue(mr_hand, tmp_epi);
                if (1 != enQueRet_2)
                {
                    NSPOL_LOGERR("]mr_hand=%p,tmp_epi=%p", mr_hand, tmp_epi);
                    return retVal;
                }
                g_ns_sync_ops.ns_sync_sem_post(&ep->waitSem);   /*do not need return value */
            }
            else
            {
                /* have finish all dequeue, return call */
                return retVal;
            }
            tmp_count++;
        }

        /* in queue, don't have this epi */
    }
    return retVal;
}

/*  epoll global lock in daemon-stack
    cause daemon-stack message handle slowing */
void nsep_recycle_upgrade_resource(void)
{
    /* if app use new version, daemon-stack use old version, then conn_pool  resource that
       app apply willn't recycle by old daemon-stack version, so when upgrade daemon-stack to new vesion,
       it need recycle these resource;
     */
    nsep_epollManager_t *manager = nsep_get_manager();
    struct spl_conn_pool *pool = manager->ep_connPoll.pool;

    u32_t pos;
    u32_t free_count = 0;
    int tmp_pid = 0;
    for (pos = 0; pos < NSTACK_MAX_EPOLL_FD_NUM - 1; pos++)
    {
        if (pool[pos].pid == 0)
        {
            continue;
        }
        tmp_pid = pool[pos].pid;

        if (0 == nsfw_ps_check_pid_nstack_status(tmp_pid))
        {
            continue;
        }

        if (-1 == nsep_free_ep_spl_conn_ring(&pool[pos]))
        {
            NSFW_LOGWAR("spl_conn_ring]pid=%d,pool=%p,pos=%u,ring_hd=%p",
                        tmp_pid, &pool[pos], pos, pool[pos].ring_hd);
            break;
        }
        else
        {
            free_count++;
        }
    }
    if (free_count > 0)
    {
        NSFW_LOGINF("spl_conn_ring]pid=%d,free_count=%u", tmp_pid,
                    free_count);
    }
    return;
}

/*
 *    This function will find the epitem of fd in eventpool ep
 *    This is only used in epoll_ctl add
 */
struct epitem *nsep_find_ep(struct eventpoll *ep, int fd)
{
    struct ep_rb_node *rbp;
    struct epitem *epi, *epir = NULL;
    u32_t loopCnt = 0;

    for (rbp = SHMEM_ADDR_SHTOL(ep->rbr.rb_node); rbp;)
    {
        ++loopCnt;
        if (loopCnt > NSTACK_MAX_EPITEM_NUM)
            break;

        epi = (struct epitem *) ep_rb_entry(rbp, struct epitem, rbn);

        if (fd > epi->fd)
        {
            rbp = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(rbp->rb_right);
        }
        else if (fd < epi->fd)
        {
            rbp = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(rbp->rb_left);
        }
        else
        {
            epir = epi;
            break;
        }
    }

    if (loopCnt > NSTACK_MAX_EPITEM_NUM)
    {
        NSSOC_LOGERR("Loop out of range!!!!");
    }

    return epir;
}

int nstack_ep_unlink(struct eventpoll *ep, struct epitem *epi)
{
    int error = ENOENT;

    if (ep_rb_parent(&epi->rbn) == (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(&epi->rbn))       /* if (!ep_rb_linked(&epi->rbn)) */
    {
        NSSOC_LOGWAR("ep_rb_parent == epi->rbn");
        return error;
    }

    epi->event.events = 0;

    ep_rb_erase(&epi->rbn, &ep->rbr);
    ep_rb_set_parent(&epi->rbn, &epi->rbn);

    if (EP_HLIST_NODE_LINKED(&epi->rdllink))
    {
        ep_hlist_del(&ep->rdlist, &epi->rdllink);
    }

    return 0;
}

/**
 * @Function        nsep_free_epitem
 * @Description     free nstack epitem
 * @param in        data - the epitem to be free
 * @return          0 on success, -1 on error
 */
int nsep_free_epitem(struct epitem *data)
{

    struct epitem *epiEntry = (struct epitem *) data;
    struct epitem_pool *pool = &nsep_get_manager()->epitemPool;
    epiEntry->pid = 0;
    NSSOC_LOGDBG("nsep_free_epitem data:%p", data);
    if (res_free(&epiEntry->res_chk))
    {
        NSFW_LOGERR("epitem refree!]epitem=%p", epiEntry);
        return -1;              //3th round code security review fix
    }

    /* dont clear epi successfully, it cause app coredump */
    epiEntry->ep = NULL;
    epiEntry->epInfo = NULL;
    epiEntry->private_data = NULL;
    epiEntry->ep_spl = NULL;
    epiEntry->revents = 0;
    if (nsfw_mem_ring_enqueue(pool->ring, (void *) epiEntry) != 1)
    {
        NSSOC_LOGERR("Error to free epitem");
        return -1;              //3th round code security review fix
    }
    return 0;
}

NSTACK_STATIC void nsep_init_epinfo(nsep_epollInfo_t * info)
{
    int iindex = 0;
    EP_LIST_INIT(&info->epiList);
    DMM_SPINLOCK_MALLOC(info->epiLock, 1);
    DMM_SPINLOCK_MALLOC(info->freeLock, 1);

    info->rlfd = -1;
    info->rmidx = -1;
    info->fd = -1;
    info->ep = NULL;
    info->fdtype = 0;
    info->ep_conn = NULL;       /* for epoll d use, when create epoll fd, it will set this to valid pointer */
    info->ep_conn_flag = 1;     /* if this  */
    info->private_data = NULL;
    for (iindex = 0; iindex < NSEP_SMOD_MAX; iindex++)
    {
        info->protoFD[iindex] = -1;
        info->epaddflag[iindex] = 0;
    }
    if (nsep_for_pidinfo_init(&(info->pidinfo)))
    {
        NSSOC_LOGERR("pid info init failed]epitem=%p", info);
    }
}

NSTACK_STATIC void nsep_destroy_epinfo(nsep_epollInfo_t * info)
{
    if (NULL == info)
    {
        return;
    }
    info->ep_conn = NULL;       /* must set to NULL when free , it impact new old nstackverion compatible */
    info->ep_conn_flag = 0;
    // TODO: Here we need to free the semaphore
    return;
}

/**
 * @Function        nstack_eventpoll_allocShareInfo
 * @Description     alloc nstack share info
 * @param out       data - the return value alloced
 * @return          0 on success, -1 on error
 */
int nsep_alloc_epinfo(nsep_epollInfo_t ** data)
{
    nsep_epollInfo_t *head_info = NULL;

    if (NULL == data)
        return -1;
    NSSOC_LOGDBG("epinfo alloc begin");

    nsep_infoPool_t *pool = &nsep_get_manager()->infoPool;
    if (0 == nsfw_mem_ring_dequeue(pool->ring, (void *) &head_info)
        || NULL == head_info)
    {
        NSSOC_LOGERR("epinfo ring alloc failed]pool->ring=%p", pool->ring);
        return -1;
    }

    res_alloc(&head_info->res_chk);

    nsep_init_epinfo(head_info);
    if (0 != nsep_add_pid(&head_info->pidinfo, get_sys_pid()))
    {
        NSSOC_LOGERR("epinfo pid add to headinfo failed]pid=%d,headinfo=%p",
                     get_sys_pid(), head_info);
    }
    NSSOC_LOGDBG("epinfo ring:%p alloc epinfo:%p end", pool->ring, head_info);
    *data = head_info;
    return 0;
}

/*  epoll global lock in daemon-stack
    cause daemon-stack message handle slowing */
NSTACK_STATIC int nsep_lookup_ep_spl_conn(void)
{

    nsfw_mem_name mem_name;
    mzone_handle mz_handle = NULL;
    nsep_epollManager_t *manager = nsep_get_manager();

    int retVal = strcpy_s(mem_name.aname, sizeof(mem_name.aname),
                          MP_NSTACK_SPL_CONN_RING_NAME);
    if (EOK != retVal)
    {
        NSSOC_LOGERR("strcpy_s failed]");
        return -1;
    }

    mem_name.enowner = NSFW_PROC_MAIN;
    mem_name.entype = NSFW_SHMEM;
    mz_handle = nsfw_mem_zone_lookup(&mem_name);
    if (NULL == mz_handle)
    {
        return -1;
    }

    manager->ep_connPoll.ring = mz_handle;

    retVal =
        strcpy_s(mem_name.aname, sizeof(mem_name.aname),
                 MP_NSTACK_SPL_CONN_ARRAY_NAME);
    if (EOK != retVal)
    {
        NSSOC_LOGERR("strcpy_s failed]");
        return -1;
    }

    mz_handle = nsfw_mem_zone_lookup(&mem_name);
    manager->ep_connPoll.pool = mz_handle;
    if (NULL == mz_handle)
    {
        return -1;
    }

    return 0;
}

/*  epoll global lock in daemon-stack
    cause daemon-stack message handle slowing */
int nsep_alloc_ep_spl_conn_ring(struct spl_conn_pool **data)
{
    struct spl_conn_pool *head_info = NULL;
    i32 enQueRet = 0;
    struct epitem *epi = NULL;

    if (NULL == data)
        return -1;
    NSSOC_LOGDBG("epinfo alloc begin");

    struct ep_conn_pool *pool = &nsep_get_manager()->ep_connPoll;

    /* support upgrade, if daemon-stack is old version, then here will fail */
    if (NULL == pool->ring)
    {
        /* check whether  daemon-stack  is new version, if it use new version, then use ring epoll */
        if (-1 == nsep_lookup_ep_spl_conn())
        {
            return -1;
        }
    }

    if (0 == nsfw_mem_ring_dequeue(pool->ring, (void *) &head_info)
        || NULL == head_info)
    {
        NSSOC_LOGERR("ep_spl_conn_ring alloc failed]pool->ring=%p",
                     pool->ring);
        return -1;
    }
    res_alloc(&head_info->res_chk);
    head_info->pid = get_sys_pid();
    head_info->revents = 0;

    /* clear the ring_hd before use */
    do
    {
        enQueRet =
            nsfw_mem_ring_dequeue(SHMEM_ADDR_SHTOL(head_info->ring_hd),
                                  (void **) &epi);
        /* when free ep_con, it have clean ring_hd, if here find it still have epi in this ring, it indicate that it still use it after ep_conn was freed,
           it need check the reason */
        if (enQueRet > 0)
        {
            NSSOC_LOGERR
                ("fine have epi in ep_spl ring]head_info=%p,ring_hd=%p,epi=%p",
                 head_info, head_info->ring_hd, epi);
        }

    }
    while (enQueRet > 0);

    NSSOC_LOGDBG("spl_conn_ring]head_info=%p,ring_hd=%p,pid=%d", head_info,
                 head_info->ring_hd, head_info->pid);

    NSSOC_LOGDBG("epinfo ring:%p alloc epinfo:%p end", pool->ring, head_info);
    *data = head_info;
    return 0;
}

int nsep_free_ep_spl_conn_ring(struct spl_conn_pool *data)
{
    struct spl_conn_pool *head_info = data;
    struct epitem *epi = NULL;
    i32 enQueRet = 0;
    unsigned int total_count = 0;

    if (NULL == data)
        return -1;
    NSSOC_LOGDBG("nsep_free_ep_spl_conn_ring begin");

    struct ep_conn_pool *pool = &nsep_get_manager()->ep_connPoll;
    /* clear the ring_hd before free */
    do
    {
        enQueRet =
            nsfw_mem_ring_dequeue(SHMEM_ADDR_SHTOL(head_info->ring_hd),
                                  (void **) &epi);
        if (enQueRet > 0)
        {
            total_count += enQueRet;
        }
    }
    while (enQueRet > 0);

    head_info->pid = 0;
    head_info->revents = 0;

    if (res_free(&head_info->res_chk))
    {
        NSFW_LOGERR
            ("ep_spl_conn refree!]spl_conn=%p,ring_hd=%p,total_count=%u",
             head_info, head_info->ring_hd, total_count);
        return -1;              // 3th round code security review fix
    }

    if (0 == nsfw_mem_ring_enqueue(pool->ring, (void *) head_info))
    {
        NSSOC_LOGERR("spl_conn_ring free failed]pool->ring=%p,head_info=%p",
                     pool->ring, head_info);
        return -1;
    }

    NSSOC_LOGDBG("spl_conn_ring]head_info=%p,ring_hd=%p,pid=%d", head_info,
                 head_info->ring_hd, head_info->pid);

    return 0;
}

/**
 * @Function        nstack_eventpoll_freeShareInfo
 * @Description     free nstack share info
 * @param in        info - the info to be free
 * @return          0 on success, -1 on error
 */
int nsep_free_epinfo(nsep_epollInfo_t * info)
{

    if (NULL == info)
        return -1;

    nsep_infoPool_t *pool = &nsep_get_manager()->infoPool;
    NSSOC_LOGDBG("nsep_free_epinfo info:%p, pool->ring:%p", info, pool->ring);
    nsep_destroy_epinfo(info);

    if (nsep_for_pidinfo_init(&(info->pidinfo)))
    {
        NSSOC_LOGERR("pid info init failed]epitem=%p", info);
        return -1;
    }

    if (res_free(&info->res_chk))
    {
        NSFW_LOGERR("epinfo refree!]epitem=%p", info);
        return -1;              // 3th round code security review fix
    }

    if (nsfw_mem_ring_enqueue(pool->ring, (void *) info) != 1)
    {
        NSSOC_LOGERR("Errot to free epinfo");
        return -1;              // 3th round code security review fix
    }

    return 0;
}

int nsep_force_epinfo_free(void *data)
{
    nsep_epollInfo_t *info = data;
    if (NULL == info)
    {
        return FALSE;
    }

    if (!nsep_is_pid_array_empty(&info->pidinfo))
    {
        return FALSE;
    }

    res_alloc(&info->res_chk);
    (void) nsep_free_epinfo(info);
    NSFW_LOGINF("free epinfo]%p", data);
    return TRUE;
}

int nsep_force_epitem_free(void *data)
{
    struct epitem *item = data;
    if (NULL == item)
    {
        return FALSE;
    }

    if (0 != item->pid)
    {
        return FALSE;
    }

    res_alloc(&item->res_chk);
    (void) nsep_free_epitem(item);
    NSFW_LOGINF("free epitem]%p", data);
    return TRUE;
}

int nsep_force_epevent_free(void *data)
{
    struct eventpoll *epevent = data;
    if (NULL == epevent)
    {
        return FALSE;
    }

    if (0 != epevent->pid)
    {
        return FALSE;
    }

    res_alloc(&epevent->res_chk);
    (void) nsep_free_eventpoll(epevent);
    NSFW_LOGINF("free event pool]%p", data);
    return TRUE;
}

int nsep_force_ep_spl_conn_free(void *data)
{
    struct spl_conn_pool *epConnPool = data;
    if (NULL == epConnPool)
    {
        return FALSE;
    }

    if (0 != epConnPool->pid)
    {
        return FALSE;
    }

    res_alloc(&epConnPool->res_chk);
    (void) nsep_free_ep_spl_conn_ring(epConnPool);
    NSFW_LOGINF("free spl conn pool]%p", data);
    return TRUE;
}

NSTACK_STATIC int nsep_init_eventpoll(struct eventpoll *ep, int idx)
{
    int *args;

    args = (int *) ep->waitSem.args;
    *args = idx;
    if (0 != g_ns_sync_ops.ns_sync_sem_init(&ep->waitSem, 1, 0))
    {
        return -1;
    }

    DMM_SPINLOCK_MALLOC(ep->lock, 1);
    DMM_SPINLOCK_MALLOC(ep->sem, 1);

    EP_HLIST_INIT(&ep->rdlist);

    ep->rbr.rb_node = NULL;
    ep->epfd = -1;
    //ep->pid = 0;
    return 0;
}

NSTACK_STATIC void nsep_destroy_eventpoll(struct eventpoll *ep)
{
    (void) g_ns_sync_ops.ns_sync_sem_destroy(&ep->waitSem);
}

/**
 * @Function        nsep_free_eventpoll
 * @Description     free nstack eventpoll
 * @param in        ep - the eventpoll to be free
 * @return          0 on success, -1 on error
 */
int nsep_free_eventpoll(struct eventpoll *ep)
{

    if (!ep)
        return -1;
    struct eventpoll *epEntry = (struct eventpoll *) ep;
    struct eventpoll_pool *pool = &nsep_get_manager()->epollPool;
    NSSOC_LOGDBG("nsep_free_eventpoll ep:%p, epollPool:%p", ep, pool);
    nsep_destroy_eventpoll(ep);
    ep->pid = 0;
    NSSOC_LOGDBG("Free eventpool");
    if (res_free(&ep->res_chk))
    {
        NSFW_LOGERR("ep refree!]epitem=%p", epEntry);
        return -1;              // 3th round code security review fix
    }

    if (nsfw_mem_ring_enqueue(pool->ring, epEntry) != 1)
    {
        NSSOC_LOGERR("Errot to free eventpoll");
        return -1;              // 3th round code security review fix
    }

    return 0;
}

/**
 * @Function        nsep_alloc_eventpoll
 * @Description     alloc nstack eventpoll
 * @param out       data - the eventpoll alloced
 * @return          0 on success, -1 on error
 */
int nsep_alloc_eventpoll(struct eventpoll **data)
{
    struct eventpoll *p_head = NULL;
    struct eventpoll_pool *pool = &nsep_get_manager()->epollPool;
    int idx;

    NSSOC_LOGDBG("ring:%p alloc eventpool begin", pool->ring);
    if (0 == nsfw_mem_ring_dequeue(pool->ring, (void *) &p_head)
        || NULL == p_head)
    {
        NSSOC_LOGERR("ring alloc eventpool failed]ring=%p", pool->ring);
        return -1;
    }

    NSSOC_LOGDBG("alloc eventpool, pid=%d", get_sys_pid());
    res_alloc(&p_head->res_chk);
    p_head->pid = get_sys_pid();

    idx =
        ((unsigned long) p_head -
         (unsigned long) (pool->pool)) / sizeof(struct eventpoll);
    if (0 != nsep_init_eventpoll((struct eventpoll *) p_head, idx))
    {
        NSSOC_LOGERR("p_head init pid alloc failed]p_head=%p,pid=%d", p_head,
                     get_sys_pid());
        (void) nsep_free_eventpoll((struct eventpoll *) p_head);
        return -1;
    }

    NSSOC_LOGDBG("ring:%p eventpoll:%p alloc eventpool end", pool->ring,
                 p_head);
    *data = p_head;

    return 0;
}

NSTACK_STATIC int nsep_init_epitem(struct epitem *epi)
{
    int retVal;
    epi->rbn.rb_parent =
        (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(&epi->rbn);
    EP_HLIST_INIT_NODE(&epi->rdllink);

    epi->ptr_reserve = NULL;
    epi->ep_spl = NULL;
    epi->ep = NULL;
    epi->app_poll_count = 0;
    epi->spl_enter_count = 0;
    epi->reserve = 0;

    //epi->pid = 0;
    /* There are some unsafe function ,need to be replace with safe function */
    retVal = memset_s(&epi->event, sizeof(epi->event), 0, sizeof(epi->event));
    if (EOK != retVal)
    {
        NSSOC_LOGERR("memset_s failed]ret=%d", retVal);
        return -1;
    }

    EP_LIST_INIT_NODE(&epi->fllink);
    EP_HLIST_INIT_NODE(&epi->txlink);
    epi->revents = 0;
    epi->fd = -1;
    epi->private_data = NULL;

    return 0;
}

/**
 * @Function        nsep_alloc_epitem
 * @Description     alloc nstack epitem
 * @param out       data - the epitem alloced
 * @return          0 on success, -1 on error
 */
int nsep_alloc_epitem(struct epitem **data)
{
    struct epitem *p_head_entry = NULL;
    struct epitem_pool *pool = &nsep_get_manager()->epitemPool;

    NSSOC_LOGDBG("epitem alloc begin..");

    if (0 == nsfw_mem_ring_dequeue(pool->ring, (void *) &p_head_entry)
        || NULL == p_head_entry)
    {
        NSSOC_LOGERR("epitem ring alloc failed]ring=%p", pool->ring);
        return -1;
    }

    res_alloc(&p_head_entry->res_chk);
    p_head_entry->pid = get_sys_pid();

    if (nsep_init_epitem((struct epitem *) p_head_entry))
    {
        (void) nsep_free_epitem((struct epitem *) p_head_entry);
        p_head_entry = NULL;
        NSSOC_LOGERR("ring epitem init failed]ring=%p,epitem=%p", pool->ring,
                     p_head_entry);
        return -1;
    }

    NSSOC_LOGDBG("epitem alloc success..ring:%p head:%p", pool->ring,
                 p_head_entry);
    *data = p_head_entry;
    return 0;
}

typedef int (*nsep_shem_initFn_t) (void *, size_t);

/*****************************************************************************
*   Prototype    : sbr_create_mzone
*   Description  : create mzone
*   Input        : const char* name
*                  size_t size
*   Output       : None
*   Return Value : mzone_handle
*   Calls        :
*   Called By    :
*****************************************************************************/
mzone_handle nsep_create_mzone(const char *name, size_t size)
{
    if (!name)
    {
        NSFW_LOGERR("name is NULL");
        return NULL;
    }

    mzone_handle zone;
    nsfw_mem_zone param;

    param.isocket_id = -1;
    param.lenth = size;
    param.stname.entype = NSFW_SHMEM;

    if (strcpy_s(param.stname.aname, NSFW_MEM_NAME_LENTH, name) != 0)
    {
        NSFW_LOGERR("strcpy_s failed]name=%s", name);
        return NULL;
    }

    zone = nsfw_mem_zone_create(&param);
    if (!zone)
    {
        NSFW_LOGERR("nsfw_mem_zone_create failed]name=%s, size:%zu", name,
                    size);
        return NULL;
    }

    return zone;
}

/*****************************************************************************
*   Prototype    : sbr_create_multi_ring
*   Description  : create multi ring
*   Input        : const char* name
*                  u32 ring_size
*                  i32 ring_num
*                  mring_handle* array
*                  nsfw_mpool_type type
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int nsep_create_multi_ring(const char *name, u32 ring_size, i32 ring_num,
                           mring_handle * array, nsfw_mpool_type type)
{
    if (!name)
    {
        NSFW_LOGERR("name is NULL");
        return -1;
    }

    if (!array)
    {
        NSFW_LOGERR("array is NULL");
        return -1;
    }

    nsfw_mem_mring param;

    if (EOK != memset_s(&param, sizeof(param), 0, sizeof(param)))
    {
        NSSBR_LOGERR("Error to memset]name=%s", name);
        return -1;
    }

    param.enmptype = type;
    param.stname.entype = NSFW_SHMEM;
    if (strcpy_s(param.stname.aname, NSFW_MEM_NAME_LENTH, name) != 0)
    {
        NSSBR_LOGERR("strcpy_s failed]name=%s", name);
        return -1;
    }

    param.usnum = ring_size - 1;
    param.isocket_id = -1;
    if (nsfw_mem_sp_ring_create(&param, array, ring_num) != 0)
    {
        NSSBR_LOGERR
            ("Create ring pool failed]name=%s, ring_num=%d, ring_size=%u",
             name, ring_num, ring_size);
        return -1;
    }

    return 0;
}

NSTACK_STATIC int nsep_ep_conn_pool_create(void)
{
    u32_t pos;
    int ret;

    nsep_epollManager_t *manager = nsep_get_manager();

    struct spl_conn_pool *conn_pool_array =
        (struct spl_conn_pool *)
        nsep_create_mzone(MP_NSTACK_SPL_CONN_ARRAY_NAME,
                          (size_t) sizeof(struct spl_conn_pool) *
                          NSTACK_MAX_EPOLL_FD_NUM);

    if (!conn_pool_array)
    {
        NSSBR_LOGERR
            ("Create tx_msg_array zone fail]name=%s, num=%u, size=%lu",
             MP_NSTACK_SPL_CONN_ARRAY_NAME, NSTACK_MAX_EPOLL_FD_NUM,
             (size_t) sizeof(struct spl_conn_pool) * NSTACK_MAX_EPOLL_FD_NUM);
        return -1;
    }

    MEM_STAT(MP_NSTACK_SPL_CONN_POOL, MP_NSTACK_SPL_CONN_ARRAY_NAME,
             NSFW_SHMEM,
             (size_t) sizeof(struct spl_conn_pool) * NSTACK_MAX_EPOLL_FD_NUM);
    NSSBR_LOGINF
        ("Create tx_msg_array zone ok]name=%s, ptr=%p, num=%u, size=%lu",
         MP_NSTACK_SPL_CONN_ARRAY_NAME, conn_pool_array,
         NSTACK_MAX_EPOLL_FD_NUM,
         sizeof(struct spl_conn_pool) * NSTACK_MAX_EPOLL_FD_NUM);

    mring_handle *array =
        (mring_handle *) malloc(NSTACK_MAX_EPOLL_FD_NUM *
                                sizeof(mring_handle));
    if (NULL == array)
    {
        NSSOC_LOGERR("malloc failed");
        return -1;
    }

    ret =
        memset_s(array, NSTACK_MAX_EPOLL_FD_NUM * sizeof(mring_handle), 0,
                 NSTACK_MAX_EPOLL_FD_NUM * sizeof(mring_handle));
    if (EOK != ret)
    {
        NSSOC_LOGERR("memset_s failed]ret=%d", ret);
        free(array);
        return -1;
    }
    if (nsep_create_multi_ring
        (MP_NSTACK_SPL_CONN_POOL, NSTACK_MAX_EPOLL_INFO_NUM - 1,
         NSTACK_MAX_EPOLL_FD_NUM - 1, (mring_handle *) array,
         NSFW_MRING_MPMC) != 0)
    {
        free(array);
        return -1;
    }

    for (pos = 0; pos < NSTACK_MAX_EPOLL_FD_NUM - 1; pos++)
    {
        conn_pool_array[pos].pid = 0;
        conn_pool_array[pos].revents = 0;
        conn_pool_array[pos].res_chk.alloc_flag = 0;
        conn_pool_array[pos].res_chk.chk_count = 0;
        conn_pool_array[pos].res_chk.data = 0;
        conn_pool_array[pos].res_chk.u8Reserve = 0;
        conn_pool_array[pos].ring_hd = array[pos];
        if (-1 ==
            nsfw_mem_ring_enqueue(manager->ep_connPoll.ring,
                                  &conn_pool_array[pos]))
        {
            free(array);
            NSSOC_LOGERR("init fail to enqueue epitem]pos=%u", pos);
            return -1;
        }
    }
    manager->ep_connPoll.pool = &conn_pool_array[0];
    free(array);

    return 0;
}

NSTACK_STATIC int nsep_ep_pool_init(void *addr, size_t lenth)
{
    u32_t pos;
    int ret;

    NSSOC_LOGDBG("Start to init eventpoll pool");

    /* add return value check */
    ret = memset_s(addr, lenth, 0, lenth);
    if (EOK != ret)
    {
        NSSOC_LOGERR("memset_s failed]ret=%d", ret);
        return -1;
    }
    struct eventpoll *pool = (struct eventpoll *) addr;
    nsep_epollManager_t *manager = nsep_get_manager();
    manager->epollPool.pool = pool;

    /* init g_nStackInfo.sockPool->nstack_block_array */
    for (pos = 0; pos < NSTACK_MAX_EPOLL_FD_NUM; pos++)
    {
        pool[pos].pid = 0;
        if (-1 == nsfw_mem_ring_enqueue(manager->epollPool.ring, &pool[pos]))
        {
            NSSOC_LOGERR("init fail to enqueue epitem]pos=%u", pos);
            return -1;
        }
    }

    ret = nsep_ep_conn_pool_create();

    if (0 != ret)
    {
        NSSOC_LOGERR("nsep_ep_conn_pool_create failed]ret=%d", ret);
        return -1;
    }

    return 0;
}

NSTACK_STATIC int nsep_epitem_pool_init(void *addr, size_t lenth)
{
    u32_t pos;
    int ret;

    NSSOC_LOGDBG("Start to init epitem pool");

    /* add return value check */
    ret = memset_s(addr, lenth, 0, lenth);
    if (EOK != ret)
    {
        NSSOC_LOGERR("memset_s failed]ret=%d", ret);
        return -1;
    }
    struct epitem *pool = (struct epitem *) addr;
    nsep_epollManager_t *manager = nsep_get_manager();
    manager->epitemPool.pool = pool;

    /* init g_nStackInfo.sockPool->nstack_block_array */
    for (pos = 0; pos < NSTACK_MAX_EPITEM_NUM; pos++)
    {
        pool[pos].pid = 0;
        pool[pos].ep_spl = NULL;
        pool[pos].ptr_reserve = NULL;
        if (-1 == nsfw_mem_ring_enqueue(manager->epitemPool.ring, &pool[pos]))
        {
            NSSOC_LOGERR("init fail to enqueue epitem]pos=%u", pos);
            return -1;
        }
    }
    return 0;
}

NSTACK_STATIC int nsep_epinfo_pool_init(void *addr, size_t lenth)
{
    u32_t pos;
    int ret;

    NSSOC_LOGDBG("shmem info init start");

    /* add return value check */
    ret = memset_s(addr, lenth, 0, lenth);
    if (EOK != ret)
    {
        NSSOC_LOGERR("memset_s failed]ret=%d", ret);
        return -1;
    }
    nsep_epollInfo_t *pool = (nsep_epollInfo_t *) addr;
    nsep_epollManager_t *manager = nsep_get_manager();
    manager->infoPool.pool = pool;

    /* init g_nStackInfo.sockPool->nstack_block_array */
    for (pos = 0; pos < NSTACK_MAX_EPOLL_INFO_NUM; pos++)
    {
        if (nsep_for_pidinfo_init(&(pool[pos].pidinfo)))
        {
            NSSOC_LOGERR("pid info init failed]pos=%u", pos);
            return -1;
        }

        if (-1 == nsfw_mem_ring_enqueue(manager->infoPool.ring, &pool[pos]))
        {
            NSSOC_LOGERR("init fail to enqueue epInfo]pos=%u", pos);
            return -1;
        }
    }

    NSSOC_LOGDBG("nstack_shmen_info_init success");
    return 0;
}

NSTACK_STATIC
    int nsep_create_shmem(size_t length, char *name,
                          nsep_shem_initFn_t initFn)
{
    nsfw_mem_zone pmeminfo;
    mzone_handle phandle;
    int ret;

    pmeminfo.ireserv = 0;
    pmeminfo.isocket_id = NSFW_SOCKET_ANY;
    pmeminfo.lenth = length;
    ret =
        strcpy_s(pmeminfo.stname.aname, sizeof(pmeminfo.stname.aname), name);
    if (EOK != ret)
    {
        NSSOC_LOGERR("strcpy_s failed]name=%s,ret=%d", name, ret);
        return -1;
    }
    pmeminfo.stname.entype = NSFW_SHMEM;

    phandle = nsfw_mem_zone_create(&pmeminfo);
    if (NULL == phandle)
    {
        NSSOC_LOGERR("create nstack epoll memory failed]name=%s", name);
        return -1;
    }

    if (0 != initFn((void *) phandle, length))
    {
        NSSOC_LOGERR("Fail to init memory]name=%s", name);
        (void) nsfw_mem_zone_release(&pmeminfo.stname); //3th round code security review fix
        return -1;
    }

    return 0;
}

NSTACK_STATIC int nsep_create_epinfo_mem()
{
    nsfw_mem_mring pringinfo;
    pringinfo.enmptype = NSFW_MRING_MPMC;
    pringinfo.isocket_id = NSFW_SOCKET_ANY;
    pringinfo.stname.entype = NSFW_SHMEM;
    pringinfo.usnum = NSTACK_MAX_EPOLL_INFO_NUM - 1;

    if (-1 ==
        sprintf_s(pringinfo.stname.aname, NSFW_MEM_NAME_LENTH, "%s",
                  MP_NSTACK_EPINFO_RING_NAME))
    {
        NSSOC_LOGERR("Error to create ring]name=%s", pringinfo.stname.aname);
        return -1;
    }

    mring_handle ring_handle = nsfw_mem_ring_create(&pringinfo);

    if (NULL == ring_handle)
    {
        NSSOC_LOGERR("Error to create ring]name=%s", pringinfo.stname.aname);
        return -1;
    }

    nsep_epollManager_t *manager = nsep_get_manager();
    manager->infoPool.ring = ring_handle;

    return nsep_create_shmem(sizeof(nsep_epollInfo_t) *
                             NSTACK_MAX_EPOLL_INFO_NUM,
                             MP_NSTACK_EPOLL_INFO_NAME,
                             nsep_epinfo_pool_init);
}

NSTACK_STATIC int nsep_adpt_attach_epinfo_mem()
{
    nsfw_mem_name name;
    name.entype = NSFW_SHMEM;
    name.enowner = NSFW_PROC_MAIN;

    if (-1 ==
        sprintf_s(name.aname, NSFW_MEM_NAME_LENTH, "%s",
                  MP_NSTACK_EPINFO_RING_NAME))
    {
        NSSOC_LOGERR("Error to attach ring]name=%s", name.aname);
        return -1;
    }
    mring_handle ring_handle = nsfw_mem_ring_lookup(&name);

    if (NULL == ring_handle)
    {
        NSSOC_LOGERR("Error to attach ring]name=%s", name.aname);
        return -1;
    }

    nsep_epollManager_t *manager = nsep_get_manager();
    manager->infoPool.ring = ring_handle;

    if (-1 ==
        sprintf_s(name.aname, NSFW_MEM_NAME_LENTH, "%s",
                  MP_NSTACK_EPOLL_INFO_NAME))
    {
        NSSOC_LOGERR("sprintf_s failed]");
        return -1;
    }
    manager->infoPool.pool = nsfw_mem_zone_lookup(&name);
    if (NULL == manager->infoPool.pool)
    {
        NSSOC_LOGERR("Error to attach memzone]name=%s",
                     MP_NSTACK_EPOLL_INFO_NAME);
        return -1;
    }
    return 0;
}

NSTACK_STATIC int nsep_create_epitem_mem()
{
    nsfw_mem_mring pringinfo;
    pringinfo.enmptype = NSFW_MRING_MPMC;
    pringinfo.isocket_id = NSFW_SOCKET_ANY;
    pringinfo.stname.entype = NSFW_SHMEM;
    pringinfo.usnum = NSTACK_MAX_EPITEM_NUM - 1;

    if (-1 ==
        sprintf_s(pringinfo.stname.aname, NSFW_MEM_NAME_LENTH, "%s",
                  MP_NSTACK_EPITEM_RING_NAME))
    {
        NSSOC_LOGERR("Error to create ring]name=%s", pringinfo.stname.aname);
        return -1;
    }

    mring_handle ring_handle = nsfw_mem_ring_create(&pringinfo);

    if (NULL == ring_handle)
    {
        NSSOC_LOGERR("Error to create ring]name=%s", pringinfo.stname.aname);
        return -1;
    }

    nsep_epollManager_t *manager = nsep_get_manager();
    manager->epitemPool.ring = ring_handle;

    return nsep_create_shmem(sizeof(struct epitem) * NSTACK_MAX_EPITEM_NUM,
                             MP_NSTACK_EPITEM_POOL, nsep_epitem_pool_init);

}

NSTACK_STATIC int nsep_adpt_attach_epitem_mem()
{
    nsfw_mem_name name;
    name.entype = NSFW_SHMEM;
    name.enowner = NSFW_PROC_MAIN;

    if (-1 ==
        sprintf_s(name.aname, NSFW_MEM_NAME_LENTH, "%s",
                  MP_NSTACK_EPITEM_RING_NAME))
    {
        NSSOC_LOGERR("Error to attach epItemMem]name=%s", name.aname);
        return -1;
    }

    mring_handle ring_handle = nsfw_mem_ring_lookup(&name);

    if (NULL == ring_handle)
    {
        NSSOC_LOGERR("Error to attach ring]name=%s", name.aname);
        return -1;
    }

    nsep_epollManager_t *manager = nsep_get_manager();
    manager->epitemPool.ring = ring_handle;

    if (-1 ==
        sprintf_s(name.aname, NSFW_MEM_NAME_LENTH, "%s",
                  MP_NSTACK_EPITEM_POOL))
    {
        NSSOC_LOGERR("sprintf_s failed]");
        return -1;
    }

    manager->epitemPool.pool = nsfw_mem_zone_lookup(&name);
    if (NULL == manager->epitemPool.pool)
    {
        NSSOC_LOGERR("Error to attach memzone]name=%s",
                     MP_NSTACK_EPITEM_POOL);
        return -1;
    }
    return 0;
}

NSTACK_STATIC int nsep_create_eventpoll_mem()
{
    nsfw_mem_mring pringinfo;
    pringinfo.enmptype = NSFW_MRING_MPMC;
    pringinfo.isocket_id = NSFW_SOCKET_ANY;
    pringinfo.stname.entype = NSFW_SHMEM;
    pringinfo.usnum = NSTACK_MAX_EPOLL_FD_NUM - 1;

    if (-1 ==
        sprintf_s(pringinfo.stname.aname, NSFW_MEM_NAME_LENTH, "%s",
                  MP_NSTACK_EVENTPOOL_RING_NAME))
    {
        NSSOC_LOGERR("Error to create ring]name=%s", pringinfo.stname.aname);
        return -1;
    }

    mring_handle ring_handle = nsfw_mem_ring_create(&pringinfo);

    if (NULL == ring_handle)
    {
        NSSOC_LOGERR("Error to create ring]name=%s", pringinfo.stname.aname);
        return -1;
    }

    nsep_epollManager_t *manager = nsep_get_manager();
    manager->epollPool.ring = ring_handle;

    pringinfo.usnum = NSTACK_MAX_EPOLL_FD_NUM - 1;
    if (-1 ==
        sprintf_s(pringinfo.stname.aname, NSFW_MEM_NAME_LENTH, "%s",
                  MP_NSTACK_SPL_CONN_RING_NAME))
    {
        NSSOC_LOGERR("Error to create ring]name=%s", pringinfo.stname.aname);
        return -1;
    }

    ring_handle = nsfw_mem_ring_create(&pringinfo);

    if (NULL == ring_handle)
    {
        NSSOC_LOGERR("Error to create ring]name=%s", pringinfo.stname.aname);
        return -1;
    }

    manager->ep_connPoll.ring = ring_handle;

    return nsep_create_shmem(sizeof(struct eventpoll) *
                             NSTACK_MAX_EPOLL_FD_NUM,
                             MP_NSTACK_EVENTPOLL_POOL, nsep_ep_pool_init);
}

NSTACK_STATIC int nsep_adpt_attach_eventpoll_mem()
{
    nsfw_mem_name name;
    u32 tmp_count = 0;
    name.entype = NSFW_SHMEM;
    name.enowner = NSFW_PROC_MAIN;

    if (-1 ==
        sprintf_s(name.aname, NSFW_MEM_NAME_LENTH, "%s",
                  MP_NSTACK_EVENTPOOL_RING_NAME))
    {
        NSSOC_LOGERR("Error to attach ring]name=%s", name.aname);
        return -1;
    }

    mring_handle ring_handle = nsfw_mem_ring_lookup(&name);

    if (NULL == ring_handle)
    {
        NSSOC_LOGERR("Error to create ring]name=%s", name.aname);
        return -1;
    }

    nsep_epollManager_t *manager = nsep_get_manager();
    manager->epollPool.ring = ring_handle;

    int retVal = sprintf_s(name.aname, NSFW_MEM_NAME_LENTH, "%s",
                           MP_NSTACK_EVENTPOLL_POOL);
    if (-1 == retVal)
    {
        NSSOC_LOGERR("sprintf_s faild]ret=%d", retVal);
        return -1;
    }
    manager->epollPool.pool = nsfw_mem_zone_lookup(&name);
    if (NULL == manager->epollPool.pool)
    {
        NSSOC_LOGERR("Error to attach memzone]name=%s",
                     MP_NSTACK_EVENTPOLL_POOL);
        return -1;
    }

    retVal =
        sprintf_s(name.aname, NSFW_MEM_NAME_LENTH, "%s",
                  MP_NSTACK_SPL_CONN_RING_NAME);
    if (-1 == retVal)
    {
        NSSOC_LOGERR("sprintf_s faild]ret=%d", retVal);
        return -1;
    }

    manager->ep_connPoll.ring = nsfw_mem_zone_lookup(&name);
    if (NULL == manager->ep_connPoll.ring)
    {

        nsfw_mem_mring pringinfo;
        pringinfo.enmptype = NSFW_MRING_MPMC;
        pringinfo.isocket_id = NSFW_SOCKET_ANY;
        pringinfo.stname.entype = NSFW_SHMEM;
        pringinfo.usnum = NSTACK_MAX_EPOLL_FD_NUM;
        if (-1 ==
            sprintf_s(pringinfo.stname.aname, NSFW_MEM_NAME_LENTH, "%s",
                      MP_NSTACK_SPL_CONN_RING_NAME))
        {
            NSSOC_LOGERR("Error to create ring]name=%s",
                         pringinfo.stname.aname);
            return -1;
        }

        ring_handle = nsfw_mem_ring_create(&pringinfo);

        if (NULL == ring_handle)
        {
            NSSOC_LOGERR("Error to create ring]name=%s",
                         pringinfo.stname.aname);
            return -1;
        }

        manager->ep_connPoll.ring = ring_handle;

    }

    retVal =
        sprintf_s(name.aname, NSFW_MEM_NAME_LENTH, "%s",
                  MP_NSTACK_SPL_CONN_ARRAY_NAME);
    if (-1 == retVal)
    {
        NSSOC_LOGERR("sprintf_s faild]ret=%d", retVal);
        return -1;
    }

    manager->ep_connPoll.pool = nsfw_mem_zone_lookup(&name);
    if (NULL == manager->ep_connPoll.pool)
    {
        retVal = nsep_ep_conn_pool_create();
        if (0 != retVal)
        {
            NSSOC_LOGERR("nsep_ep_conn_pool_create failed]ret=%d", retVal);
            return -1;
        }
    }
    else
    {
        /* epoll global lock in daemon-stack cause daemon-stack message handle slowing */
        nsep_recycle_upgrade_resource();
        tmp_count = nsfw_mem_ring_using_count(manager->ep_connPoll.ring);
        NSSOC_LOGINF("ep_connPoll.ring]ring=%p,free_num=%u",
                     manager->ep_connPoll.ring, tmp_count);
    }

    return 0;
}

int nsep_create_memory()
{
    typedef int (*nsep_createMemFunc_t) (void);
    nsep_createMemFunc_t createFuncs[] = { nsep_create_epinfo_mem,
        nsep_create_epitem_mem,
        nsep_create_eventpoll_mem
    };

    int i = 0;
    for (i = 0;
         i < (int) (sizeof(createFuncs) / sizeof(nsep_createMemFunc_t)); i++)
    {
        if (-1 == createFuncs[i] ())
            return -1;
    }

    return 0;
}

int nsep_adpt_attach_memory()
{
    typedef int (*nsep_attachMemFunc_t) (void);
    nsep_attachMemFunc_t attachFuncs[] = { nsep_adpt_attach_epinfo_mem,
        nsep_adpt_attach_epitem_mem,
        nsep_adpt_attach_eventpoll_mem
    };

    int i = 0;
    for (i = 0;
         i < (int) (sizeof(attachFuncs) / sizeof(nsep_attachMemFunc_t)); i++)
    {
        if (-1 == attachFuncs[i] ())
        {
            NSSOC_LOGERR("mem attach fail]idx=%d", i);
            return -1;
        }
    }

    return 0;
}

int nsep_adpt_reg_res_mgr()
{
    nsep_epollManager_t *manager = nsep_get_manager();

    nsfw_res_scn_cfg scn_cfg_info = { NSFW_RES_SCAN_ARRAY, 90, 3, 16,
        NSTACK_MAX_EPOLL_INFO_NUM / 128, NSTACK_MAX_EPOLL_INFO_NUM,
        sizeof(nsep_epollInfo_t),

        offsetof(nsep_epollInfo_t, res_chk),

        manager->infoPool.pool,
        manager->infoPool.ring,
        nsep_force_epinfo_free
    };

    nsfw_res_scn_cfg scn_cfg_item = { NSFW_RES_SCAN_ARRAY, 90, 3, 16,
        NSTACK_MAX_EPITEM_NUM / 128, NSTACK_MAX_EPITEM_NUM,
        sizeof(struct epitem),

        offsetof(struct epitem, res_chk),

        manager->epitemPool.pool,
        manager->epitemPool.ring,
        nsep_force_epitem_free
    };

    nsfw_res_scn_cfg scn_cfg_event = { NSFW_RES_SCAN_ARRAY, 90, 3, 16,
        NSTACK_MAX_EPOLL_FD_NUM / 16, NSTACK_MAX_EPOLL_FD_NUM,
        sizeof(struct eventpoll),

        offsetof(struct eventpoll, res_chk),

        manager->epollPool.pool,
        manager->epollPool.ring,
        nsep_force_epevent_free
    };

    /* solve epoll_wait hangup issue, because force free invalid ep_conn */
    nsfw_res_scn_cfg scn_cfg_spl_conn = { NSFW_RES_SCAN_ARRAY, 90, 3, 16,
        NSTACK_MAX_EPOLL_FD_NUM / 16, NSTACK_MAX_EPOLL_FD_NUM,
        sizeof(struct spl_conn_pool),

        offsetof(struct spl_conn_pool, res_chk),

        manager->ep_connPoll.pool,
        manager->ep_connPoll.ring,
        nsep_force_ep_spl_conn_free
    };

    (void) nsfw_res_mgr_reg(&scn_cfg_info);
    (void) nsfw_res_mgr_reg(&scn_cfg_item);
    (void) nsfw_res_mgr_reg(&scn_cfg_event);
    (void) nsfw_res_mgr_reg(&scn_cfg_spl_conn);
    return 0;
}

int nsep_epitem_remove(nsep_epollInfo_t * pinfo, u32 pid)
{
    struct list_node *prenode = NULL;
    struct list_node *nextnode = NULL;
    struct epitem *epi = NULL;
    u32_t i = 0;
    int icnt = 0;

    (void) dmm_spin_lock_with_pid(&pinfo->epiLock);
    /*list head must be not null */
    prenode = (struct list_node *) SHMEM_ADDR_SHTOL(pinfo->epiList.head);
    nextnode = (struct list_node *) SHMEM_ADDR_SHTOL(prenode->next);
    /* Change "<=" to "<" */
    while ((nextnode) && (i++ < NSTACK_MAX_EPOLL_INFO_NUM))
    {

        epi = ep_list_entry(nextnode, struct epitem, fllink);
        if (pid == epi->pid)
        {
            /*shmem equal to shmem */
            prenode->next = nextnode->next;
            nextnode->next = NULL;
            /* after close fd in epfd, epfd still can epoll_wait EPOLLIN event for these fd */
            (void) nstack_epoll_event_dequeue(epi, 0);
            (void) nsep_free_epitem(epi);
            nextnode = SHMEM_ADDR_SHTOL(prenode->next);
            icnt++;
            continue;
        }
        prenode = nextnode;
        nextnode = SHMEM_ADDR_SHTOL(nextnode->next);
    }
    dmm_spin_unlock(&pinfo->epiLock);
    if (i >= NSTACK_MAX_EPOLL_INFO_NUM)
    {
        NSSOC_LOGERR("free pinfo:%p pid:%u, error maybe happen", pinfo, pid);
    }
    /* needn't call:nsep_epctl_triggle(NULL, epInfo, nstack_ep_triggle_inform), because here is called by daemon-stack */
    return icnt;
}

void nsep_recycle_epfd(void *epinfo, u32 pid)
{
    struct eventpoll *ep = NULL;
    struct spl_conn_pool *ep_conn = NULL;
    nsep_epollInfo_t *info = (nsep_epollInfo_t *) SHMEM_ADDR_SHTOL(epinfo);
    int ret = 0;
    int ileftcnt = 0;
    if (!epinfo)
    {
        NSSOC_LOGDBG("input null, pid:%u", pid);
        return;
    }
    (void) dmm_spin_lock_with_pid(&info->freeLock);
    ileftcnt = nsep_del_last_pid(&info->pidinfo, pid);
    dmm_spin_unlock(&info->freeLock);
    /*no pid exist */
    if (-1 == ileftcnt)
    {
        return;
    }
    if (NSTACK_EPOL_FD == info->fdtype)
    {
        NSSOC_LOGDBG("recycle epfd:%d epinfo pid:%u begin...", info->fd, pid);
        if (0 == ileftcnt)
        {
            ep = SHMEM_ADDR_SHTOL(info->ep);
            ep_conn = SHMEM_ADDR_SHTOL(info->ep_conn);
            info->ep = NULL;
            (void) nsep_free_eventpoll(ep);
            (void) nsep_free_ep_spl_conn_ring(ep_conn);
            info->ep_conn = NULL;
            (void) nsep_free_epinfo(info);
        }
        return;
    }

    NSSOC_LOGDBG("recycle fd:%d epinfo pid:%u begin...", info->fd, pid);

    ret = nsep_epitem_remove(info, pid);
    if (0 != ret)
    {
        NSSOC_LOGDBG("info:%p, fd:%d pid:%u, %d items was left", info,
                     info->fd, pid, ret);
    }

    if (0 == ileftcnt)
    {
        NSSOC_LOGDBG("info:%p, fd:%d pid:%u was finally freed", info,
                     info->fd, pid);
        (void) nsep_free_epinfo(info);
    }
    return;
}

int nsep_recyle_ep(u32 pid)
{
    nsep_epollManager_t *manager = nsep_get_manager();
    nsep_epollInfo_t *pool = manager->infoPool.pool;

    u32_t pos;
    for (pos = 0; pos < NSTACK_MAX_EPOLL_INFO_NUM; pos++)
    {
        (void) nsep_recycle_epfd(&pool[pos], pid);
    }
    return 0;
}

NSTACK_STATIC int nsep_recyle_epitem(u32 pid)
{
    nsep_epollManager_t *manager = nsep_get_manager();
    struct epitem *pool = manager->epitemPool.pool;

    u32_t pos;
    for (pos = 0; pos < NSTACK_MAX_EPITEM_NUM; pos++)
    {
        if (pool[pos].pid != pid)
            continue;

        if (-1 == nsep_free_epitem(&pool[pos]))
            return -1;
    }

    return 0;
}

NSTACK_STATIC int nsep_recyle_eventpoll(u32 pid)
{
    nsep_epollManager_t *manager = nsep_get_manager();
    struct eventpoll *pool = manager->epollPool.pool;

    u32_t pos;
    for (pos = 0; pos < NSTACK_MAX_EPOLL_INFO_NUM; pos++)
    {
        if (pool[pos].pid != pid)
            continue;

        if (-1 == nsep_free_eventpoll(&pool[pos]))
            return -1;
    }

    return 0;
}

NSTACK_STATIC int nsep_recyle_spl_conn_pool(u32 pid)
{
    nsep_epollManager_t *manager = nsep_get_manager();
    struct spl_conn_pool *pool = manager->ep_connPoll.pool;

    u32_t pos;
    for (pos = 0; pos < NSTACK_MAX_EPOLL_FD_NUM - 1; pos++)
    {
        if (pool[pos].pid != pid)
            continue;

        if (-1 == nsep_free_ep_spl_conn_ring(&pool[pos]))
        {
            return -1;
        }
    }

    return 0;
}

nsfw_rcc_stat nsep_recycle_resource(u32 exit_pid, void *pdata, u16 rec_type)
{
    NSSOC_LOGINF("pid:%u recycle", exit_pid);
    //nsep_recyle_epInfo(exit_pid);
    (void) nsep_recyle_epitem(exit_pid);
    (void) nsep_recyle_eventpoll(exit_pid);
    (void) nsep_recyle_spl_conn_pool(exit_pid);
    return NSFW_RCC_CONTINUE;
}

NSTACK_STATIC
    nsfw_rcc_stat nsep_recyle_lock(u32 pid, void *pdata, u16 rec_type)
{
    nsep_epollManager_t *manager = nsep_get_manager();
    nsep_epollInfo_t *pool = manager->infoPool.pool;
    u32_t pos;
    if (NULL != pool)
    {
        for (pos = 0; pos < NSTACK_MAX_EPOLL_INFO_NUM; pos++)
        {
            if (pid == pool[pos].epiLock.lock)
            {
                pool[pos].epiLock.lock = 0;
                NSFW_LOGWAR("epiLock locked]pos=%u,pid=%u", pos, pid);
            }
            if (pid == pool[pos].freeLock.lock)
            {
                pool[pos].freeLock.lock = 0;
                NSFW_LOGWAR("freelock locked]pos=%u,pid=%u", pos, pid);
            }
        }
    }

    struct eventpoll *ev_pool = manager->epollPool.pool;
    if (NULL != ev_pool)
    {
        for (pos = 0; pos < NSTACK_MAX_EPOLL_FD_NUM; pos++)
        {
            if (pid == ev_pool[pos].lock.lock)
            {
                ev_pool[pos].lock.lock = 0;
                NSFW_LOGWAR("event_pollLock locked]pos=%u,pid=%u", pos, pid);
            }

            if (pid == ev_pool[pos].sem.lock)
            {
                ev_pool[pos].sem.lock = 0;
                NSFW_LOGWAR("event_pollLock sem]pos=%u,pid=%u", pos, pid);
            }
        }
    }

    return NSFW_RCC_CONTINUE;
}

int nstack_adpt_init(int flag)
{
    int ret;
    if (0 == flag)
    {
        if (nstack_init_share_res() != 0)
        {
            return -1;
        }

        ret = nsep_create_memory();
    }
    else
    {
        if (nstack_attach_share_res() != 0)
        {
            return -1;
        }

        /**
        * the share memory for epoll is created and usedy be app, don't clear
        * it in fault case.
        */
        ret = nsep_adpt_attach_memory();
    }

    if (ret)
    {
        return ret;
    }
    void *pret =
        nsfw_recycle_reg_obj(NSFW_REC_PRO_LOWEST, NSFW_REC_NSOCKET_EPOLL,
                             NULL);
    if (!pret)
    {
        NSFW_LOGERR("regist recycle failed");
        return -1;
    }

    (void) nsep_adpt_reg_res_mgr();     // not implemented now, no need to check return value
    return 0;
}

REGIST_RECYCLE_OBJ_FUN(NSFW_REC_NSOCKET_EPOLL, nsep_recycle_resource)
REGIST_RECYCLE_LOCK_REL(nsep_recyle_lock, NULL, NSFW_PROC_NULL)
