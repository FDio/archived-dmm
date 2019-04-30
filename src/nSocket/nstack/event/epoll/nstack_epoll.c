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
#include "nstack_log.h"
#include "nsfw_recycle_api.h"
#include "nstack_securec.h"
#include "nstack_module.h"
#include "nstack_sockops.h"
#include "nsfw_mem_api.h"
#include "nstack_fd_mng.h"
#include "nstack.h"
#include "dmm_spinlock.h"
#include "nsfw_base_linux_api.h"
#include "nstack_dmm_dfx.h"
#include "nstack_epoll_api.h"
#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C"{
/* *INDENT-ON* */
#endif /* __cplusplus */

const int EPOLL_DFX_OPS_MAP[nstack_ep_event_max] =
    { DMM_APP_EPOLL_ADD_TICK, DMM_APP_EPOLL_MOD_TICK, DMM_APP_EPOLL_DEL_TICK,
    DMM_DFX_MAX
};

static inline void *nstack_ep_triggle
    (int proFD,
     int modInx,
     int triggle_ops, struct epitem *epi, nsep_epollInfo_t * epinfo)
{
    void *data = NULL;
    int events = 0;

    if (nstack_fd_deal[modInx].ep_triggle != NULL)
    {
        data =
            nstack_fd_deal[modInx].ep_triggle(proFD, triggle_ops, epinfo,
                                              &events);
        if (data && epi)
        {
            struct stat_epfd_info tmp_epfd_info;
            struct eventpoll *ep =
                (struct eventpoll *) SHMEM_ADDR_SHTOL(epi->ep);
            switch (triggle_ops)
            {
                case nstack_ep_triggle_add:
                    if (epi->event.events & events)
                    {
                        NSTACK_EPOLL_EVENT_ADD(epinfo, events,
                                               EVENT_INFORM_APP);
                    }
                    break;
                case nstack_ep_triggle_mod:
                    if (epi->event.events & events)
                    {
                        NSTACK_EPOLL_EVENT_ADD(epinfo, events,
                                               EVENT_INFORM_APP);
                    }
                    else
                    {
                        NSTACK_EPOLL_EVENT_DEL(epi, EPOLLET);
                    }
                    break;
                default:
                    break;
            }
            tmp_epfd_info.epoll_wait_tick = ep->epoll_wait_tick;
            tmp_epfd_info.epfd = ep->epfd;
            tmp_epfd_info.epoll_fork_flag = ep->epoll_fork_flag;
            tmp_epfd_info.hhpid = get_sys_pid();
            nsep_epollInfo_t *epfd_info = nsep_get_info_by_sock(ep->epfd);
            if (NULL != epfd_info)
                tmp_epfd_info.ep_sleepTime = epfd_info->sleepTime;
            else
                tmp_epfd_info.ep_sleepTime = 0;
            nstack_dfx_state_update((u64) proFD, modInx,
                                    EPOLL_DFX_OPS_MAP[triggle_ops],
                                    &tmp_epfd_info);
        }
    }
    return data;
}

#define nstack_ep_get_evt(_epInfo, _epi) do\
{\
    if ((_epInfo)->rmidx != -1 && nstack_fd_deal[(_epInfo)->rmidx].ep_getEvt != NULL)\
    {\
        int evt_events;\
        evt_events= nstack_fd_deal[(_epInfo)->rmidx].ep_getEvt((_epInfo)->rlfd);\
        if(((_epi)->event.events & EPOLLIN) && (evt_events & EPOLLIN))\
            (_epi)->revents |=EPOLLIN;\
        if(((_epi)->event.events & EPOLLOUT) && (evt_events & EPOLLOUT))\
            (_epi)->revents |=EPOLLOUT;     \
    }\
}while(0)\

#define NSEP_IS_SOCK_VALID(_sock) ((_sock) >= 0 && (u32_t)(_sock) < NSTACK_KERNEL_FD_MAX)

/*
 *    Triggle epoll events of stack
 *    ep - eventpoll instance
 *    fdInf - file descriptor of stack
 *    triggle_ops - why triggle
 */
/*no need null pointer check*/
void nsep_epctl_triggle(struct epitem *epi, nsep_epollInfo_t * info,
                        int triggle_ops)
{
    int modInx;
    int protoFd = -1;
    void *data = NULL;

    NSSOC_LOGDBG("info=%p,info->rmidx=%d,triggle_ops=%d", info, info->rmidx,
                 triggle_ops);

    /* Now need to triggle userspace network stack events after add operation */
    if (info->rmidx >= 0)
    {
        if (info->rmidx != nstack_get_linux_mid())
        {
            /* fix overflow type */
            if ((info->rmidx >= NSEP_SMOD_MAX)
                || (info->rmidx >= NSTACK_MAX_MODULE_NUM))
            {
                return;
            }
            data =
                nstack_ep_triggle(info->rlfd, info->rmidx, triggle_ops, epi,
                                  info);
            if ((NULL != data) && (nstack_ep_triggle_add == triggle_ops))
            {
                info->private_data = (void *) SHMEM_ADDR_LTOSH(data);
                info->epaddflag[info->rmidx] = 1;
            }
            NSSOC_LOGDBG
                ("info=%p,module=%s,protoFd=%d,triggle_ops=%d, ret:%p", info,
                 nstack_get_module_name_by_idx(info->rmidx), info->rlfd,
                 triggle_ops, data);
        }
    }
    else
    {
        nstack_each_mod_inx(modInx)
        {
            if ((modInx >= NSEP_SMOD_MAX)
                || (modInx >= NSTACK_MAX_MODULE_NUM))
            {
                return;
            }
            protoFd = info->protoFD[modInx];
            if (modInx == nstack_get_linux_mid() || -1 == protoFd)
                continue;       // Don't do anything , epoll_wait will do for you

            data = nstack_ep_triggle(protoFd, modInx, triggle_ops, epi, info);
            if ((NULL != data) && (nstack_ep_triggle_add == triggle_ops))
            {
                info->private_data = (void *) SHMEM_ADDR_LTOSH(data);
                info->epaddflag[modInx] = 1;
            }
            NSSOC_LOGDBG
                ("info=%p,module=%s,protoFd=%d,triggle_ops=%d, ret:%p", info,
                 nstack_get_module_name_by_idx(modInx), protoFd, triggle_ops,
                 data);
        }
    }
}

NSTACK_STATIC
    void nsep_rbtree_insert(struct eventpoll *ep, struct epitem *epi)
{

    struct ep_rb_node **p = &ep->rbr.rb_node, *parent = NULL;   /*not null here */
    struct epitem *epic;
    u32_t loopCnt = 0;

    while (*p)
    {
        ++loopCnt;
        if (loopCnt > NSTACK_MAX_EPITEM_NUM)
        {
            NSSOC_LOGERR("Loop out of range!!!!");
            break;
        }

        parent = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(*p);

        epic = ep_rb_entry(parent, struct epitem, rbn);

        if (epi->fd > epic->fd)
        {
            p = &(parent->rb_right);
        }
        else
        {
            p = &(parent->rb_left);
        }
    }

    ep_rb_link_node(&epi->rbn, parent, p);
    ep_rb_insert_color(&epi->rbn, &ep->rbr);    /*not null here */

}

void _InOrder(struct ep_rb_node *root)
{
    struct epitem *epi = NULL;
    nsep_epollInfo_t *epInfo = NULL;
    stat_epitem_info_t epitem_info;

    if (NULL == root)
    {
        return;
    }

    _InOrder((struct ep_rb_node *) SHMEM_ADDR_SHTOL(root->rb_left));

    epi = ep_rb_entry(root, struct epitem, rbn);

    epInfo = (nsep_epollInfo_t *) SHMEM_ADDR_SHTOL(epi->private_data);
    if (NULL != epInfo)
    {
        epitem_info.event = epi->event;
        epitem_info.is_linked = EP_HLIST_NODE_LINKED(&epi->rdllink);
        nstack_dfx_state_update((u64) epInfo->rlfd, epInfo->rmidx,
                                DMM_APP_EPOLL_WAIT_FAIL, &epitem_info);
    }
    _InOrder((struct ep_rb_node *) SHMEM_ADDR_SHTOL(root->rb_right));

}

void nsep_notify_fd_epoll_wait_fail(struct eventpoll *ep)
{

    if (!ep)
        return;

    dmm_spin_lock_with_pid((dmm_spinlock_t *) (&ep->sem));      /*do not need return value */
    _InOrder((struct ep_rb_node *) SHMEM_ADDR_SHTOL(ep->rbr.rb_node));
    dmm_spin_unlock((dmm_spinlock_t *) (&ep->sem));
}

/*
 *    This function is called by epctl_add , it will create one epitem of fd, and insert to eventpoll
 */
NSTACK_STATIC
    int nsep_insert_node(struct eventpoll *ep,
                         nsep_epollInfo_t * epfd_epInfo,
                         struct epoll_event *event, nsep_epollInfo_t * epInfo)
{
    struct epitem *epi;

    if (nsep_alloc_epitem(&epi))
    {
        NSSOC_LOGERR("Can't alloc epitem");
        errno = ENOMEM;
        return -1;
    }

    EP_HLIST_INIT_NODE(&epi->rdllink);

    epi->ptr_reserve = NULL;
    epi->ep_spl = (struct spl_conn_pool *) (epfd_epInfo->ep_conn);
    epi->ep = (struct eventpoll *) SHMEM_ADDR_LTOSH_EXT(ep);
    epi->epInfo = (nsep_epollInfo_t *) SHMEM_ADDR_LTOSH_EXT(epInfo);
    epi->revents = 0;
    epi->event = *event;        /*no need null pointer check */

    EP_LIST_INIT_NODE(&epi->fllink);
    EP_HLIST_INIT_NODE(&epi->txlink);
    epi->fd = epInfo->fd;       /*no need null pointer check */

    /* Add the current item to the list of active epoll hook for this file
       This should lock because file descriptor may be called by other eventpoll */

    dmm_spin_lock_with_pid((dmm_spinlock_t *) (&epInfo->epiLock));      /*do not need return value */
    ep_list_add_tail(&epInfo->epiList, &epi->fllink);
    epi->private_data = (void *) SHMEM_ADDR_LTOSH_EXT(epInfo);
    dmm_spin_unlock((dmm_spinlock_t *) (&epInfo->epiLock));

    /* Add epitem to eventpoll fd list, don't need lock here because epoll_ctl will lock before calling this function */
    nsep_rbtree_insert(ep, epi);

    /* Need to poll the events already stored in stack */
    nsep_epctl_triggle(epi, epInfo, nstack_ep_triggle_add);

    NSSOC_LOGINF("epfd=%d,ep=%p,fd=%d,epi=%p", ep->epfd, ep, epInfo->fd, epi);

    return 0;
}

#ifdef KERNEL_FD_SUPPORT
NSTACK_STATIC int nsep_is_add_valid(int fd, struct epoll_event *events)
{
    if (-1 == nsep_get_manager()->checkEpollFD)
    {
        return -1;
    }
    if (-1 ==
        nsfw_base_epoll_ctl(nsep_get_manager()->checkEpollFD, EPOLL_CTL_ADD,
                            fd, events))
    {
        return -1;
    }

    nsfw_base_epoll_ctl(nsep_get_manager()->checkEpollFD, EPOLL_CTL_DEL, fd, NULL);     /*do not need return value */
    return 0;
}

NSTACK_STATIC
    int nsep_add_to_kernel(int epfd, int fd, const struct epoll_event *events)
{
    struct epoll_event tmpEvt;
    tmpEvt.data.fd = fd;
    tmpEvt.events = events->events;     /*no need null pointer check */
    NSSOC_LOGINF("epfd=%d,fd=%d,events=%u", epfd, fd, events->events);
    return nsfw_base_epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &tmpEvt);
}

NSTACK_STATIC
    int nsep_mod_to_kernel(int epfd, int fd, const struct epoll_event *events)
{
    struct epoll_event tmpEvt;
    tmpEvt.data.fd = fd;
    tmpEvt.events = events->events;     /*no need null pointer check */
    NSSOC_LOGINF("epfd=%d,fd=%d,events=%u", epfd, fd, events->events);
    return nsfw_base_epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &tmpEvt);
}
#endif

int nsep_epctl_add(struct eventpoll *ep, nsep_epollInfo_t * epfd_epInfo,
                   int fd, struct epoll_event *events)
{

    int ret = 0;

    NSSOC_LOGINF("epfd=%d,fd=%d,events=%u", ep->epfd, fd, events->events);

    nsep_epollInfo_t *epInfo = nsep_get_info_by_sock(fd);

    if (NULL == epInfo)
    {
#ifdef KERNEL_FD_SUPPORT
        if (-1 == nsep_is_add_valid(fd, events))
        {
            NSSOC_LOGERR("Invalid add check nfd=%d]", fd);
            return -1;
        }
        if (-1 == nsep_alloc_info_with_sock(fd))
        {
            NSSOC_LOGERR("Can't alloc epInfo for nfd]nfd=%d", fd);
            return -1;
        }
        nsep_set_info_proto_fd(fd, nstack_get_linux_mid(), fd);
        epInfo = nsep_get_info_by_sock(fd);
#else
        /*if FD is not in use, epoll_ctl_add return fail */
        NSSOC_LOGERR("Invalid add check nfd]nfd=%d", fd);
        return -1;
#endif
    }

    if (NULL == epfd_epInfo)
    {
        NSSOC_LOGWAR("epfd_epInfo is NULL]epfd=%d,fd=%d ", ep->epfd,
                     epInfo->fd);
        return -1;
    }

    ret = nsep_insert_node(ep, epfd_epInfo, events, epInfo);
    if (0 != ret)
    {
        NSSOC_LOGWAR("insert fail]epfd=%d,fd=%d ", ep->epfd, epInfo->fd);
        return -1;
    }

#ifdef KERNEL_FD_SUPPORT
    /* Add fd to epoll fd to support kernel epoll thread */
    if (-1 == epInfo->rmidx || epInfo->rmidx == nstack_get_linux_mid())
    {
        if (-1 == nsep_add_to_kernel(ep->epfd, epInfo->fd, events))
        {                       /*no need null pointer check */
            NSSOC_LOGWAR("epctl fail]epfd=%d,fd=%d,errno=%d", ep->epfd,
                         epInfo->fd, errno);
            return -1;
        }
    }
#endif

    return 0;
}

int nsep_epctl_del(struct eventpoll *ep, struct epitem *epi)
{
    int ret = 0;

    nsep_epollInfo_t *epInfo = (nsep_epollInfo_t *) SHMEM_ADDR_SHTOL(epi->private_data);        /*no need null pointer check */
    NSSOC_LOGINF("epfd=%d,fd=%d,epi=%p", ep->epfd, epi->fd, epi);

#ifdef KERNEL_FD_SUPPORT
    nsfw_base_epoll_ctl(ep->epfd, EPOLL_CTL_DEL, epi->fd, NULL);        /*do not need return value */
#endif
    nsep_epctl_triggle(epi, epInfo, nstack_ep_triggle_del);

    dmm_spin_lock_with_pid((dmm_spinlock_t *) (&epInfo->epiLock));      /*do not need return value */
    /* Here need to check because nstack_close may has removed this epi->fllink */
    ep_list_del(&epInfo->epiList, &epi->fllink);        /*no need null pointer check */
    /* after close fd in epfd, epfd still can epoll_wait EPOLLIN event for these fd */
    (void) nstack_epoll_event_dequeue(epi, 0);
    dmm_spin_unlock((dmm_spinlock_t *) (&epInfo->epiLock));
    nsep_epctl_triggle(NULL, epInfo, nstack_ep_triggle_inform_app);

    dmm_spin_lock_with_pid((dmm_spinlock_t *) (&ep->lock));     /*do not need return value */
    ret = nstack_ep_unlink(ep, epi);
    dmm_spin_unlock((dmm_spinlock_t *) (&ep->lock));    /*no need null pointer check */
    nsep_free_epitem(epi);      /*do not need return value */

    return ret;
}

/*no need null pointer check*/
int nsep_epctl_mod(struct eventpoll *ep,
                   nsep_epollInfo_t * epInfo,
                   struct epitem *epi, struct epoll_event *events)
{
    if (NULL == epInfo)
    {
        errno = EINVAL;
        NSSOC_LOGWAR("epfd=%d, intput epInfo is null err", ep->epfd);
        return -1;
    }

    NSSOC_LOGINF("epfd=%d,fd=%d,events=%u", ep->epfd, epInfo->fd,
                 events->events);

    dmm_spin_lock_with_pid((dmm_spinlock_t *) (&ep->lock));     /*do not need return value */
    epi->event = *events;       /* kernel tells me that I need to modify epi->event in lock context */
    dmm_spin_unlock((dmm_spinlock_t *) (&ep->lock));

#ifdef KERNEL_FD_SUPPORT
    /* Modify fd to epoll fd to support kernel epoll thread */
    if (-1 == epInfo->rmidx || epInfo->rmidx == nstack_get_linux_mid())
    {
        if (-1 == nsep_mod_to_kernel(ep->epfd, epInfo->fd, events))
        {
            NSSOC_LOGWAR("epctl fail]epfd=%d,fd=%d,errno=%d", ep->epfd,
                         epInfo->fd, errno);
            return -1;
        }
    }
#endif

    nsep_epctl_triggle(epi, epInfo, nstack_ep_triggle_mod);
    return 0;
}

/*
 * Called by epoll_wait
 * Wait until events come or timeout
 */
 /*no need to check return value */
int nsep_ep_poll(struct eventpoll *ep, struct epoll_event *events,
                 int maxevents, struct spl_conn_pool *ep_conn)
{
    int evt = 0;
    struct ep_hlist_node *node = NULL;
    struct epitem *epi = NULL;
    i32 enQueRet = 0;
    void *ring_hd = NULL;
    unsigned int tmp_revents = 0;

    if (maxevents <= 0 || !events)
        return 0;

    if (NULL == ep_conn)
    {
        goto rdlist_check;
    }

    ring_hd = SHMEM_ADDR_SHTOL(ep_conn->ring_hd);

    dmm_spin_lock_with_pid((dmm_spinlock_t *) (&ep->sem));
    dmm_spin_lock_with_pid((dmm_spinlock_t *) (&ep->lock));
    while (1)
    {
        enQueRet = nsfw_mem_ring_dequeue(ring_hd, (void **) &epi);
        if (1 != enQueRet)
        {
            break;
        }
        /* dont clear epi successfully, it cause app coredump */
        nsep_epollInfo_t *epInfo =
            (nsep_epollInfo_t *) SHMEM_ADDR_SHTOL(epi->private_data);
        if ((NULL == epInfo) || (NULL == epi->ep))
        {
            NSPOL_LOGERR
                ("epInfo or ep is NULL]ep_conn=%p,ep=%p,ring_hd=%p,epi=%p,epi->ep=%p,epInfo=%p",
                 ep_conn, ep, ring_hd, epi, SHMEM_ADDR_SHTOL(epi->ep),
                 epInfo);
            continue;
        }
        epi->app_poll_count = epi->spl_enter_count;
        /* dont clear epi successfully, it cause app coredump */
        if (ep != SHMEM_ADDR_SHTOL(epi->ep))
        {
            NSPOL_LOGERR
                ("ep_conn use by multi ep]ep_conn=%p,ep=%p,ring_hd=%p,epi=%p,epInfo=%p,epInfo->fd=%d,epi->ep=%p",
                 ep_conn, ep, ring_hd, epi, epInfo, epInfo->fd,
                 SHMEM_ADDR_SHTOL(epi->ep));
            continue;
        }

        nstack_dfx_state_update((u64) epInfo->rlfd, epInfo->rmidx,
                                DMM_APP_EPOLL_WAIT_GET_TICK, NULL);

        if (!EP_HLIST_NODE_LINKED(&epi->rdllink))
        {
            ep_hlist_add_tail(&ep->rdlist, &epi->rdllink);
        }

    };

    dmm_spin_unlock((dmm_spinlock_t *) (&ep->lock));
    dmm_spin_unlock((dmm_spinlock_t *) (&ep->sem));

  rdlist_check:

    if (EP_HLIST_EMPTY(&ep->rdlist))
    {
        NSSOC_LOGDBG("ep->rdlist is Empty, epfd=%d", ep->epfd);
        return 0;
    }

    dmm_spin_lock_with_pid((dmm_spinlock_t *) (&ep->sem));      /*do not need return value */
    if (EP_HLIST_EMPTY(&ep->rdlist))
        goto out;

    dmm_spin_lock_with_pid((dmm_spinlock_t *) (&ep->lock));     /*do not need return value */

    struct ep_hlist_node *epRdHead =
        (struct ep_hlist_node *) SHMEM_ADDR_SHTOL(ep->rdlist.head);
    if (!epRdHead)
    {
        return 0;
    }
    node = (struct ep_hlist_node *) SHMEM_ADDR_SHTOL(epRdHead->next);

    while (node)
    {

        epi = ep_hlist_entry(node, struct epitem, rdllink);

        node = (struct ep_hlist_node *) SHMEM_ADDR_SHTOL(node->next);
        nsep_epollInfo_t *epInfo =
            (nsep_epollInfo_t *) SHMEM_ADDR_SHTOL(epi->private_data);
        epInfo = (nsep_epollInfo_t *) SHMEM_ADDR_SHTOL(epi->private_data);

        nstack_ep_get_evt(epInfo, epi);

        tmp_revents = epi->revents;

        /* app epoll_wait return 24 event, when the fd is in establish state */

        while (!__sync_bool_compare_and_swap(&epi->revents, tmp_revents, 0))
        {                       /* daemon-stack don't have lock for err hup rdhup event, so here must ensure that daemon-stack don't modify it */
            tmp_revents = epi->revents;
        };

        if (tmp_revents)
        {
            events[evt].events = tmp_revents;
            events[evt].data = epi->event.data;
            NSSOC_LOGDBG("Add event]epfd=%d,fd=%d,events=%u", ep->epfd,
                         epi->fd, events[evt].events);
            evt++;
            nstack_dfx_state_update((u64) epInfo->rlfd, epInfo->rmidx,
                                    DMM_APP_EPOLL_WAIT_EVENT,
                                    (void *) (u64) tmp_revents);
        }

        if (0 == tmp_revents || epi->event.events & EPOLLET)
        {
            NSSOC_LOGDBG("Del epi->rdllink,epfd=%d,fd=%d", ep->epfd, epi->fd);
            ep_hlist_del(&ep->rdlist, &epi->rdllink);
        }

        if (tmp_revents & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))
        {
            NSSOC_LOGINF("epfd=%d,fd=%d,epi=%p,revent=%u", ep->epfd, epi->fd,
                         epi, tmp_revents);
        }

        if (evt >= maxevents)
            break;
    }
    dmm_spin_unlock((dmm_spinlock_t *) (&ep->lock));
  out:
    dmm_spin_unlock((dmm_spinlock_t *) (&ep->sem));

    NSSOC_LOGDBG("Return epfd=%d,fd=%d,EP_HLIST_EMPTY(&ep->rdlist)=%d",
                 ep->epfd, epi ? epi->fd : -1, EP_HLIST_EMPTY(&ep->rdlist));

    return evt;
}

/*no need to check return value*/

void nsep_remove_epfd(nsep_epollInfo_t * pinfo)
{
    pid_t pid = get_sys_pid();
    struct list_node *prenode = NULL;
    struct list_node *nextnode = NULL;
    struct list_node **node_arry = NULL;
    int lenth = NSTACK_MAX_EPOLL_INFO_NUM * sizeof(struct list_node *);
    struct epitem *epi = NULL;
    struct epitem *tepi = NULL;
    struct eventpoll *ep = NULL;
    u32_t i = 0;
    u32_t icnt = 0;

    if (!pinfo)
    {
        return;
    }
    /*malloc a block memory to store epitem node, do not use list for maybe free item */
    /*malloc() & free() can be used */
    node_arry = (struct list_node **) malloc(lenth);
    if (!node_arry)
    {
        NSSOC_LOGERR("remove fd from ep malloc mem fail]fd=%d,ep=%p",
                     pinfo->fd, pinfo->ep);
        return;
    }
    /*add return value check */
    int retVal = memset_s(node_arry, lenth, 0, lenth);
    if (EOK != retVal)
    {
        NSSOC_LOGERR("memset_s failed]retVal=%d", retVal);
        free(node_arry);        /*free() can be used */
        return;
    }

    dmm_spin_lock_with_pid((dmm_spinlock_t *) (&pinfo->epiLock));       /*do not need return value */
    /*list head must be not null */
    prenode = (struct list_node *) SHMEM_ADDR_SHTOL(pinfo->epiList.head);
    nextnode = (struct list_node *) SHMEM_ADDR_SHTOL(prenode->next);
    icnt = 0;

    /*find all node that pid is belong to itself */
    while (nextnode)
    {
        if (++i > NSTACK_MAX_EPOLL_INFO_NUM)
        {
            /*record the exception log */
            NSSOC_LOGERR("error maybe happen]free pinfo=%p", pinfo);
            break;
        }

        epi = ep_list_entry(nextnode, struct epitem, fllink);
        if (pid == epi->pid)
        {
            prenode->next = nextnode->next;
            nextnode->next = NULL;
            /*put into release list */
            node_arry[icnt] = nextnode;
            icnt++;
            /* only can clear ring for epi that del */
            (void) nstack_epoll_event_dequeue(epi, 0);
        }
        else
        {
            prenode = nextnode;
        }
        nextnode = (struct list_node *) SHMEM_ADDR_SHTOL(prenode->next);
    }

    dmm_spin_unlock((dmm_spinlock_t *) (&pinfo->epiLock));

    /*free all epitem */
    for (i = 0; i < icnt; i++)
    {

        epi = ep_list_entry(node_arry[i], struct epitem, fllink);
        ep = (struct eventpoll *) SHMEM_ADDR_SHTOL(epi->ep);
        if (ep)
        {
            dmm_spin_lock_with_pid((dmm_spinlock_t *) (&ep->sem));
            /* Here don't use epi you find before, use fd and ep to find the epi again.that is multithread safe */
            tepi = nsep_find_ep(ep, pinfo->fd);
            /*record the exception log */
            if (epi != tepi)
            {
                NSSOC_LOGERR("remove fd:%d epi:%p tepi:%p erro maybe happen",
                             pinfo->fd, epi, tepi);
            }
            /*if tepi is null, epi maybe free by nsep_close_epfd, so no need to free again */
            if (tepi)
            {
#ifdef KERNEL_FD_SUPPORT
                nsfw_base_epoll_ctl(ep->epfd, EPOLL_CTL_DEL, tepi->fd, NULL);   /*do not need return value */
#endif
                nsep_epctl_triggle(tepi, pinfo, nstack_ep_triggle_del);
                dmm_spin_lock_with_pid((dmm_spinlock_t *) (&ep->lock)); /*do not need return value */
                (void) nstack_ep_unlink(ep, tepi);
                dmm_spin_unlock((dmm_spinlock_t *) (&ep->lock));

                nsep_free_epitem(epi);
            }
            dmm_spin_unlock((dmm_spinlock_t *) (&ep->sem));
        }
    }

    nsep_epctl_triggle(NULL, pinfo, nstack_ep_triggle_inform_app);
    /*malloc() & free() can be used */
    free(node_arry);
    return;
}

void nsep_close_epfd(struct eventpoll *ep)
{

    if (!ep)
        return;

    struct epitem *epi = NULL;
    struct ep_rb_node *node = NULL;

    dmm_spin_lock_with_pid((dmm_spinlock_t *) (&ep->sem));      /*do not need return value */
    while ((node = ep_rb_first(&ep->rbr)))
    {

        epi = ep_rb_entry(node, struct epitem, rbn);

        int ret = nsep_epctl_del(ep, epi);

        /* Avoid dead loop */
        if (ret)
        {
            NSSOC_LOGERR
                ("nstack epctl del fail, will break to avoid dead loop]ep->fd=%d,epi->fd=%d",
                 ep->epfd, epi->fd);
            break;
        }
    }
    dmm_spin_unlock((dmm_spinlock_t *) (&ep->sem));
    nsep_free_eventpoll(ep);    /*do not need return value */
}

/*no need to check null pointer*/
static inline int nsp_epoll_close_kernel_fd(int sock,
                                            nsep_epollInfo_t * epInfo)
{
    NSSOC_LOGINF("fd=%d,type=%d", sock, epInfo->fdtype);
    int ret = 0;
    nsep_remove_epfd(epInfo);

    u32_t pid = get_sys_pid();
    dmm_spin_lock_with_pid((dmm_spinlock_t *) (&epInfo->freeLock));     /*do not need return value */
    int left_count = nsep_del_last_pid(&epInfo->pidinfo, pid);
    dmm_spin_unlock((dmm_spinlock_t *) (&epInfo->freeLock));
    if (-1 == left_count)
    {
        NSSOC_LOGERR("pid not exist]fd=%d,type=%d,pid=%u", sock,
                     epInfo->fdtype, pid);
    }

    if (0 == left_count)
    {
        ret = nsep_free_epinfo(epInfo);
        NSSOC_LOGINF("epinfo removed]fd=%d,type=%d", sock, epInfo->fdtype);
    }

    return ret;
}

/*no need to check null pointer*/
static inline int nsp_epoll_close_spl_fd(int sock, nsep_epollInfo_t * epInfo)
{
    NSSOC_LOGINF("fd=%d,type=%d", sock, epInfo->fdtype);
    nsep_remove_epfd(epInfo);   /*no need to check null pointer */
    return 0;
}

/*no need to check null pointer*/
static inline int nsp_epoll_close_ep_fd(int sock, nsep_epollInfo_t * epInfo)
{
    struct eventpoll *ep = SHMEM_ADDR_SHTOL(epInfo->ep);
    struct spl_conn_pool *ep_conn = SHMEM_ADDR_SHTOL(epInfo->ep_conn);
    u32_t pid = get_sys_pid();
    NSSOC_LOGINF("fd:%d is epoll fd ep:%p]", sock, ep);
    dmm_spin_lock_with_pid((dmm_spinlock_t *) (&epInfo->freeLock));
    int left_count = nsep_del_last_pid(&epInfo->pidinfo, pid);
    dmm_spin_unlock((dmm_spinlock_t *) (&epInfo->freeLock));
    if (0 == left_count)
    {
        epInfo->ep = NULL;
        epInfo->ep_conn = NULL;
        nsep_close_epfd(ep);
        /* must close ep fistly before free ep_conn, becasue if close ep_conn firstly, then this ep_conn will alloc by other epfd,
           this time, now daemon-stack possiblely will report event using this ep_conn */
        (void) nsep_free_ep_spl_conn_ring(ep_conn);
        nsep_free_epinfo(epInfo);
    }
    return 0;
}

/*no need to check null pointer*/
int nsep_epoll_close(int sock)
{
    int ret = 0;
    nsep_epollInfo_t *epInfo = nsep_get_info_by_sock(sock);
    if (!epInfo)
    {
        NSSOC_LOGDBG("epollsock close sock:%d is not exist", sock);
        return 0;
    }

    nsep_set_info_sock_map(sock, NULL);

    if (NSTACK_EPOL_FD == epInfo->fdtype)
    {
        return nsp_epoll_close_ep_fd(sock, epInfo);
    }

    if (epInfo->rmidx == nstack_get_linux_mid())
    {
        ret = nsp_epoll_close_kernel_fd(sock, epInfo);
    }
    else
    {
        ret = nsp_epoll_close_spl_fd(sock, epInfo);
    }

    return ret;
}

/* epinfo add pid */
void nsep_fork(u32_t ppid)
{
    u32 cpid = get_sys_pid();
    nsep_epollManager_t *manager = nsep_get_manager();
    if (NULL == manager->infoSockMap)
    {
        NSSOC_LOGERR("infoSockMap is NULL]ppid=%u,cpid=%u", ppid, cpid);
        return;
    }

    nsep_epollInfo_t *epinfo = NULL;
    int pos;
    for (pos = 0; (u32_t) pos < NSTACK_KERNEL_FD_MAX; pos++)
    {
        epinfo = manager->infoSockMap[pos];
        if (epinfo)
        {
            if (nsep_add_pid(&epinfo->pidinfo, cpid) != 0)
            {
                NSSOC_LOGERR("epinfo add pid failed]fd=%d,ppid=%u.cpid=%u",
                             pos, ppid, cpid);
            }
            else
            {
                NSSOC_LOGDBG("epinfo add pid ok]fd=%d,ppid=%u.cpid=%u", pos,
                             ppid, cpid);
            }
        }
    }
}

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif /* __cplusplus */
