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
//#include "nstack_module.h"
//#include "nstack_sockops.h"
#include "nsfw_mem_api.h"
//#include "nstack_fd_mng.h"
//#include "nstack.h"

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C"{
/* *INDENT-ON* */
#endif /* __cplusplus */

static uint32_t g_nstack_epoll_fd_max = 0;
static uint32_t g_nstack_epoll_module_max = 0;

#define EP_CHECK_SOCK_VALID(_sock) ((_sock) >= 0 && (u32_t)(_sock) < g_nstack_epoll_fd_max)

void nsep_set_info_sock_map(int sock, nsep_epollInfo_t * info)
{
    nsep_epollManager_t *manager = nsep_get_manager();
    if (NULL == manager->infoSockMap)
        return;

    if (sock < 0 || (u32_t) sock >= g_nstack_epoll_fd_max)
        return;

    manager->infoSockMap[sock] = info;
}

nsep_epollInfo_t *nsep_get_info_by_sock(int sock)
{
    nsep_epollManager_t *manager = nsep_get_manager();
    if ((NULL == manager) || (NULL == manager->infoSockMap))
        return NULL;

    if (sock < 0 || (u32_t) sock >= g_nstack_epoll_fd_max)
        return NULL;

    return manager->infoSockMap[sock];
}

int nsep_alloc_info_with_sock(int nfd)
{

    nsep_epollInfo_t *epInfo = NULL;

    if (!EP_CHECK_SOCK_VALID(nfd))
    {
        return -1;
    }

    if (-1 == nsep_alloc_epinfo(&epInfo))
    {
        NSSOC_LOGERR("Alloc share info fail,[return]");
        return -1;
    }

    epInfo->fd = nfd;

    nsep_set_info_sock_map(nfd, epInfo);

    return 0;
}

void nsep_set_info_proto_fd(int fd, int modInx, int protoFD)
{
    nsep_epollInfo_t *epInfo = nsep_get_info_by_sock(fd);

    if (NULL == epInfo)
        return;

    if (modInx < 0 || modInx >= g_nstack_epoll_module_max)
        return;

    epInfo->protoFD[modInx] = protoFD;
}

int nsep_get_info_proto_fd(int fd, int modInx)
{
    nsep_epollInfo_t *epInfo = nsep_get_info_by_sock(fd);

    if (NULL == epInfo)
        return -1;

    return epInfo->protoFD[modInx];
}

void nsep_set_infomdix(int fd, int rmidx)
{
    nsep_epollInfo_t *epInfo = nsep_get_info_by_sock(fd);

    if (NULL == epInfo)
        return;

    epInfo->rmidx = rmidx;
}

int nsep_get_info_midx(int fd)
{
    nsep_epollInfo_t *epInfo = nsep_get_info_by_sock(fd);

    if (NULL == epInfo)
        return -1;

    return epInfo->rmidx;
}

void nsep_set_info_rlfd(int fd, int rlfd)
{
    nsep_epollInfo_t *epInfo = nsep_get_info_by_sock(fd);

    if (NULL == epInfo)
        return;

    epInfo->rlfd = rlfd;
}

int nsep_get_info_rlfd(int fd)
{
    nsep_epollInfo_t *epInfo = nsep_get_info_by_sock(fd);

    if (NULL == epInfo)
        return -1;

    return epInfo->rlfd;
}

void nsep_set_info_sleep_time(int fd, u32 sleepTime)
{
    nsep_epollInfo_t *epInfo = nsep_get_info_by_sock(fd);

    if (NULL == epInfo)
        return;

    epInfo->sleepTime = sleepTime;
}

int nsep_get_info_sleep_time(int fd)
{
    nsep_epollInfo_t *epInfo = nsep_get_info_by_sock(fd);

    if (NULL == epInfo)
        return -1;

    return epInfo->sleepTime;
}

/*  if APP got killed while ep and
    fdtype has been assigned but ep_conn not, the daemon-stack will trigger cordump when recycling
    APP's ep resource. So we must make sure ep and ep_conn has been assigned before fdtype get NSTACK_EPOL_FD,
    and combine them both to single function */
void nsep_set_info_ep_resource(int fd, struct eventpoll *ep,
                               struct spl_conn_pool *ep_spl_conn)
{
    nsep_epollInfo_t *epInfo = nsep_get_info_by_sock(fd);

    if (NULL == epInfo)
        return;

    epInfo->ep_conn = (struct spl_conn_pool *) SHMEM_ADDR_LTOSH(ep_spl_conn);
    epInfo->ep = (struct eventpoll *) SHMEM_ADDR_LTOSH(ep);

    epInfo->fdtype = NSTACK_EPOL_FD;
}

struct eventpoll *nsep_get_info_ep(int fd)
{
    nsep_epollInfo_t *epInfo = nsep_get_info_by_sock(fd);

    if (NULL == epInfo)
        return NULL;

    return (struct eventpoll *) SHMEM_ADDR_SHTOL(epInfo->ep);
}

int nsep_free_info_with_sock(int nfd)
{
    if ((u32_t) nfd >= g_nstack_epoll_fd_max || nfd < 0)
        return -1;

    nsep_epollInfo_t *info = nsep_get_info_by_sock(nfd);

    if (NULL == info)
        return 0;

    nsep_set_info_sock_map(nfd, NULL);

    NSSOC_LOGDBG("nsep_free_info_with_sock info:%p, nfd:%d", info, nfd);
    /* If this not just used by linux, it should be freed in stackpool */
    if (-1 == nsep_free_epinfo(info))
    {
        NSSOC_LOGERR("Error to free ep info");
        return -1;
    }
    return 0;
}

/**
 * @Function        nsep_init_info_sock_map
 * @Description     initial map of epoll info and socket
 * @param           none
 * @return          0 on success, -1 on error
 */
int nsep_init_info_sock_map(uint32_t epoll_fd_max, uint32_t module_max)
{
    nsep_epollManager_t *manager = nsep_get_manager();
    /*this function is necessary */

    g_nstack_epoll_fd_max = epoll_fd_max;
    g_nstack_epoll_module_max = module_max;
    nsep_epollInfo_t **map =
        (nsep_epollInfo_t **) malloc(g_nstack_epoll_fd_max *
                                     sizeof(nsep_epollInfo_t *));

    if (!map)
    {
        NSSOC_LOGERR("malloc epInfoPool fail");
        return -1;
    }

    u32_t iindex;
    for (iindex = 0; iindex < g_nstack_epoll_fd_max; iindex++)
    {
        map[iindex] = NULL;
    }

    manager->infoSockMap = map;

    return 0;
}

NSTACK_STATIC mzone_handle nsep_ring_lookup(char *name)
{
    if (NULL == name)
    {
        NSSOC_LOGERR("param error]name=%p", name);
        return NULL;
    }

    nsfw_mem_name mem_name;
    /*modify strncpy to strcpy, because strlen(name) with strncpy is meaningless */
    if (EOK != strcpy_s(mem_name.aname, sizeof(mem_name.aname), name))
    {                           /*not null here */
        NSSOC_LOGERR("Error to lookup ring by name, strcpy fail]name=%s",
                     name);
        return NULL;
    }
    mem_name.enowner = NSFW_PROC_MAIN;
    mem_name.entype = NSFW_SHMEM;

    return nsfw_mem_ring_lookup(&mem_name);
}

NSTACK_STATIC mzone_handle nsep_attach_shmem(char *name)
{
    if (NULL == name)
    {
        NSSOC_LOGERR("param error]name=%p", name);
        return NULL;
    }

    nsfw_mem_name mem_name;
    /*add return value check */
    int retVal = strcpy_s(mem_name.aname, sizeof(mem_name.aname), name);
    if (EOK != retVal)
    {
        NSSOC_LOGERR("strcpy_s failed]");
        return NULL;
    }
    mem_name.enowner = NSFW_PROC_MAIN;
    mem_name.entype = NSFW_SHMEM;

    return nsfw_mem_zone_lookup(&mem_name);
}

NSTACK_STATIC int nsep_attach_info_mem()
{
    mzone_handle hdl = nsep_attach_shmem(MP_NSTACK_EPOLL_INFO_NAME);
    if (NULL == hdl)
        return -1;

    nsep_epollManager_t *manager = nsep_get_manager();
    manager->infoPool.pool = (nsep_epollInfo_t *) hdl;

    hdl = nsep_ring_lookup(MP_NSTACK_EPINFO_RING_NAME);
    if (NULL == hdl)
    {
        NSSOC_LOGERR("Fail to loock up epoll info ring]name=%s",
                     MP_NSTACK_EPINFO_RING_NAME);
        return -1;
    }

    manager->infoPool.ring = hdl;

    return 0;
}

NSTACK_STATIC int nsep_attach_epitem_mem()
{
    mzone_handle hdl = nsep_attach_shmem(MP_NSTACK_EPITEM_POOL);
    if (NULL == hdl)
        return -1;

    nsep_epollManager_t *manager = nsep_get_manager();
    manager->epitemPool.pool = (struct epitem *) hdl;

    hdl = nsep_ring_lookup(MP_NSTACK_EPITEM_RING_NAME);
    if (NULL == hdl)
    {
        NSSOC_LOGERR("Fail to loock up epoll info ring]name=%s",
                     MP_NSTACK_EPITEM_RING_NAME);
        return -1;
    }

    manager->epitemPool.ring = hdl;

    return 0;
}

NSTACK_STATIC int nsep_attach_eventpoll_mem()
{
    mzone_handle hdl = nsep_attach_shmem(MP_NSTACK_EVENTPOLL_POOL);
    if (NULL == hdl)
        return -1;

    nsep_epollManager_t *manager = nsep_get_manager();
    manager->epollPool.pool = (struct eventpoll *) hdl;

    hdl = nsep_ring_lookup(MP_NSTACK_EVENTPOOL_RING_NAME);
    if (NULL == hdl)
    {
        NSSOC_LOGERR("Fail to loock up epoll info ring]name=%s",
                     MP_NSTACK_EVENTPOOL_RING_NAME);
        return -1;
    }

    manager->epollPool.ring = hdl;

    hdl = nsep_ring_lookup(MP_NSTACK_SPL_CONN_RING_NAME);
    manager->ep_connPoll.ring = hdl;

    hdl = nsep_attach_shmem(MP_NSTACK_SPL_CONN_ARRAY_NAME);
    manager->ep_connPoll.pool = hdl;

    return 0;
}

int nsep_attach_memory()
{
    typedef int (*nsep_attachMemFunc_t) (void);
    nsep_attachMemFunc_t attachFuncs[] = { nsep_attach_info_mem,
        nsep_attach_epitem_mem,
        nsep_attach_eventpoll_mem
    };

    int i = 0;
    for (i = 0;
         i < (int) (sizeof(attachFuncs) / sizeof(nsep_attachMemFunc_t)); i++)
    {
        if (-1 == attachFuncs[i] ())
            return -1;
    }

    return 0;
}

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif /* __cplusplus */
