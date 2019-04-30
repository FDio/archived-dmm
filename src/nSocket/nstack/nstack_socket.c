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

#include <time.h>
#include <stdarg.h>

#ifndef __USE_GNU
#define __USE_GNU
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE             /* define RTLD_NEXT */
#endif

#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include "nstack.h"
#include "nstack_socket.h"
#include "nstack_fd_mng.h"
#include "nstack_callback_ops.h"
#include "nstack_sockops.h"
#include "nstack_module.h"
#include "nstack_securec.h"
#include "nsfw_init_api.h"
#include "nsfw_recycle_api.h"
#include "nsfw_base_linux_api.h"
#include "nstack_rd_data.h"
#include "nstack_rd.h"
#include "select_adapt.h"
#include "nstack_select.h"
#include "nstack_share_res.h"
#include "nsfw_ps_api.h"
#include "nstack_ip_addr.h"
#include "nsfw_mem_api.h"
#include "dmm_spinlock.h"
#include "dmm_rwlock.h"
#include "nstack_dmm_dfx.h"
#include <stdlib.h>
#include <unistd.h>

#ifndef F_SETFL
#define	F_SETFL		4
#endif

#define NSTACK_LOOP_IP  0x100007f
#define NSTACK_ANY_IP   0x0

#ifndef REPLAYS_POSIX_API
#define REPLAYS_POSIX_API 1
#endif

#if REPLAYS_POSIX_API
#define strong_alias(name, aliasname) \
  extern __typeof (name) aliasname __attribute__ ((alias (#name)));
#undef NSTACK_MK_DECL
#define NSTACK_MK_DECL(ret, fn, args)        strong_alias(nstack_##fn, fn)
#include <declare_syscalls.h.tmpl>
#endif
__thread unsigned int g_addrinfo_flag = 0;

extern void nsep_notify_fd_epoll_wait_fail(struct eventpoll *ep);
extern void custom_close_status(int fd, int status);

#define NSTACK_FUN_CHECK_RET(fdops, mod, fun) \
    if (!(fdops) || !(fdops)->pf##fun) \
    { \
       nstack_set_errno(ENOSYS); \
       NSSOC_LOGERR("nstack module:%d ops:%p, ops->pf%s:%p error [return]", mod, fdops, #fun, (fdops)->pf##fun); \
       return -1; \
    }

#define NSTACK_DOMAIN_CHECK_RETURN(domainVal, fn, para) { \
        if (domainVal != AF_INET && domainVal != PF_INET && \
            domainVal != AF_INET6 && domainVal != PF_INET6)  \
        { \
            int _ret_ = nsfw_base_socket para ; \
            return _ret_; \
        }  \
    }

#define NSTACK_ADDRINFO_CHECK_RETURN(flag, fn, para){\
    if (1 == flag) \
    {\
        NSSOC_LOGINF("linux getaddrinfo [call]");\
        return nsfw_base_##fn para ; \
    }\
}

NSTACK_STATIC inline int support_kernel_fd()
{
#ifdef KERNEL_FD_SUPPORT
    return 1;
#else
    return 0;
#endif
}

/*  fork will close all fd(dont create by nstack) in continure,
    which cause lots of log, here remove the log output */
#define NSTACK_FD_LINUX_CHECK_RETURN(fdVal, fn, fdInf, para) { \
    if (!(fdInf = nstack_get_valid_inf(fdVal))) \
    { \
        if ((support_kernel_fd()) && (fdVal != nsep_get_manager()->checkEpollFD))  \
        {  \
            return nsfw_base_##fn para; \
        }  \
        nstack_set_errno(ENOSYS); \
        return -1; \
    } \
}

#define NSTACK_SELECT_LINUX_CHECK()     (get_select_module()->inited)

/* Support multi-threaded and multi-process */
NSTACK_STATIC inline void set_fd_status(int fd, FD_STATUS status)
{
    nstack_fd_local_lock_info_t *local_lock = get_fd_local_lock_info(fd);
    if (local_lock)
    {
        if (FD_OPEN == status)
        {
            atomic_inc(&local_lock->fd_ref);
        }
        local_lock->fd_status = (int) status;
    }
}

#define LOCK_SEND(fd, fd_inf, local_lock) \
    u64_t tmp_in;               /* use tmp_in to avoid statistic mistake from the lock acquiring */ \
    NSTACK_GET_SYS_TICK(&tmp_in);\
    INC_FD_REF_RETURN(fd, fd_inf, local_lock) \
    NSTACK_FD_DFX_LAST_SEND_TICK_IN(fd, tmp_in)

static inline void UNLOCK_SEND(int fd, nstack_fd_Inf * fdInf,
                               nstack_fd_local_lock_info_t * local_lock)
{
    u64_t tmp_out;
    NSTACK_GET_SYS_TICK(&tmp_out);
    NSTACK_FD_DFX_LAST_SEND_TICK_OUT(fd, tmp_out);
    nstack_fd_dfx_update_dfx_data(fd, fdInf->rlfd, fdInf->rmidx,
                                  DMM_STAT_LONGEST_SEND_COST, NULL);
    if ((NULL != local_lock) && atomic_dec(&local_lock->fd_ref) == 0)
    {
        release_fd(fd, local_lock);
    }
}

#define LOCK_RECV(fd, fd_inf, local_lock) \
    u64_t tmp_in; /* use tmp_in to avoid statistic mistake from the lock acquiring */ \
    NSTACK_GET_SYS_TICK(&tmp_in);\
    LOCK_BASE_WITHOUT_KERNEL(fd, fd_inf, local_lock) \
    NSTACK_FD_DFX_LAST_RECV_TICK_IN(fd, tmp_in)

static inline void UNLOCK_RECV(int fd, nstack_fd_Inf * fdInf,
                               nstack_fd_local_lock_info_t * local_lock)
{
    u64_t tmp_out;
    NSTACK_GET_SYS_TICK(&tmp_out);
    NSTACK_FD_DFX_LAST_RECV_TICK_OUT(fd, tmp_out);
    nstack_fd_dfx_update_dfx_data(fd, fdInf->rlfd, fdInf->rmidx,
                                  DMM_STAT_LONGEST_RECV_COST, NULL);
    /*do not need return value */ UNLOCK_BASE(fd, fdInf, local_lock);
}

#define NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_SEND(fdVal, fun, inf, err, local_lock) \
    /*do not need return value*/NSTACK_EPOLL_FD_CHECK_RET_UNLOCK(fdVal, fun, inf, err, local_lock, UNLOCK_SEND)

#define NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_RECV(fdVal, fun, inf, err, local_lock) \
    /*do not need return value*/NSTACK_EPOLL_FD_CHECK_RET_UNLOCK(fdVal, fun, inf, err, local_lock, UNLOCK_RECV)

void set_fd_status_lock_fork(int fd, FD_STATUS status)
{
    dmm_read_lock(get_fork_lock());
    set_fd_status(fd, status);
    dmm_read_unlock(get_fork_lock());
}

/* Implemet aggregation packets send/receive. */

int nstack_create_kernel_socket()
{
    return nsfw_base_socket(AF_UNIX, SOCK_DGRAM, 0);
}

int nstack_socket_create_index(int domain, int itype, int protocol,
                               rd_data_item * matched_item)
{
    int ret_fd;
    if (nstack_rd_match_pre(domain, itype, protocol, matched_item) == -1)
    {
        return nsfw_base_socket(domain, itype, protocol);
    }

    //NSTACK_CAL_FUN(nstack_module_ops(matched_item.stack_id), socket, (domain, itype, protocol), ret_fd);
    ret_fd = nstack_create_kernel_socket();

    return ret_fd;
}

int nstack_socket(int domain, int itype, int protocol)
{
    int ret = -1;               //tmp ret of a Single proctol mode.
    int modInx;
    nstack_socket_ops *ops;
    int ret_fd = -1;
    int protoFD[NSTACK_MAX_MODULE_NUM];
    rd_data_item matched_item = {
        .stack_id = -1
    };

    /*check whether module init finish or not */
    NSTACK_INIT_CHECK_RET(socket, domain, itype, protocol);

    NSSOC_LOGINF("(domain=%d, type=%d, protocol=%d) [Caller]", domain, itype,
                 protocol);

#ifndef KERNEL_FD_SUPPORT
    if (domain != AF_INET && domain != PF_INET && domain != AF_INET6)
    {
        NSSOC_LOGERR("don't support the specified address family.]domain=%d",
                     domain);
        nstack_set_errno(EAFNOSUPPORT);
        return ns_fail;
    }

    if (protocol < 0)
    {
        nstack_set_errno(EINVAL);
        return ns_fail;
    }
#endif

    /*if domain don't equal AF_INET , just call linux */
    NSTACK_DOMAIN_CHECK_RETURN(domain, socket, (domain, itype, protocol));

    /* if the socket is called by getaddrinfo, just call linux */
    NSTACK_ADDRINFO_CHECK_RETURN(g_addrinfo_flag, socket,
                                 (domain, itype, protocol));

    nstack_each_mod_inx(modInx)
    {
        protoFD[modInx] = -1;
    }

#ifdef KERNEL_FD_SUPPORT
    /*firstly create linux fd, if create fail or fd is too big just return fail */
    ret_fd =
        nstack_socket_create_index(domain, itype, protocol, &matched_item);
    if (-1 == ret_fd)
    {
        NSSOC_LOGERR
            ("[nstack_linux]domain=%d,type=%d protocol=%d create fail errno:%d [return]",
             domain, itype, protocol, errno);
        return ns_fail;
    }

    /*linux fd is to big, return fail */
    if (!nstack_is_nstack_sk(ret_fd))
    {
        if (ret_fd >= 0)
        {
            nsfw_base_close(ret_fd);    /*donot need return value */
        }
        nstack_set_errno(EMFILE);
        NSSOC_LOGERR
            ("[nstack_linux]domain=%d,type=%d protocol=%d linux fd=%d is too big and return fail [return]",
             domain, itype, protocol, ret_fd);
        return ns_fail;
    }

    nstack_fd_local_lock_info_t *lock_info = get_fd_local_lock_info(ret_fd);
    LOCK_FOR_EP(lock_info);

    protoFD[nstack_get_linux_mid()] = ret_fd;   // Set kernel fd here.
#endif

    /*create socket by calling every module */
    nstack_each_mod_ops(modInx, ops)
    {
#ifdef KERNEL_FD_SUPPORT
        if (modInx == nstack_get_linux_mid())
            continue;
#endif
        NSTACK_CAL_FUN(ops, socket, (domain, itype, protocol), ret);
        protoFD[modInx] = ret;
        NSSOC_LOGINF("Create socket of]modName=%s:%d",
                     nstack_get_module_name_by_idx(modInx), protoFD[modInx]);
    }

    /* alloc nstack fd info */
#ifdef KERNEL_FD_SUPPORT
    nstack_fd_Inf *fdInf = nstack_lk_fd_alloc_with_kernel(ret_fd);
#else
    nstack_fd_Inf *fdInf = nstack_lk_fd_alloc_without_kernel();
#endif
    if (NULL == fdInf)
    {
        /*if alloc failed */
        nstack_each_mod_ops(modInx, ops)
        {
            if (-1 != protoFD[modInx])
            {
                NSTACK_CAL_FUN(ops, close, (protoFD[modInx]), ret);
            }
        }

        nstack_set_errno(EMFILE);
        NSSOC_LOGERR("have no available nstack_fd_Inf [return]");
#ifdef KERNEL_FD_SUPPORT
        UNLOCK_FOR_EP(lock_info);
#endif
        return -1;
    }
#ifndef KERNEL_FD_SUPPORT
    nstack_fd_local_lock_info_t *lock_info =
        get_fd_local_lock_info(fdInf->fd);
    LOCK_FOR_EP(lock_info);
#endif
    fdInf->type = itype;
    fdInf->rd_opt = -1;
    fdInf->rd_item.stack_id = -1;

    if (matched_item.stack_id != -1)
    {
        if (EOK !=
            memcpy_s(&fdInf->rd_item, sizeof(rd_data_item), &matched_item,
                     sizeof(rd_data_item)))
        {
            NSSOC_LOGERR("memcpy_s failed!");
            nstack_set_errno(EMFILE);
            return -1;
        }
    }
    nstack_each_mod_inx(modInx)
    {
#ifndef KERNEL_FD_SUPPORT
        //if (modInx == nstack_get_linux_mid())
        //continue;
#endif
        nstack_set_ret(fdInf, modInx, 0);
        nstack_set_proto_fd(fdInf, modInx, protoFD[modInx]);
        nstack_set_app_info(fdInf, modInx);
    }

#ifdef KERNEL_FD_SUPPORT
    NSSOC_LOGINF("createfd=%d,fdInf->fd=%d,ret=%d [return]", ret_fd,
                 fdInf->fd, ret_fd);
    set_fd_status_lock_fork(ret_fd, FD_OPEN);
#else
    NSSOC_LOGINF("fdInf->fd=%d,ret=%d [return]", fdInf->fd, fdInf->fd);
    set_fd_status_lock_fork(fdInf->fd, FD_OPEN);
    ret_fd = fdInf->fd;
#endif

#ifdef KERNEL_FD_SUPPORT
    if (matched_item.stack_id != -1)
    {
        switch (matched_item.type)
        {
            case RD_DATA_TYPE_TYPE:
                {
                    NSTACK_SET_FD_ATTR(fdInf, matched_item.type_data.attr);
                    break;
                }
            case RD_DATA_TYPE_PROTO:
                {
                    NSTACK_SET_FD_ATTR(fdInf, matched_item.proto_data.attr);
                    break;
                }
            default:
                break;
        }
        fdInf->ops = nstack_module_ops(matched_item.stack_id);
        nstack_set_router_protocol(fdInf, matched_item.stack_id);
        nstack_set_routed_fd(fdInf, protoFD[matched_item.stack_id]);
    }
#endif

    UNLOCK_FOR_EP(lock_info);
    return ret_fd;
}

int nstack_get_stackid_by_name(char *stackname, int *stackid)
{
    int modIdx = 0;

    nstack_each_mod_inx(modIdx)
    {
        /* params are not NULL */
        if (strcmp(nstack_get_module_name_by_idx(modIdx), stackname) == 0)
        {
            *stackid = modIdx;
            return ns_success;
        }
    }
    return ns_fail;
}

int nstack_get_stackid_by_opt(nstack_fd_Inf * fdInf, int *stackid)
{
    *stackid = (int) fdInf->rd_opt;
    switch (fdInf->rd_opt)
    {
        case NSTACK_RD_OPT_KERNEL:
            *stackid = nstack_get_linux_mid();
            return ns_success;

        case NSTACK_RD_OPT_STACKPOOL:
            return nstack_get_stackid_by_name(RD_STACKPOOL_NAME, stackid);

        default:
            return ns_fail;
    }
}

int nstack_socket_get_stackid(nstack_fd_Inf * fdInf,
                              const struct sockaddr *addr, socklen_t addrlen)
{

    nstack_rd_key rdkey = { 0 };

    if (fdInf->rd_opt != -1)
    {
        return nstack_get_stackid_by_opt(fdInf, &fdInf->rd_item.stack_id);
    }

    if (addr->sa_family == AF_INET)
    {
        rdkey.type = RD_DATA_TYPE_IP;
        rdkey.ip_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
    }
    else if (addr->sa_family == AF_INET6)
    {
        rdkey.type = RD_DATA_TYPE_IP6;
        rdkey.in6_addr = ((struct sockaddr_in6 *) addr)->sin6_addr;
    }
    else
    {
        rdkey.type = RD_DATA_TYPE_MAX;
    }

    if (rdkey.type == RD_DATA_TYPE_MAX)
    {
        fdInf->rd_item.stack_id = nstack_get_linux_mid();
        return ns_success;
    }

    return nstack_rd_get_stackid(&rdkey, &fdInf->rd_item);
}

int nstack_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    nstack_fd_Inf *fdInf;
    int retval = ns_fail;
    int tem = -1;
    int modIdx = 0;
    int tfd;
    nstack_rd_key rdkey = { 0 };

    NSTACK_INIT_CHECK_RET(bind, fd, addr, addrlen);

    NSSOC_LOGINF("(sockfd=%d, addr=%p, addrlen=%u) [Caller]", fd, addr,
                 addrlen);

    if (fd < 0)
    {
        nstack_set_errno(EBADF);
        NSSOC_LOGERR("invalid input]fd=%d,addr=%p,len=0x%x [return]", fd,
                     addr, addrlen);
        return -1;
    }
    if ((NULL == addr) || (addrlen < 2))
    {
        nstack_set_errno(EINVAL);
        NSSOC_LOGERR("invalid input]fd=%d,addr=%p,len=0x%x [return]", fd,
                     addr, addrlen);
        return -1;
    }

    /*avoid access to iaddr memory */
    /*miss the condition about sockaddr_un,and get wrong value */
    if ((addrlen >= sizeof(struct sockaddr_in))
        && ((addr->sa_family) == AF_INET))
    {
        struct sockaddr_in *iaddr = (struct sockaddr_in *) addr;
        NSSOC_LOGINF("fd=%d,addr=*.*.%u.%u,port=%d", fd,
                     FUZZY_IP_VAR(&iaddr->sin_addr), ntohs(iaddr->sin_port));
    }
    else if ((addrlen >= sizeof(struct sockaddr_in6))
             && ((addr->sa_family) == AF_INET6))
    {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
        NSSOC_LOGINF("fd=%d,addr=%s,port=%u", fd,
                     inet6_ntoa(&addr6->sin6_addr), htons(addr6->sin6_port));
    }
    else
    {
        NSSOC_LOGINF("addrlen = %d ,fd=%d", (int) addrlen, fd);
    }

    NSTACK_FD_LINUX_CHECK_RETURN(fd, bind, fdInf, (fd, addr, addrlen));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_COMMON(fd, fdInf, local_lock);

    NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_COMMON(fd, bind, fdInf, ENOTSOCK,
                                            local_lock);

    /*bind repeat, first time success, other return fail */
    if (fdInf->isBound)
    {
        nstack_set_errno(EINVAL);
        NSPOL_LOGERR("error, alread bind]fd=%d", fd);
        UNLOCK_COMMON(fd, fdInf, local_lock);
        return -1;
    }

    /*just support af_inet and pf_inet */
    if (addr->sa_family != AF_INET && addr->sa_family != PF_INET
        && addr->sa_family != AF_INET6)
    {
        nstack_set_errno(EAFNOSUPPORT);
        NSSOC_LOGERR("not surport]fd=%d,domain=%d,[return]", fd,
                     addr->sa_family);
        UNLOCK_COMMON(fd, fdInf, local_lock);
        return -1;
    }

    /* need check addrlen's validity, will visite iaddr->sin_addr.s_addr following code
       for visite iaddr->sin_addr.s_addr is 8 byte  */
    if (addrlen < 8)
    {
        nstack_set_errno(EINVAL);
        NSPOL_LOGERR("addrlen<sizeof(struct sockaddr_in)]addrlen=%u",
                     addrlen);
        UNLOCK_COMMON(fd, fdInf, local_lock);
        return -1;
    }

    /* for custom socket, choose stack after creating socket. */
    if (fdInf->ops)
    {
        NSTACK_CAL_FUN(fdInf->ops, bind, (fdInf->rlfd, addr, addrlen), tem);
        if (ns_success == tem)
        {
            retval = ns_success;
            nstack_set_bind_ret(fdInf, fdInf->rmidx, NSTACK_BIND_SUCCESS);
        }
        else
        {
            nstack_set_bind_ret(fdInf, fdInf->rmidx, NSTACK_BIND_FAIL);
        }
        goto bind_over;
    }

    if (fdInf->rd_opt != -1)
    {
        retval = nstack_get_stackid_by_opt(fdInf, &fdInf->rd_item.stack_id);
        if (ns_success != retval)
        {
            NSSOC_LOGWAR
                ("fd Can't select any module by opt for]fd=%d,opt=%d", fd,
                 fdInf->rd_opt);
            fdInf->rd_item.stack_id = -1;
        }
        else
        {
            NSSOC_LOGINF("fd opt Select module]fd=%d,opt=%d,module=%s",
                         fd, fdInf->rd_opt,
                         nstack_get_module_name_by_idx(fdInf->
                                                       rd_item.stack_id));
        }
    }
    else
    {
        if (addr->sa_family == AF_INET)
        {
            struct sockaddr_in *iaddr = (struct sockaddr_in *) addr;
            /*loop ip call linux */
            if (NSTACK_LOOP_IP == iaddr->sin_addr.s_addr)
            {
                fdInf->rd_item.stack_id = nstack_get_linux_mid();
            }
            /*any ip call defaul mod */
            else if (NSTACK_ANY_IP == iaddr->sin_addr.s_addr)
            {
                fdInf->rd_item.stack_id = nstack_defmod_inx();
            }
            else
            {
                rdkey.type = RD_DATA_TYPE_IP;
                rdkey.ip_addr = iaddr->sin_addr.s_addr;
                retval = nstack_rd_get_stackid(&rdkey, &fdInf->rd_item);
                if (ns_success != retval)
                {
                    NSSOC_LOGWAR
                        ("fd Can't select any module for]fd=%d,IP=*.*.%u.%u",
                         fd, FUZZY_IP_VAR(&iaddr->sin_addr));
                }
                else
                {
                    NSSOC_LOGINF
                        ("fd addr Select module]fd=%d,addr=*.*.%u.%u,module=%s",
                         fd, FUZZY_IP_VAR(&iaddr->sin_addr),
                         nstack_get_module_name_by_idx(fdInf->
                                                       rd_item.stack_id));
                }
            }
        }
        else if (addr->sa_family == AF_INET6)
        {
            struct in6_addr *in6 = &((struct sockaddr_in6 *) addr)->sin6_addr;

            /*loop ip call linux */
            if (IN6_IS_ADDR_LOOPBACK(in6))
            {
                fdInf->rd_item.stack_id = nstack_get_linux_mid();
            }
            /*any ip call defaul mod */
            else if (IN6_IS_ADDR_UNSPECIFIED(in6))
            {
                fdInf->rd_item.stack_id = nstack_get_linux_mid();
            }
            else
            {
                rdkey.type = RD_DATA_TYPE_IP6;
                rdkey.in6_addr = *in6;
                retval = nstack_rd_get_stackid(&rdkey, &fdInf->rd_item);
                if (ns_success != retval)
                {
                    NSSOC_LOGWAR
                        ("fd Can't select any module for]fd=%d,IP==%s", fd,
                         inet6_ntoa(in6));
                }
                else
                {
                    NSSOC_LOGINF
                        ("fd addr Select module]fd=%d,addr=%s,module=%s", fd,
                         inet6_ntoa(in6),
                         nstack_get_module_name_by_idx(fdInf->
                                                       rd_item.stack_id));
                }
            }
        }
        else
        {
            fdInf->rd_item.stack_id = nstack_get_linux_mid();
        }
    }

    retval = -1;
    nstack_each_mod_inx(modIdx)
    {
        tfd = nstack_get_proto_fd(fdInf, modIdx);
        if ((-1 == tfd) || (fdInf->rd_item.stack_id != modIdx)) // for INADDR_ANY, need try to bind on both lwip and linux
        {
            /*tfd is -1, but is the select module */
            if (fdInf->rd_item.stack_id == modIdx)
            {
                retval = -1;
                nstack_set_errno(ENOSYS);
                NSSOC_LOGDBG
                    ("fd tfd=-1, but is the select module]fd=%d,tfd=-1,modIdx=%d",
                     fd, modIdx);
            }
            nstack_set_bind_ret(fdInf, modIdx, NSTACK_BIND_FAIL);
            continue;
        }

        NSTACK_CAL_FUN(nstack_module_ops(modIdx), bind,
                       (tfd, addr, addrlen), tem);

        if (ns_success == tem)
        {
            fdInf->ops = nstack_module_ops(modIdx);
            nstack_set_router_protocol(fdInf, modIdx);  /*do not need return value */
            nstack_set_routed_fd(fdInf, tfd);   /*do not need return value */
            retval = ns_success;
            nstack_set_bind_ret(fdInf, modIdx, NSTACK_BIND_SUCCESS);
        }
        else
        {
            NSSOC_LOGWAR("bind fail]module=%s,fd=%d",
                         nstack_get_module_name_by_idx(modIdx), tfd);
            nstack_set_bind_ret(fdInf, modIdx, NSTACK_BIND_FAIL);
        }
    }

    if (-1 == fdInf->rd_item.stack_id)
    {
        nstack_set_errno(EINVAL);
        NSSOC_LOGERR("failed for no module selected]fd=%d", fd);
    }

  bind_over:
    if (ns_success == retval)
    {
        fdInf->isBound = 1;
    }
    NSSOC_LOGINF("appfd=%d,prot_fd=%d,rmidx=%d, retVal=%d [return]", fd,
                 fdInf->rlfd, fdInf->rmidx, retval);
    UNLOCK_COMMON(fd, fdInf, local_lock);
    return retval;
}

int nstack_listen(int fd, int backlog)
{
    nstack_fd_Inf *fdInf;
    int retval = -1;
    int tem = -1;
    int modIdx = 0;
    int tfd;
    int func_called = 0;

    NSTACK_INIT_CHECK_RET(listen, fd, backlog);

    NSSOC_LOGINF("(sockfd=%d, backlog=%d) [Caller]", fd, backlog);
    if (fd < 0)
    {
        nstack_set_errno(EBADF);
        NSSOC_LOGERR("invalid input]fd=%d,backlog=%d [return]", fd, backlog);
        return -1;
    }

    NSTACK_FD_LINUX_CHECK_RETURN(fd, listen, fdInf, (fd, backlog));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_COMMON(fd, fdInf, local_lock);

    NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_COMMON(fd, listen, fdInf, ENOTSOCK,
                                            local_lock);

    /*listen:use all mode we support */
    nstack_each_mod_inx(modIdx)
    {
        tfd = nstack_get_proto_fd(fdInf, modIdx);

        if ((-1 == tfd)
            || (NSTACK_BIND_FAIL == nstack_get_bind_ret(fdInf, modIdx)))
        {
            continue;
        }

        func_called = 1;
        NSTACK_CAL_FUN(nstack_module_ops(modIdx), listen, (tfd, backlog),
                       tem);
        if (ns_success == tem)
        {
            nstack_set_listen_state(fdInf, modIdx, NSTACK_LISENING);
            NSTACK_SET_FD_LISTEN_SOCKET(fdInf);
            retval = ns_success;
            nstack_set_listen_ret(fdInf, modIdx, NSTACK_LISTEN_SUCCESS);
        }
        else
        {
            NSSOC_LOGWAR("listen fail]fd=%d,module=%s,tfd=%d", fd,
                         nstack_get_module_name_by_idx(modIdx), tfd);
            nstack_set_listen_ret(fdInf, modIdx, NSTACK_LISTEN_FAIL);
            nstack_set_listen_state(fdInf, modIdx, NSTACK_NO_LISENING);
        }
    }

    if (0 == func_called)
    {
        retval = -1;
        nstack_set_errno(ENOSYS);
        NSSOC_LOGERR("listen fail for no module called]fd=%d", fd);
    }

    NSSOC_LOGINF("fd=%d,ret=%d [return]", fd, retval);
    UNLOCK_COMMON(fd, fdInf, local_lock);
    return retval;
}

int nstack_accept(int fd, struct sockaddr *addr, socklen_t * addr_len)
{
    nstack_fd_Inf *apstfdInf = NULL;
    int tfd = -1;
    int accfd = -1;
#ifdef KERNEL_FD_SUPPORT
    int kernelFD;
#endif
    int ret_fd = -1;
    nstack_fd_Inf *accInf;
    int ret = -1;

    NSTACK_INIT_CHECK_RET(accept, fd, addr, addr_len);

    NSSOC_LOGINF("(sockfd=%d, addr=%p, addrlen=%p) [Caller]", fd, addr,
                 addr_len);
    if (fd < 0)
    {
        nstack_set_errno(EBADF);
        NSSOC_LOGERR("fd is invalid]fd=%d [return]", fd);
        return -1;
    }
    NSTACK_FD_LINUX_CHECK_RETURN(fd, accept, apstfdInf, (fd, addr, addr_len));

    nstack_fd_local_lock_info_t *local_lock = &apstfdInf->local_lock;
    LOCK_ACCEPT(fd, apstfdInf, local_lock);

    NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_ACCEPT(fd, accept, apstfdInf, ENOTSOCK,
                                            local_lock);

    if (addr)
    {
        if ((!addr_len) || (*addr_len == NSTACK_MAX_U32_NUM))
        {
            nstack_set_errno(EINVAL);
            NSSOC_LOGERR("addr_len inpurt error [return]");
            UNLOCK_ACCEPT(fd, apstfdInf, local_lock);
            return -1;
        }
    }

    /*if no module select or listen / bind fail, just return fail */
    if ((!apstfdInf->ops)
        || (NSTACK_LISTEN_FAIL ==
            nstack_get_listen_ret(apstfdInf, apstfdInf->rmidx))
        || (NSTACK_BIND_FAIL ==
            nstack_get_bind_ret(apstfdInf, apstfdInf->rmidx)))
    {
        nstack_set_errno(EINVAL);
        NSSOC_LOGERR
            ("nstack accept fd=%d no mudle select, or bind/listen fail [return]",
             fd);
        UNLOCK_ACCEPT(fd, apstfdInf, local_lock);
        return -1;
    }
    tfd = nstack_get_proto_fd(apstfdInf, apstfdInf->rmidx);
    NSTACK_CAL_FUN(nstack_module_ops(apstfdInf->rmidx), accept,
                   (tfd, addr, addr_len), accfd);
    NSSOC_LOGINF("nstack fd=%d:%d accept fd=%d from module=%s", fd, tfd,
                 accfd, nstack_get_module_name_by_idx(apstfdInf->rmidx));
    if (-1 == accfd)
    {
        if (errno != EAGAIN)
        {
            NSSOC_LOGERR("appfd=%d,module=%s,ret=%d,errno=%d [return]", fd,
                         nstack_get_module_name_by_idx(apstfdInf->rmidx),
                         accfd, errno);
        }
        UNLOCK_ACCEPT(fd, apstfdInf, local_lock);
        return -1;
    }

#ifdef KERNEL_FD_SUPPORT
    // If it is not from kernel, need to create one kernel socket
    if (apstfdInf->rmidx != nstack_get_linux_mid())
    {
        /*err num is same with linux */
        kernelFD = nstack_create_kernel_socket();
        if (kernelFD < 0)
        {
            NSSOC_LOGERR
                ("nstack accept fd=%d return fd=%d kernelFD fd create fail [return]",
                 fd, accfd);
            NSTACK_CAL_FUN(nstack_module_ops(apstfdInf->rmidx), close,
                           (accfd), ret);
            UNLOCK_ACCEPT(fd, apstfdInf, local_lock);
            return -1;
        }
    }
    else
    {
        kernelFD = accfd;
    }

    if (kernelFD >= (int) NSTACK_KERNEL_FD_MAX)
    {
        /* nstack not support kernel fd >= NSTACK_MAX_SOCK_NUM.
         * close it and nstack_accept() return failed
         */
        NSSOC_LOGERR("kernelFD fd too big, close it. kernelFD=%d [return]",
                     accfd);

        NSTACK_CAL_FUN(nstack_module_ops(apstfdInf->rmidx), close, (accfd),
                       ret);
        if (apstfdInf->rmidx != nstack_get_linux_mid())
        {

            NSTACK_CAL_FUN(nstack_module_ops(nstack_get_linux_mid()),
                           close, (kernelFD), ret);
        }
        nstack_set_errno(EMFILE);
        UNLOCK_ACCEPT(fd, apstfdInf, local_lock);
        return -1;
    }

    nstack_fd_local_lock_info_t *lock_info = get_fd_local_lock_info(kernelFD);
    LOCK_FOR_EP(lock_info);

    accInf = nstack_lk_fd_alloc_with_kernel(kernelFD);
    ret_fd = kernelFD;
#else
    accInf = nstack_lk_fd_alloc_without_kernel();
#endif

    if (NULL == accInf)
    {
        NSSOC_LOGERR("Can't alloc nstack fdInf [return]");

        NSTACK_CAL_FUN(nstack_module_ops(apstfdInf->rmidx), close, (accfd),
                       ret);
#ifdef KERNEL_FD_SUPPORT
        if (apstfdInf->rmidx != nstack_get_linux_mid())
        {

            NSTACK_CAL_FUN(nstack_module_ops(nstack_get_linux_mid()),
                           close, (kernelFD), ret);
        }
        UNLOCK_FOR_EP(lock_info);
#endif
        nstack_set_errno(EMFILE);
        UNLOCK_ACCEPT(fd, apstfdInf, local_lock);

        return -1;
    }

#ifndef KERNEL_FD_SUPPORT
    nstack_fd_local_lock_info_t *lock_info =
        get_fd_local_lock_info(accInf->fd);
    ret_fd = accInf->fd;
    LOCK_FOR_EP(lock_info);
#endif

    nstack_set_routed_fd(accInf, accfd);        /*do not need return value */
    accInf->ops = nstack_module_ops(apstfdInf->rmidx);
    /*donot include SOCK_CLOEXEC SOCK_NONBLOCK */
    accInf->type =
        apstfdInf->type &
        (~((ns_int32) SOCK_CLOEXEC | (ns_int32) SOCK_NONBLOCK));
    nstack_set_router_protocol(accInf, apstfdInf->rmidx);       /*do not need return value */
    nstack_set_proto_fd(accInf, apstfdInf->rmidx, accfd);
    nstack_set_app_info(accInf, apstfdInf->rmidx);
    /* Set the linux kernel fd also in accInf for kernel module (0) */
#ifdef KERNEL_FD_SUPPORT
    if (apstfdInf->rmidx != nstack_get_linux_mid())
    {
        nstack_set_proto_fd(accInf, nstack_get_linux_mid(), kernelFD);
    }
#endif
    NSSOC_LOGINF
        ("listenfd=%d,acceptfd=%d,module=%s(rlfd=%d),ret=%d [return]", fd,
         ret_fd, nstack_get_module_name_by_idx(apstfdInf->rmidx), accfd,
         ret_fd);

    set_fd_status_lock_fork(ret_fd, FD_OPEN);
    UNLOCK_FOR_EP(lock_info);
    UNLOCK_ACCEPT(fd, apstfdInf, local_lock);
    return ret_fd;
}

int nstack_accept4(int fd, struct sockaddr *addr,
                   socklen_t * addr_len, int flags)
{
    nstack_fd_Inf *pstfdInf = NULL;
    int tfd = -1;
    int accfd = -1;
#ifdef KERNEL_FD_SUPPORT
    int kernelFD = -1;
#endif
    int ret_fd = -1;
    int ret = -1;
    nstack_fd_Inf *accInf;

    NSTACK_INIT_CHECK_RET(accept4, fd, addr, addr_len, flags);

    NSSOC_LOGINF("(sockfd=%d, addr=%p, addrlen=%p, flags=%d) [Caller]", fd,
                 addr, addr_len, flags);
    if (fd < 0)
    {
        nstack_set_errno(EBADF);
        NSSOC_LOGERR("nstack accept4,fd=%d invalid [return]", fd);
        return -1;
    }
    NSTACK_FD_LINUX_CHECK_RETURN(fd, accept4, pstfdInf,
                                 (fd, addr, addr_len, flags));

    nstack_fd_local_lock_info_t *local_lock = &pstfdInf->local_lock;
    LOCK_ACCEPT(fd, pstfdInf, local_lock);

    NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_ACCEPT(fd, accept4, pstfdInf, ENOTSOCK,
                                            local_lock);

    if (addr)
    {
        if ((!addr_len) || (*addr_len == NSTACK_MAX_U32_NUM))
        {
            nstack_set_errno(EINVAL);
            NSSOC_LOGERR("nstack accept4 addr_len inpurt error [return]");
            UNLOCK_ACCEPT(fd, pstfdInf, local_lock);
            return -1;
        }
    }

    /*if no module select or listen / bind fail, just return fail */
    if ((!pstfdInf->ops)
        || (NSTACK_LISTEN_FAIL ==
            nstack_get_listen_ret(pstfdInf, pstfdInf->rmidx))
        || (NSTACK_BIND_FAIL ==
            nstack_get_bind_ret(pstfdInf, pstfdInf->rmidx)))
    {
        nstack_set_errno(EINVAL);
        NSSOC_LOGERR
            ("nstack accept4 fd:%d no mudle select, or bind/listen fail [return]",
             fd);
        UNLOCK_ACCEPT(fd, pstfdInf, local_lock);
        return -1;
    }

    tfd = nstack_get_proto_fd(pstfdInf, pstfdInf->rmidx);
    NSTACK_CAL_FUN(nstack_module_ops(pstfdInf->rmidx), accept4,
                   (tfd, addr, addr_len, flags), accfd);
    if (-1 == accfd)
    {
        if (errno != EAGAIN)
        {
            NSSOC_LOGERR("appfd=%d,module=%s,ret=%d,errno=%d [return]", fd,
                         nstack_get_module_name_by_idx(pstfdInf->rmidx),
                         accfd, errno);
        }
        UNLOCK_ACCEPT(fd, pstfdInf, local_lock);
        return -1;
    }

#ifdef KERNEL_FD_SUPPORT
    // If it is not from kernel, need to create one kernel socket
    if (pstfdInf->rmidx != nstack_get_linux_mid())
        kernelFD = nstack_create_kernel_socket();
    else
        kernelFD = accfd;

    if (!nstack_is_nstack_sk(kernelFD))
    {
        /* nstack not support kernel fd >= NSTACK_MAX_SOCK_NUM.
         * close it and nstack_accept() return failed
         */
        NSSOC_LOGERR
            ("nstack accept4 fd=%d kernelFD fd too big, close it. kernelFD=%d [return]",
             fd, kernelFD);

        if (kernelFD >= 0)
            NSTACK_CAL_FUN(nstack_module_ops(pstfdInf->rmidx), close,
                           (accfd), ret);

        if (pstfdInf->rmidx != nstack_get_linux_mid())
        {

            NSTACK_CAL_FUN(nstack_module_ops(nstack_get_linux_mid()),
                           close, (kernelFD), ret);
        }
        nstack_set_errno(EMFILE);
        UNLOCK_ACCEPT(fd, pstfdInf, local_lock);
        return -1;
    }

    nstack_fd_local_lock_info_t *lock_info = get_fd_local_lock_info(kernelFD);
    LOCK_FOR_EP(lock_info);
    accInf = nstack_lk_fd_alloc_with_kernel(kernelFD);
    ret_fd = kernelFD;
#else
    accInf = nstack_lk_fd_alloc_without_kernel();
#endif

    if (NULL == accInf)
    {

        NSTACK_CAL_FUN(nstack_module_ops(pstfdInf->rmidx), close, (accfd),
                       ret);
#ifdef KERNEL_FD_SUPPORT
        if (pstfdInf->rmidx != nstack_get_linux_mid())
        {

            NSTACK_CAL_FUN(nstack_module_ops(nstack_get_linux_mid()),
                           close, (kernelFD), ret);
        }
        UNLOCK_FOR_EP(lock_info);
#endif
        NSSOC_LOGERR("nstack accept fd alloc is NULL [return]");
        UNLOCK_ACCEPT(fd, pstfdInf, local_lock);
        return -1;
    }

#ifndef KERNEL_FD_SUPPORT
    nstack_fd_local_lock_info_t *lock_info =
        get_fd_local_lock_info(accInf->fd);
    ret_fd = accInf->fd;
    LOCK_FOR_EP(lock_info);
#endif

    nstack_set_routed_fd(accInf, accfd);        /*do not need return value */
    accInf->ops = nstack_module_ops(pstfdInf->rmidx);
    accInf->type =
        (pstfdInf->type &
         (~((ns_int32) SOCK_CLOEXEC | (ns_int32) SOCK_NONBLOCK))) | (ns_int32)
        flags;
    nstack_set_router_protocol(accInf, pstfdInf->rmidx);        /*do not need return value */
    nstack_set_proto_fd(accInf, pstfdInf->rmidx, accfd);
    nstack_set_app_info(accInf, pstfdInf->rmidx);
#ifdef KERNEL_FD_SUPPORT
    /* Set the linux kernel fd also in accInf for kernel module (0) */
    if (pstfdInf->rmidx != nstack_get_linux_mid())
    {
        nstack_set_proto_fd(accInf, nstack_get_linux_mid(), kernelFD);
    }
#endif
    NSSOC_LOGINF
        ("listenfd=%d,acceptfd=%d,accInf->fd=%d,module=%s(rlfd:%d),ret=%d [return]",
         fd, ret_fd, accInf->fd,
         nstack_get_module_name_by_idx(pstfdInf->rmidx), accfd, ret_fd);
    set_fd_status_lock_fork(ret_fd, FD_OPEN);
    UNLOCK_FOR_EP(lock_info);
    UNLOCK_ACCEPT(fd, pstfdInf, local_lock);
    return ret_fd;
}

int nstack_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    int retval = -1;
    nstack_fd_Inf *fdInf;
    struct sockaddr_in *iaddr = (struct sockaddr_in *) addr;

    NSTACK_INIT_CHECK_RET(connect, fd, addr, addrlen);

    NSSOC_LOGINF("(sockfd=%d, addr=%p, addrlen=%u) [Caller]", fd, addr,
                 addrlen);

    if (fd < 0)
    {
        nstack_set_errno(EBADF);
        NSSOC_LOGERR
            ("nstack connect, fd=%d invalid input: addr=%p,len=0x%x [return]",
             fd, addr, addrlen);
        return -1;
    }
    if ((NULL == addr) || (addrlen < 2))
    {
        nstack_set_errno(EINVAL);
        NSSOC_LOGERR
            ("nstack connect, fd=%d invalid input: addr=%p,len=0x%x [return]",
             fd, addr, addrlen);
        return -1;
    }

    /* avoid access to iaddr memory */
    /* miss the condition about sockaddr_un,and get wrong value */
    if ((addrlen >= sizeof(struct sockaddr_in))
        && ((addr->sa_family) == AF_INET))
    {
        NSSOC_LOGINF("fd=%d,addr=*.*.%u.%u,port=%d", fd,
                     FUZZY_IP_VAR(&iaddr->sin_addr), ntohs(iaddr->sin_port));
    }
    else if ((addrlen >= sizeof(struct sockaddr_in6))
             && ((addr->sa_family) == AF_INET6))
    {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
        NSSOC_LOGINF("fd=%d,addr=%s,port=%u", fd,
                     inet6_ntoa(&addr6->sin6_addr), htons(addr6->sin6_port));
    }
    else
    {
        NSSOC_LOGINF("addrlen = %d ,fd=%d", (int) addrlen, fd);
    }

    /* need check addrlen's validity, will visite iaddr->sin_addr.s_addr following code,for visite iaddr->sin_addr.s_addr is 8 byte  */
    if (addrlen < 8)
    {
        nstack_set_errno(EINVAL);
        NSSOC_LOGERR
            ("nstack connect, fd=%d invalid addrlen input: addr=%p,len=0x%x [return]",
             fd, addr, addrlen);
        return -1;
    }

    if (addr->sa_family == AF_INET)
    {
        if (addrlen < sizeof(struct sockaddr_in))
        {
            /* sa family is always AF_INET */
            NSSOC_LOGERR
                ("nstack connect, fd=%d family=AF_INET invalid size: %d [return]",
                 fd, addrlen);
            nstack_set_errno(EINVAL);
            return -1;
        }
        if (NSTACK_ANY_IP == iaddr->sin_addr.s_addr)    /*no need to check null pointer */
        {
            nstack_set_errno(ECONNREFUSED);
            NSSOC_LOGERR
                ("nstack connect, fd=%d invalid input: 0==addr_in->sin_addr.s_addr [return]",
                 fd);
            return -1;
        }
        else if (NSTACK_MAX_U32_NUM == iaddr->sin_addr.s_addr)  /*no need to check null pointer */
        {
            nstack_set_errno(ENETUNREACH);
            NSSOC_LOGERR
                ("nstack connect, fd=%d invalid input: 0xffffffff==addr_in->sin_addr.s_addr [return]",
                 fd);
            return -1;
        }
    }
    else if (addr->sa_family == AF_INET6)
    {
        if (addrlen < sizeof(struct sockaddr_in6))
        {
            NSSOC_LOGERR
                ("nstack connect, fd=%d family=AF_INET6 invalid size: %d [return]",
                 fd, addrlen);
            nstack_set_errno(EINVAL);
            return -1;
        }

        if (IN6_IS_ADDR_UNSPECIFIED
            (&((const struct sockaddr_in6 *) addr)->sin6_addr))
        {
            nstack_set_errno(ECONNREFUSED);
            NSSOC_LOGERR
                ("nstack connect, fd=%d invalid input: 0==addr_in->sin6_addr [return]",
                 fd);
            return -1;
        }
    }

    NSTACK_FD_LINUX_CHECK_RETURN(fd, connect, fdInf, (fd, addr, addrlen));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_CONNECT(fd, fdInf, local_lock);

    NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_CONNECT(fd, connect, fdInf, ENOTSOCK, local_lock); /*do not need return value */

    /*if no module select, according to dest ip */
    if (!fdInf->ops)
    {
        retval = nstack_socket_get_stackid(fdInf, addr, addrlen);
        if (ns_success == retval && fdInf->rd_item.stack_id != -1)
        {
            NSSOC_LOGINF("fd=%d addr=%s Select module=%s, rd_opt=%d", fd,
                         inet_ntoa_x(addr),
                         nstack_get_module_name_by_idx(fdInf->
                                                       rd_item.stack_id),
                         fdInf->rd_opt);
            /*in case of that multi-thread connect. if route was chosed by one thread, the other just use the first one */
            fdInf->rmidx = fdInf->rd_item.stack_id;
            fdInf->ops = nstack_module_ops(fdInf->rd_item.stack_id);
            nstack_set_routed_fd(fdInf, nstack_get_proto_fd(fdInf, fdInf->rd_item.stack_id));   /*do not need return value */
            nstack_set_router_protocol(fdInf, fdInf->rd_item.stack_id); /*do not need return value */
        }
        else
        {
            NSSOC_LOGERR
                ("fd=%d Callback select module=%d rd_opt=%d, ret=0x%x", fd,
                 fdInf->rd_item.stack_id, fdInf->rd_opt, retval);
            nstack_set_errno(ENETUNREACH);
            UNLOCK_CONNECT(fd, fdInf, local_lock);
            return -1;
        }
    }

    NSTACK_CAL_FUN(fdInf->ops, connect, (fdInf->rlfd, addr, addrlen), retval);
    if (-1 == retval && errno != EINPROGRESS)
    {
        NSSOC_LOGERR
            ("appfd=%d,module=%s,proto_fd=%d,ret=%d,errno=%d [return]", fd,
             nstack_get_module_name_by_idx(fdInf->rmidx), fdInf->rlfd,
             retval, errno);
    }
    else
    {
        NSSOC_LOGINF
            ("appfd=%d,module=%s,proto_fd=%d,ret=%d,errno=%d [return]", fd,
             nstack_get_module_name_by_idx(fdInf->rmidx), fdInf->rlfd,
             retval, errno);
    }
    UNLOCK_CONNECT(fd, fdInf, local_lock);
    return retval;
}

int nstack_shutdown(int fd, int how)
{
    nstack_fd_Inf *fdInf = NULL;
    int retval = -1;
    int tfd;

    if (fd < 0)
    {
        nstack_set_errno(EBADF);
        NSSOC_LOGERR("fd=%d invalid input [return]", fd);
        return -1;
    }

    NSTACK_INIT_CHECK_RET(shutdown, fd, how);

    /*  begin fork will close all fd(dont create by nstack) in continure,
       which cause lots of log, here remove the log output */
    NSSOC_LOGINF("(fd=%d, how=%d) [Caller]", fd, how);

    NSTACK_FD_LINUX_CHECK_RETURN(fd, shutdown, fdInf, (fd, how));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_COMMON(fd, fdInf, local_lock);

    NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_COMMON(fd, shutdown, fdInf, ENOTSOCK,
                                            local_lock);

    if (!fdInf->ops || -1 == fdInf->rlfd)
    {
        NSSOC_LOGWAR("fd=%d,how=%d, shutdown fail [return]", fd, how);
        nstack_set_errno(ENOTCONN);
        UNLOCK_COMMON(fd, fdInf, local_lock);
        return -1;
    }
    tfd = fdInf->rlfd;
    NSTACK_CAL_FUN(fdInf->ops, shutdown, (tfd, how), retval);
    if ((-1 == retval) && (fdInf->rmidx != nstack_get_linux_mid()))
    {
        NSSOC_LOGWAR("fd=%d,ret=%d [return]", fd, retval);
    }
    else
    {
        NSSOC_LOGINF("fd=%d,ret=%d [return]", fd, retval);
    }
    UNLOCK_COMMON(fd, fdInf, local_lock);
    return retval;
}

int release_fd(int fd, nstack_fd_local_lock_info_t * local_lock)
{
    nstack_fd_Inf *fdInf = NULL;
    nstack_module *pMod = NULL;
#ifdef KERNEL_FD_SUPPORT
    int retval = -1;
#else
    int retval = 0;
#endif
    int curRet = -1;
    int modInx, tfd;

    if (!local_lock)
    {
        return -1;
    }

    LOCK_CLOSE(local_lock);

    /* if fd is used by others, just pass, delay close it */
    if (local_lock->fd_status != FD_CLOSING || local_lock->fd_ref.counter > 0)
    {
        UNLOCK_CLOSE(local_lock);
        return 0;
    }
    local_lock->fd_status = FD_CLOSE;

    fdInf = nstack_fd2inf(fd);
    if (NULL == fdInf)
    {
        nstack_set_errno(EINVAL);
        NSSOC_LOGERR("pstfdInf is NULL");
        UNLOCK_CLOSE(local_lock);
        return -1;
    }

    (void) nsep_epoll_close(fd);

    nstack_each_module(modInx, pMod)
    {
        tfd = nstack_get_proto_fd(fdInf, modInx);

        /*  add tfd rang check */
        if (nstack_get_minfd_id(modInx) > tfd
            || tfd > nstack_get_maxfd_id(modInx))
        {
            continue;
        }

        NSSOC_LOGINF("fd=%d,module=%s,tfd=%d", fd,
                     nstack_get_module_name_by_idx(modInx), tfd);

#ifdef KERNEL_FD_SUPPORT
        if (0 ==
            strcmp(RD_KERNEL_NAME, nstack_get_module_name_by_idx(modInx)))
        {
            if (!(tfd >= 3 && tfd < (int) NSTACK_KERNEL_FD_MAX))
            {
                NSSOC_LOGERR("tfd is out of scope]tfd=%d", tfd);
                /*  should release lock in this error branch */
                UNLOCK_CLOSE(local_lock);
                return -1;
            }

            /* should release resource for kernel */
            continue;
        }
#endif

        nssct_close(fd, modInx);        /*do not need return value */
        NSTACK_CAL_FUN((&pMod->ops), close, (tfd), curRet);

        if (-1 == curRet)
        {
            NSSOC_LOGERR("failed]module=%s,tfd=%d,errno=%d",
                         nstack_get_module_name_by_idx(modInx), tfd, errno);
        }

#ifdef KERNEL_FD_SUPPORT
        retval &= curRet;
#else
        retval |= curRet;
#endif
    }
#ifdef KERNEL_FD_SUPPORT
    retval &= nstack_fd_free_with_kernel(fdInf);
    if (-1 == retval)
    {
        NSSOC_LOGWAR("fd=%d,ret=%d [return]", fd, retval);
    }
    else
    {
        NSSOC_LOGINF("fd=%d,ret=%d [return]", fd, retval);
    }
#else
    nstack_fd_free(fdInf);
#endif

    UNLOCK_CLOSE(local_lock);
    return retval;
}

/*not support fork now,  to support fork the module must provide gfdt & refer cnt
  while fork the frame use callback fun to add refer*/
/*vars are used in macro*/
int nstack_close(int fd)
{
    nstack_fd_Inf *fdInf;
    int modInx = 0;
    int ret = -1;

    NSTACK_INIT_CHECK_RET(close, fd);

#ifdef KERNEL_FD_SUPPORT
    /*linux fd check */
    if (!(fdInf = nstack_get_valid_inf(fd)))
    {
        if (fd != nsep_get_manager()->checkEpollFD)
        {
            /*free epoll resouce */
            nsep_epoll_close(fd);       /*do not need return value */
            nssct_close(fd, nstack_get_linux_mid());    /*do not need return value */

            return nsfw_base_close(fd);
        }
        nstack_set_errno(ENOSYS);
        return -1;
    }
#else
    NSTACK_FD_LINUX_CHECK_RETURN(fd, close, fdInf, (fd));
#endif

    NSSOC_LOGINF("Caller]fd=%d", fd);

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_CLOSE(local_lock);
    if (local_lock->fd_status != FD_OPEN)
    {
        NSSOC_LOGERR("return]fd_status=%d,fd=%d", local_lock->fd_status, fd);
        nstack_set_errno(EBADF);
        UNLOCK_CLOSE(local_lock);
        return -1;
    }

    set_fd_status_lock_fork(fd, FD_CLOSING);

    /* add fdInf->rlfd and  fdInf->ops's validity check,avoid
       print error log in normal scenario */
    if (NSTACK_IS_FD_ATTR(fdInf, fdInf->rd_item.type_data.attr)
        && (-1 != fdInf->rlfd) && fdInf->ops)
    {
        nstack_each_mod_inx(modInx)
        {
            if (nstack_fd_deal[modInx].set_close_stat)
            {
                nstack_fd_deal[modInx].set_close_stat(fdInf->rlfd,
                                                      FD_CLOSING);
            }
        }
    }

    UNLOCK_CLOSE(local_lock);
    ret =
        (atomic_dec(&local_lock->fd_ref) >
         0 ? 0 : release_fd(fd, local_lock));

    if (-1 == ret)
    {
        NSSOC_LOGWAR("return]fd=%d,retVal=%d", fd, ret);
    }
    else
    {
        NSSOC_LOGINF("return]fd=%d,retVal=%d", fd, ret);
    }

    return ret;
}

ssize_t nstack_send(int fd, const void *buf, size_t len, int flags)
{
    nstack_fd_Inf *fdInf = NULL;
    ssize_t size = -1;

    NSTACK_INIT_CHECK_RET(send, fd, buf, len, flags);

    NS_LOG_CTRL(LOG_CTRL_SEND, NSOCKET, "SOC", NSLOG_DBG,
                "sockfd=%d,buf=%p,len=%zu,flags=%d[Caller]", fd, buf, len,
                flags);

    NSTACK_FD_LINUX_CHECK_RETURN(fd, send, fdInf, (fd, buf, len, flags));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_SEND(fd, fdInf, local_lock);

    NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_SEND(fd, send, fdInf, ENOTSOCK,
                                          local_lock);

    if ((!fdInf->ops) || (-1 == fdInf->rlfd))
    {
        NSSOC_LOGINF("fd Fail: Not select any module yet]fd=%d[return]", fd);
        nstack_set_errno(ENOTCONN);
        UNLOCK_SEND(fd, fdInf, local_lock);
        return -1;
    }

    nstack_fd_dfx_update_dfx_data(fd, fdInf->rlfd, fdInf->rmidx,
                                  DMM_STAT_LONGEST_SEND_INTERVAL, NULL);
    NSTACK_CAL_FUN(fdInf->ops, send, (fdInf->rlfd, buf, len, flags), size);

    NSSOC_LOGDBG("fd=%d,ret=%zd[Return]", fd, size);
    UNLOCK_SEND(fd, fdInf, local_lock);
    return size;
}

ssize_t nstack_recv(int fd, void *buf, size_t len, int flags)
{
    nstack_fd_Inf *fdInf = NULL;
    ssize_t size = -1;

    NSTACK_INIT_CHECK_RET(recv, fd, buf, len, flags);

    NS_LOG_CTRL(LOG_CTRL_RECV, NSOCKET, "SOC", NSLOG_DBG,
                "sockfd=%d,buf=%p,len=%zu,flags=%d[Caller]", fd, buf, len,
                flags);

    NSTACK_FD_LINUX_CHECK_RETURN(fd, recv, fdInf, (fd, buf, len, flags));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_RECV(fd, fdInf, local_lock);

    NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_RECV(fd, recv, fdInf, ENOTSOCK,
                                          local_lock);

    if ((!fdInf->ops) || (-1 == fdInf->rlfd))
    {
        NSSOC_LOGINF("Not select any module yet]fd=%d[Return]", fd);
        nstack_set_errno(ENOTCONN);
        UNLOCK_RECV(fd, fdInf, local_lock);
        return -1;
    }

    nstack_fd_dfx_update_dfx_data(fd, fdInf->rlfd, fdInf->rmidx,
                                  DMM_STAT_LONGEST_RECV_INTERVAL, NULL);
    NSTACK_CAL_FUN(fdInf->ops, recv, (fdInf->rlfd, buf, len, flags), size);

    NSSOC_LOGDBG("fd=%d,ret=%zd[Return]", fd, size);

    UNLOCK_RECV(fd, fdInf, local_lock);
    return size;
}

ssize_t nstack_write(int fd, const void *buf, size_t count)
{
    nstack_fd_Inf *fdInf = NULL;
    ssize_t size = -1;

    NSTACK_INIT_CHECK_RET(write, fd, buf, count);

    NSTACK_FD_LINUX_CHECK_RETURN(fd, write, fdInf, (fd, buf, count));
    NS_LOG_CTRL(LOG_CTRL_WRITE, NSOCKET, "SOC", NSLOG_DBG,
                "fd=%d,buf=%p,count=%zu[Caller]", fd, buf, count);

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_SEND(fd, fdInf, local_lock);

    NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_SEND(fd, write, fdInf, EINVAL,
                                          local_lock);

    if ((!fdInf->ops) || (-1 == fdInf->rlfd))
    {
        NSSOC_LOGINF("Not select any module yet]fd=%d[Return]", fd);
        nstack_set_errno(ENOTCONN);
        UNLOCK_SEND(fd, fdInf, local_lock);
        return -1;
    }

    nstack_fd_dfx_update_dfx_data(fd, fdInf->rlfd, fdInf->rmidx,
                                  DMM_STAT_LONGEST_SEND_INTERVAL, NULL);
    NSTACK_CAL_FUN(fdInf->ops, write, (fdInf->rlfd, buf, count), size);

    NSSOC_LOGDBG("fd=%d,ret=%zd[Return]", fd, size);

    UNLOCK_SEND(fd, fdInf, local_lock);
    return size;
}

ssize_t nstack_read(int fd, void *buf, size_t count)
{
    nstack_fd_Inf *fdInf = NULL;
    ssize_t size = -1;

    NSTACK_INIT_CHECK_RET(read, fd, buf, count);

    NS_LOG_CTRL(LOG_CTRL_READ, NSOCKET, "SOC", NSLOG_DBG,
                "fd=%d,buf=%p,count=%zu[Caller]", fd, buf, count);

    NSTACK_FD_LINUX_CHECK_RETURN(fd, read, fdInf, (fd, buf, count));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_RECV(fd, fdInf, local_lock);

    NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_RECV(fd, read, fdInf, EINVAL,
                                          local_lock);

    if ((!fdInf->ops) || (-1 == fdInf->rlfd))
    {
        NSSOC_LOGINF("Not select any module yet]fd=%d[Return]", fd);
        nstack_set_errno(ENOTCONN);
        UNLOCK_RECV(fd, fdInf, local_lock);
        return -1;
    }

    nstack_fd_dfx_update_dfx_data(fd, fdInf->rlfd, fdInf->rmidx,
                                  DMM_STAT_LONGEST_RECV_INTERVAL, NULL);
    NSTACK_CAL_FUN(fdInf->ops, read, (fdInf->rlfd, buf, count), size);

    NSSOC_LOGDBG("fd=%d,ret=%zd[Return]", fd, size);

    UNLOCK_RECV(fd, fdInf, local_lock);
    return size;
}

ssize_t nstack_writev(int fd, const struct iovec * iov, int iovcnt)
{
    nstack_fd_Inf *fdInf = NULL;
    ssize_t size = -1;

    NSTACK_INIT_CHECK_RET(writev, fd, iov, iovcnt);

    NS_LOG_CTRL(LOG_CTRL_WRITEV, NSOCKET, "SOC", NSLOG_DBG,
                "fd=%d,iov=%p,count=%d[Caller]", fd, iov, iovcnt);

    NSTACK_FD_LINUX_CHECK_RETURN(fd, writev, fdInf, (fd, iov, iovcnt));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_SEND(fd, fdInf, local_lock);

    NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_SEND(fd, writev, fdInf, EINVAL,
                                          local_lock);

    if ((!fdInf->ops) || (-1 == fdInf->rlfd))
    {
        NSSOC_LOGERR("Not select any module yet]fd=%d[Return]", fd);
        nstack_set_errno(ENOTCONN);
        UNLOCK_SEND(fd, fdInf, local_lock);
        return -1;
    }

    nstack_fd_dfx_update_dfx_data(fd, fdInf->rlfd, fdInf->rmidx,
                                  DMM_STAT_LONGEST_SEND_INTERVAL, NULL);
    NSTACK_CAL_FUN(fdInf->ops, writev, (fdInf->rlfd, iov, iovcnt), size);

    NSSOC_LOGDBG("fd=%d,ret=%zd[Return]", fd, size);

    UNLOCK_SEND(fd, fdInf, local_lock);
    return size;
}

ssize_t nstack_readv(int fd, const struct iovec * iov, int iovcnt)
{
    nstack_fd_Inf *fdInf = NULL;
    ssize_t size = -1;

    NSTACK_INIT_CHECK_RET(readv, fd, iov, iovcnt);

    NS_LOG_CTRL(LOG_CTRL_READV, NSOCKET, "SOC", NSLOG_DBG,
                "fd=%d,iov=%p,count=%d[Caller]", fd, iov, iovcnt);

    NSTACK_FD_LINUX_CHECK_RETURN(fd, readv, fdInf, (fd, iov, iovcnt));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_RECV(fd, fdInf, local_lock);

    NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_RECV(fd, readv, fdInf, EINVAL,
                                          local_lock);

    if ((!fdInf->ops) || (-1 == fdInf->rlfd))
    {
        NSSOC_LOGERR("Not select any module yet]fd=%d [Return]", fd);
        nstack_set_errno(ENOTCONN);
        UNLOCK_RECV(fd, fdInf, local_lock);
        return -1;
    }

    nstack_fd_dfx_update_dfx_data(fd, fdInf->rlfd, fdInf->rmidx,
                                  DMM_STAT_LONGEST_RECV_INTERVAL, NULL);
    NSTACK_CAL_FUN(fdInf->ops, readv, (fdInf->rlfd, iov, iovcnt), size);

    NSSOC_LOGDBG("fd=%d,ret=%zd[Return]", fd, size);

    UNLOCK_RECV(fd, fdInf, local_lock);
    return size;
}

/*we assumed that the connect allready called, if not call, we must try many sok*/
ssize_t nstack_sendto(int fd, const void *buf, size_t len, int flags,
                      const struct sockaddr * dest_addr, socklen_t addrlen)
{
    nstack_fd_Inf *fdInf = NULL;
    ssize_t size = -1;
    int retval = 0;

    ns_udp_route_Inf udp_route_info;

    NSTACK_INIT_CHECK_RET(sendto, fd, buf, len, flags, dest_addr, addrlen);

    NSSOC_LOGDBG
        ("sockfd=%d, buf=%p,len=%zu,flags=%d,dest_addr=%p,addrlen=%u[Caller]",
         fd, buf, len, flags, dest_addr, addrlen);

    NSTACK_FD_LINUX_CHECK_RETURN(fd, sendto, fdInf,
                                 (fd, buf, len, flags, dest_addr, addrlen));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_SEND(fd, fdInf, local_lock);

    NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_SEND(fd, sendto, fdInf, ENOTSOCK,
                                          local_lock);

    if (fdInf->ops)
    {
        nstack_fd_dfx_update_dfx_data(fd, fdInf->rlfd, fdInf->rmidx,
                                      DMM_STAT_LONGEST_SEND_INTERVAL, NULL);
        NSTACK_CAL_FUN(fdInf->ops, sendto,
                       (fdInf->rlfd, buf, len, flags, dest_addr, addrlen),
                       size);

        NSSOC_LOGDBG
            ("fdInf->ops]fd=%d buf=%p,len=%zu,size=%zd,addr=%p[Return]", fd,
             buf, len, size, dest_addr);
        UNLOCK_SEND(fd, fdInf, local_lock);
        return size;
    }
    /*invalid ip, just return */
    /* add validity check for addrlen: for visite iaddr->sin_addr.s_addr is 8 byte */
    if ((NULL == dest_addr) || (addrlen < 8))
    {
        nstack_set_errno(EINVAL);
        NSSOC_LOGERR("invalid input]fd=%d,buf=%p,len=%zu,addr=%p[Return]",
                     fd, buf, len, dest_addr);
        UNLOCK_SEND(fd, fdInf, local_lock);
        return -1;
    }

    retval = nstack_socket_get_stackid(fdInf, dest_addr, addrlen);

    if ((ns_success == retval) && (fdInf->rd_item.stack_id != -1))
    {
        NSSOC_LOGINF("fd=%d,addr=%s,select_module=%s, rd_opt=%d", fd,
                     inet_ntoa_x(dest_addr),
                     nstack_get_module_name_by_idx(fdInf->rd_item.stack_id),
                     fdInf->rd_opt);
        fdInf->rmidx = fdInf->rd_item.stack_id;
        nstack_set_routed_fd(fdInf,
                             nstack_get_proto_fd(fdInf,
                                                 fdInf->rd_item.stack_id));
        nstack_set_router_protocol(fdInf, fdInf->rd_item.stack_id);
        fdInf->ops = nstack_module_ops(fdInf->rd_item.stack_id);

        udp_route_info.iaddr = *(struct sockaddr_in *) dest_addr;
        udp_route_info.selectmod = fdInf->rd_item.stack_id;
        nstack_fd_dfx_update_dfx_data(fd, fdInf->rlfd, fdInf->rmidx,
                                      DMM_STAT_ROUTE_INFO, &udp_route_info);

    }
    else
    {
        NSSOC_LOGERR("fd=%d Callback select module=%d, rd_opt=%d, ret=0x%x",
                     fd, fdInf->rd_item.stack_id, fdInf->rd_opt, retval);
        nstack_set_errno(ENETUNREACH);
        UNLOCK_SEND(fd, fdInf, local_lock);
        return -1;
    }

    NSSOC_LOGDBG("fd=%d,addr=%s,select_module=%s,rd_opt=%d", fd,
                 inet_ntoa_x(dest_addr),
                 nstack_get_module_name_by_idx(fdInf->rd_item.stack_id),
                 fdInf->rd_opt);

    nstack_fd_dfx_update_dfx_data(fd, fdInf->rlfd, fdInf->rmidx,
                                  DMM_STAT_LONGEST_SEND_INTERVAL, NULL);
    NSTACK_CAL_FUN(fdInf->ops, sendto,
                   (fdInf->rlfd, buf, len, flags, dest_addr, addrlen), size);

    NSSOC_LOGDBG("fd=%d,module=%s,ret=%d[Return]", fd,
                 nstack_get_module_name_by_idx(fdInf->rmidx), size);

    UNLOCK_SEND(fd, fdInf, local_lock);
    return size;
}

ssize_t nstack_sendmsg(int fd, const struct msghdr * msg, int flags)
{
    nstack_fd_Inf *fdInf = NULL;
    ssize_t size = -1;
    struct sockaddr *addr = NULL;
    int retval = 0;

    NSTACK_INIT_CHECK_RET(sendmsg, fd, msg, flags);

    NS_LOG_CTRL(LOG_CTRL_SENDMSG, NSOCKET, "SOC", NSLOG_DBG,
                "sockfd=%d,msg=%p,flags=%d[Caller]", fd, msg, flags);

    if (NULL == msg)
    {
        nstack_set_errno(EINVAL);
        NSSOC_LOGERR("invalid input]fd=%d,msg=%p[Return]", fd, msg);
        return -1;
    }

    NSTACK_FD_LINUX_CHECK_RETURN(fd, sendmsg, fdInf, (fd, msg, flags));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_SEND(fd, fdInf, local_lock);

    NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_SEND(fd, sendmsg, fdInf, ENOTSOCK,
                                          local_lock);

    /*if some module select, just connect */
    if (fdInf->ops)
    {
        nstack_fd_dfx_update_dfx_data(fd, fdInf->rlfd, fdInf->rmidx,
                                      DMM_STAT_LONGEST_SEND_INTERVAL, NULL);
        NSTACK_CAL_FUN(fdInf->ops, sendmsg, (fdInf->rlfd, msg, flags), size);

        NSSOC_LOGDBG("]fd=%d,size=%zd msg=%p[Return]", fd, size, msg);
        UNLOCK_SEND(fd, fdInf, local_lock);
        return size;
    }

    /* add validity check for msg->msg_namelen,for visite iaddr->sin_addr.s_addr is 8 byte  */
    addr = (struct sockaddr *) msg->msg_name;
    if ((fdInf->rd_opt != -1) || ((NULL != addr) && (msg->msg_namelen >= 8)))
    {
        retval = nstack_socket_get_stackid(fdInf, addr, msg->msg_namelen);
        if (ns_success == retval && fdInf->rd_item.stack_id != -1)
        {
            if (NULL != addr)
            {
                NSSOC_LOGINF("fd=%d,addr=%s,select_module=%s, rd_opt=%d", fd,
                             inet_ntoa_x(addr),
                             nstack_get_module_name_by_idx(fdInf->
                                                           rd_item.stack_id),
                             fdInf->rd_opt);
            }
            else
            {
                NSSOC_LOGINF("fd=%d,select_module=%s, rd_opt=%d", fd,
                             nstack_get_module_name_by_idx(fdInf->
                                                           rd_item.stack_id),
                             fdInf->rd_opt);
            }

            fdInf->rmidx = fdInf->rd_item.stack_id;
            nstack_set_routed_fd(fdInf,
                                 nstack_get_proto_fd(fdInf,
                                                     fdInf->
                                                     rd_item.stack_id));
            nstack_set_router_protocol(fdInf, fdInf->rd_item.stack_id);
            fdInf->ops = nstack_module_ops(fdInf->rd_item.stack_id);
        }
        else
        {
            NSSOC_LOGERR
                ("fd=%d Callback select_module=%d, rd_opt=%d, ret=0x%x", fd,
                 fdInf->rd_item.stack_id, fdInf->rd_opt, retval);
            nstack_set_errno(ENETUNREACH);
            UNLOCK_SEND(fd, fdInf, local_lock);
            return -1;
        }
        NSSOC_LOGDBG("fd=%d,select_module=%s", fd,
                     nstack_get_module_name_by_idx(fdInf->rd_item.stack_id));
    }
    else
    {
        NSSOC_LOGINF("fd addr is null and select linux module]fd=%d", fd);
        fdInf->ops = nstack_module_ops(nstack_get_linux_mid());
        nstack_set_routed_fd(fdInf,
                             nstack_get_proto_fd(fdInf,
                                                 nstack_get_linux_mid()));
        nstack_set_router_protocol(fdInf, nstack_get_linux_mid());
    }
    nstack_fd_dfx_update_dfx_data(fd, fdInf->rlfd, fdInf->rmidx,
                                  DMM_STAT_LONGEST_SEND_INTERVAL, NULL);
    NSTACK_CAL_FUN(fdInf->ops, sendmsg, (fdInf->rlfd, msg, flags), size);

    NSSOC_LOGDBG("fd=%d,module=%s,ret=%d[Return]", fd,
                 nstack_get_module_name_by_idx(fdInf->rmidx), size);

    UNLOCK_SEND(fd, fdInf, local_lock);
    return size;
}

/*we assumed that the connect allready called, if not call, we must try many sok*/
ssize_t nstack_recvfrom(int fd, void *buf, size_t len, int flags,
                        struct sockaddr * src_addr, socklen_t * addrlen)
{
    nstack_fd_Inf *fdInf = NULL;
    ssize_t size = -1;

    NSTACK_INIT_CHECK_RET(recvfrom, fd, buf, len, flags, src_addr, addrlen);

    NSSOC_LOGDBG
        ("sockfd=%d,buf=%p,len=%zu,flags=%d,src_addr=%p,addrlen=%p[Caller]",
         fd, buf, len, flags, src_addr, addrlen);

    if (NULL == buf)
    {
        nstack_set_errno(EFAULT);
        NSSOC_LOGERR("invalid input]fd=%d,buf=%p[Return]", fd, buf);
        return -1;
    }

    NSTACK_FD_LINUX_CHECK_RETURN(fd, recvfrom, fdInf,
                                 (fd, buf, len, flags, src_addr, addrlen));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_RECV(fd, fdInf, local_lock);

    NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_RECV(fd, recvfrom, fdInf, ENOTSOCK,
                                          local_lock);

    if ((!fdInf->ops) || (-1 == fdInf->rlfd))
    {
        NSSOC_LOGINF("Not select any module yet]fd=%d[Return]", fd);
        nstack_set_errno(ENOTCONN);
        UNLOCK_RECV(fd, fdInf, local_lock);
        return -1;
    }

    nstack_fd_dfx_update_dfx_data(fd, fdInf->rlfd, fdInf->rmidx,
                                  DMM_STAT_LONGEST_RECV_INTERVAL, NULL);
    NSTACK_CAL_FUN(fdInf->ops, recvfrom,
                   (fdInf->rlfd, buf, len, flags, src_addr, addrlen), size);

    NSSOC_LOGDBG("fd=%d,retVal=%zd[Return]", fd, size);

    UNLOCK_RECV(fd, fdInf, local_lock);
    return size;
}

ssize_t nstack_recvmsg(int fd, struct msghdr * msg, int flags)
{
    nstack_fd_Inf *fdInf = NULL;
    ssize_t size = -1;

    NSTACK_INIT_CHECK_RET(recvmsg, fd, msg, flags);
    NS_LOG_CTRL(LOG_CTRL_RECVMSG, NSOCKET, "SOC", NSLOG_DBG,
                "sockfd=%d,msg=%p,flags=%d[Caller]", fd, msg, flags);

    NSTACK_FD_LINUX_CHECK_RETURN(fd, recvmsg, fdInf, (fd, msg, flags));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_RECV(fd, fdInf, local_lock);

    NSTACK_EPOLL_FD_CHECK_RET_UNLOCK_RECV(fd, recvmsg, fdInf, ENOTSOCK,
                                          local_lock);

    if ((-1 == fdInf->rlfd) || (NULL == fdInf->ops))
    {
        NSSOC_LOGERR("Not select any module yet]fd=%d[Return]", fd);
        nstack_set_errno(ENOTCONN);
        UNLOCK_RECV(fd, fdInf, local_lock);
        return -1;
    }

    nstack_fd_dfx_update_dfx_data(fd, fdInf->rlfd, fdInf->rmidx,
                                  DMM_STAT_LONGEST_RECV_INTERVAL, NULL);
    NSTACK_CAL_FUN(fdInf->ops, recvmsg, (fdInf->rlfd, msg, flags), size);

    NSSOC_LOGDBG("fd=%d,ret=%zd[Return]", fd, size);

    UNLOCK_RECV(fd, fdInf, local_lock);
    return size;
}

/*****************************************************************
Parameters    :  fd
                 addr
                 len
Return        :
Description   : use hostname to get ip or use ip to get hostname
*****************************************************************/
int nstack_getaddrinfo(const char *name, const char *service,
                       const struct addrinfo *hints, struct addrinfo **res)
{
    int ret = 0;

    g_addrinfo_flag = 1;
    ret = nsfw_base_getaddrinfo(name, service, hints, res);
    g_addrinfo_flag = 0;

    return ret;
}

/*****************************************************************
Parameters    :  fd
                 addr
                 len
Return        :
Description   : all module fd bind to same addr, so just use first rlfd to get bind addr.
*****************************************************************/
int nstack_getsockname(int fd, struct sockaddr *addr, socklen_t * addrlen)
{
    nstack_fd_Inf *fdInf = NULL;
    int tfd = -1;
    int ret = -1;

    NSTACK_INIT_CHECK_RET(getsockname, fd, addr, addrlen);

    NS_LOG_CTRL(LOG_CTRL_GETSOCKNAME, NSOCKET, "SOC", NSLOG_INF,
                "fd=%d,addr=%p,addrlen=%p[Caller]", fd, addr, addrlen);

    if (fd < 0)
    {
        nstack_set_errno(EBADF);
        NSSOC_LOGERR("invalid input]fd=%d[return]", fd);
        return -1;
    }

    NSTACK_FD_LINUX_CHECK_RETURN(fd, getsockname, fdInf, (fd, addr, addrlen));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_COMMON(fd, fdInf, local_lock);

    if ((NULL != fdInf->ops) && (fdInf->rlfd != -1))
    {
        tfd = fdInf->rlfd;
        NSTACK_CAL_FUN(fdInf->ops, getsockname, (tfd, addr, addrlen), ret);
        NSSOC_LOGINF("fd=%d,module=%s,tfd=%d[return]", fd,
                     nstack_get_module_name_by_idx(fdInf->rmidx), tfd);
        if ((-1 == ret) && (fdInf->rmidx != nstack_get_linux_mid()))
        {
            NSSOC_LOGERR("rmidx=%d,fd=%d return fail[return]", fdInf->rmidx,
                         tfd);
        }
        UNLOCK_COMMON(fd, fdInf, local_lock);
        return ret;
    }

    if (NULL != g_nstack_modules.defMod)
    {
        tfd = nstack_get_proto_fd(fdInf, nstack_defmod_inx());
        if (tfd >= 0)
        {
            nstack_socket_ops *ops = nstack_def_ops();
            NSTACK_CAL_FUN(ops, getsockname, (tfd, addr, addrlen), ret);
            NSSOC_LOGINF("fd=%d,module=%s,tfd=%d[return]", fd,
                         nstack_defmod_name(), tfd);
            if ((-1 == ret)
                && (nstack_defmod_inx() != nstack_get_linux_mid()))
            {
                NSSOC_LOGERR("return fail]mudle=%d,fd=%d[return]",
                             nstack_defmod_inx(), tfd);
            }
            UNLOCK_COMMON(fd, fdInf, local_lock);
            return ret;
        }
    }

    nstack_set_errno(ENOTSOCK);
    NSSOC_LOGINF("fd=%d,ret=%d [Return]", fd, ret);
    UNLOCK_COMMON(fd, fdInf, local_lock);
    return ret;

}

/*****************************************************************
Parameters    :  fd
                 addr
                 len
Return        :
Description   : getpeername only used by the fd who already Estblsh connection, so use first rlfd.
*****************************************************************/
int nstack_getpeername(int fd, struct sockaddr *addr, socklen_t * addrlen)
{
    nstack_fd_Inf *fdInf;
    int tfd;
    int ret = -1;

    NSTACK_INIT_CHECK_RET(getpeername, fd, addr, addrlen);

    NS_LOG_CTRL(LOG_CTRL_GETPEERNAME, NSOCKET, "SOC", NSLOG_INF,
                "fd=%d,addr=%p,addrlen=%p[Caller]", fd, addr, addrlen);

    if (fd < 0)
    {
        nstack_set_errno(EBADF);
        NSSOC_LOGERR("invalid input,fd=%d[return]", fd);
        return -1;
    }

    NSTACK_FD_LINUX_CHECK_RETURN(fd, getpeername, fdInf, (fd, addr, addrlen));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_COMMON(fd, fdInf, local_lock);

    if (fdInf->ops)
    {
        tfd = fdInf->rlfd;
        NSTACK_CAL_FUN(fdInf->ops, getpeername, (tfd, addr, addrlen), ret);
        NSSOC_LOGINF("fd=%d,module=%s,rlfd=%d,ret=%d[return]",
                     fd, nstack_get_module_name_by_idx(fdInf->rmidx),
                     fdInf->rlfd, ret);
        if ((-1 == ret) && (fdInf->rmidx != nstack_get_linux_mid()))
        {
            NSSOC_LOGERR("return fail]mudle=%d,fd=%d[return]", fdInf->rmidx,
                         tfd);
        }
        UNLOCK_COMMON(fd, fdInf, local_lock);
        return ret;
    }

    if (NULL != g_nstack_modules.defMod)
    {
        tfd = nstack_get_proto_fd(fdInf, nstack_defmod_inx());
        if (tfd >= 0)
        {
            nstack_socket_ops *ops = nstack_def_ops();
            NSTACK_CAL_FUN(ops, getpeername, (tfd, addr, addrlen), ret);
            NSSOC_LOGINF("fd=%d,module=%s,tfd=%d[return]", fd,
                         nstack_defmod_name(), tfd);
            if ((-1 == ret)
                && (nstack_defmod_inx() != nstack_get_linux_mid()))
            {
                NSSOC_LOGERR("return fail] mudle=%d,fd=%d[return]",
                             nstack_defmod_inx(), tfd);
            }
            UNLOCK_COMMON(fd, fdInf, local_lock);
            return ret;
        }
    }

    nstack_set_errno(ENOTSOCK);
    NSSOC_LOGINF("fd=%d,ret=%d[Return]", fd, ret);
    UNLOCK_COMMON(fd, fdInf, local_lock);
    return ret;
}

int nstack_option_set(nstack_fd_Inf * fdInf, int optname, const void *optval,
                      socklen_t optlen)
{

    ns_int32 rd_opt;
#define SLEEP_MAX   10000000
    if ((!optval) || (optlen < sizeof(u32_t)))
    {
        NSSOC_LOGINF("rong parmeter optname]=%d", optname);
        nstack_set_errno(EINVAL);
        return -1;
    }

    switch (optname)
    {
        case NSTACK_SEM_SLEEP:
            if ((*(u32_t *) optval) > SLEEP_MAX)
            {
                NSSOC_LOGWAR("time overflow]epfd=%d", fdInf->fd);
                nstack_set_errno(EINVAL);
                return -1;
            }

            nsep_set_info_sleep_time(fdInf->fd, *(u32_t *) optval);     /*no need to check null pointer */
            NSSOC_LOGINF("set sem wait option] g_sem_sleep_time=%u",
                         *(u32_t *) optval);
            break;
        case NSTACK_RD_MODE:
            rd_opt = *(ns_int32 *) optval;
            if (rd_opt < -1 || rd_opt >= nstack_get_module_num())
            {
                NSSOC_LOGWAR("invail rd mode fd=%d, mode=%d", fdInf->fd,
                             rd_opt);
                nstack_set_errno(EINVAL);
                return -1;
            }
            fdInf->rd_opt = rd_opt;
            NSSOC_LOGINF("set rd mode] mode=%d", rd_opt);
            break;
        default:
            NSSOC_LOGINF("rong parmeter optname]=%d", optname);
            nstack_set_errno(ENOPROTOOPT);
            return -1;
    }
    return 0;
}

int nstack_option_get(nstack_fd_Inf * fdInf, int optname, const void *optval,
                      socklen_t * optlen)
{

    if ((!optval) || (!optlen) || (*optlen < sizeof(u32_t)))
    {
        NSSOC_LOGINF("rong parmeter optname]=%d", optname);
        nstack_set_errno(EINVAL);
        return -1;
    }

    switch (optname)
    {
        case NSTACK_SEM_SLEEP:
            *(long *) optval = nsep_get_info_sleep_time(fdInf->fd);     /*no need to check null pointer */
            NSSOC_LOGINF("get sem wait option] g_sem_sleep_time=%ld",
                         *(long *) optval);
            break;
        case NSTACK_RD_MODE:
            *(ns_int32 *) optval = fdInf->rd_opt;
            NSSOC_LOGINF("get rd mode] mode=%d", *(ns_int32 *) optval);
            break;
        default:
            NSSOC_LOGINF("rong parmeter optname]=%d", optname);
            nstack_set_errno(ENOPROTOOPT);
            return -1;
    }
    return 0;
}

/* just use first rlfd to getsockopt,  this may not what app  really want.*/
/* Currently, if getsockopt is successfull either in kernel or lwip, the below API returns SUCCESS */
int nstack_getsockopt(int fd, int level, int optname, void *optval,
                      socklen_t * optlen)
{
    nstack_fd_Inf *fdInf;
    int tfd;
    int ret = -1;
    nstack_socket_ops *ops;

    NSTACK_INIT_CHECK_RET(getsockopt, fd, level, optname, optval, optlen);

    NS_LOG_CTRL(LOG_CTRL_GETSOCKOPT, NSOCKET, "SOC", NSLOG_INF,
                "fd=%d,level=%d,optname=%d,optval=%p,optlen=%p[Caller]",
                fd, level, optname, optval, optlen);

    if (fd < 0)
    {
        nstack_set_errno(EBADF);
        NSSOC_LOGERR("invalid input]fd=%d[return]", fd);
        return -1;
    }

    NSTACK_FD_LINUX_CHECK_RETURN(fd, getsockopt, fdInf,
                                 (fd, level, optname, optval, optlen));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_COMMON(fd, fdInf, local_lock);

    if ((NSTACK_SOCKOPT == level) &&
        (NSTACK_IS_FD_EPOLL_SOCKET(fdInf) || NSTACK_RD_MODE == optname))
    {
        ret = nstack_option_get(fdInf, optname, optval, optlen);
        UNLOCK_COMMON(fd, fdInf, local_lock);
        return ret;
    }

    if (fdInf->ops)
    {
        tfd = fdInf->rlfd;
        NSTACK_CAL_FUN(fdInf->ops, getsockopt,
                       (tfd, level, optname, optval, optlen), ret);
        NSSOC_LOGINF
            ("fd=%d,module=%s,tfd=%d,level=%d,optname=%d,ret=%d[return]", fd,
             nstack_get_module_name_by_idx(fdInf->rmidx), tfd, level,
             optname, ret);
        if ((-1 == ret) && (fdInf->rmidx != nstack_get_linux_mid()))
        {
            NSSOC_LOGERR("return fail]mudle=%d,fd=%d[return]", fdInf->rmidx,
                         tfd);
        }
        UNLOCK_COMMON(fd, fdInf, local_lock);
        return ret;
    }

    if (NULL != g_nstack_modules.defMod)
    {
        tfd = nstack_get_proto_fd(fdInf, nstack_defmod_inx());
        if (tfd >= 0)
        {
            ops = nstack_def_ops();
            NSTACK_CAL_FUN(ops, getsockopt,
                           (tfd, level, optname, optval, optlen), ret);
            NSSOC_LOGINF
                ("fd=%d,module=%s:%d,level=%d,optname=%d,ret=%d[return]", fd,
                 nstack_defmod_name(), tfd, level, optname, ret);
            if ((-1 == ret)
                && (nstack_defmod_inx() != nstack_get_linux_mid()))
            {
                NSSOC_LOGERR("return fail]mudle=%d,fd=%d[return]",
                             nstack_defmod_inx(), tfd);
            }
            UNLOCK_COMMON(fd, fdInf, local_lock);
            return ret;
        }
    }

    nstack_set_errno(ENOTSOCK);
    NSSOC_LOGINF("fd=%d,ret=%d [Return]", fd, ret);
    UNLOCK_COMMON(fd, fdInf, local_lock);
    return ret;
}

/* all rlfd need setsockopt, set opt failed still can Estblsh connection. so we not care suc/fail */
/* Currently, if setsockopt is successfull either in kernel or lwip, the below API returns SUCCESS */
int nstack_setsockopt(int fd, int level, int optname, const void *optval,
                      socklen_t optlen)
{
    nstack_fd_Inf *fdInf;
    int ret = -1;
    nstack_socket_ops *ops;
    int itfd;
    int modInx = 0;
    int curRet = -1;
    int lerror = 0;
    int flag = 0;

    NSTACK_INIT_CHECK_RET(setsockopt, fd, level, optname, optval, optlen);

    NSSOC_LOGINF("fd=%d,level=%d,optname=%d,optval=%p,optlen=%u[Caller]",
                 fd, level, optname, optval, optlen);

    if (fd < 0)
    {
        nstack_set_errno(EBADF);
        NSSOC_LOGERR("invalid input]fd=%d[return]", fd);
        return -1;
    }

    NSTACK_FD_LINUX_CHECK_RETURN(fd, setsockopt, fdInf,
                                 (fd, level, optname, optval, optlen));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_COMMON(fd, fdInf, local_lock);

    if ((NSTACK_SOCKOPT == level) &&
        (NSTACK_IS_FD_EPOLL_SOCKET(fdInf) || NSTACK_RD_MODE == optname))
    {
        ret = nstack_option_set(fdInf, optname, optval, optlen);
        UNLOCK_COMMON(fd, fdInf, local_lock);
        return ret;
    }

    if (fdInf->ops)
    {
        itfd = fdInf->rlfd;
        NSTACK_CAL_FUN(fdInf->ops, setsockopt,
                       (itfd, level, optname, optval, optlen), ret);
        NSSOC_LOGINF
            ("fd=%d,module=%s,tfd=%d,level=%d,optname=%d,ret=%d[return]", fd,
             nstack_get_module_name_by_idx(fdInf->rmidx), itfd, level,
             optname, ret);
        if ((-1 == ret) && (fdInf->rmidx != nstack_get_linux_mid()))
        {
            NSSOC_LOGERR("return fail]mudle=%d,fd=%d[return]", fdInf->rmidx,
                         itfd);
        }
        UNLOCK_COMMON(fd, fdInf, local_lock);
        return ret;
    }
    nstack_each_mod_ops(modInx, ops)
    {
        itfd = nstack_get_proto_fd(fdInf, modInx);
        if (-1 == itfd)
        {
            continue;
        }
        flag = 1;
        NSTACK_CAL_FUN(ops, setsockopt,
                       (itfd, level, optname, optval, optlen), curRet);
        NSSOC_LOGDBG("fd=%d,module=%s,tfd=%d,level=%d,optname=%d,ret=%d", fd,
                     nstack_get_module_name_by_idx(modInx), itfd, level,
                     optname, curRet);
        if (modInx == nstack_get_linux_mid())
        {
            ret = curRet;
            /*errno is thread safe, but stackpool is not, so save it first */
            lerror = errno;
        }
    }
    /* errno is thread safe, but stackpool is not, so save it first */
    /*if all fd of stack is -1, the input fd maybe invalid */
    if (0 == flag)
    {
        nstack_set_errno(EBADF);
    }
    /*if linux return fail, and error is none zero, just reset it again */
    if ((lerror != 0) && (ns_success != ret))
    {
        nstack_set_errno(lerror);
    }
    /*errno is thread safe, but stackpool is not, so save it first */
    NSSOC_LOGINF("fd=%d,ret=%d[Return]", fd, ret);
    UNLOCK_COMMON(fd, fdInf, local_lock);
    return ret;
}

int nstack_ioctl(int fd, unsigned long request, unsigned long argp)
{
    nstack_fd_Inf *fdInf;
    int ret = -1;
    nstack_socket_ops *ops;
    int tfd;
    int modInx = 0;
    int curRet = -1;
    int lerror = 0;
    int flag = 0;

    NSTACK_INIT_CHECK_RET(ioctl, fd, request, argp);

    NSSOC_LOGINF("fd=%d,request=%lu[Caller]", fd, request);
    if (fd < 0)
    {
        nstack_set_errno(EBADF);
        NSSOC_LOGERR("invalid input]fd=%d[return]", fd);
        return -1;
    }

    NSTACK_FD_LINUX_CHECK_RETURN(fd, ioctl, fdInf, (fd, request, argp));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;

    LOCK_COMMON(fd, fdInf, local_lock);
    if (fdInf->ops)
    {
        tfd = fdInf->rlfd;
        NSTACK_CAL_FUN(fdInf->ops, ioctl, (tfd, request, argp), ret);
        NSSOC_LOGINF("fd=%d,module=%s,rlfd=%d,argp=0x%x,ret=%d[return]",
                     fd, nstack_get_module_name_by_idx(fdInf->rmidx),
                     fdInf->rlfd, argp, ret);
        if ((-1 == ret) && (fdInf->rmidx != nstack_get_linux_mid()))
        {
            NSSOC_LOGERR("return fail]mudle=%d,fd=%d[return]", fdInf->rmidx,
                         tfd);
        }

        UNLOCK_COMMON(fd, fdInf, local_lock);
        return ret;
    }

    nstack_each_mod_ops(modInx, ops)
    {
        tfd = nstack_get_proto_fd(fdInf, modInx);
        if (-1 == tfd)
        {
            continue;
        }
        flag = 1;

        NSTACK_CAL_FUN(ops, ioctl, (tfd, request, argp), curRet);
        NSSOC_LOGINF("fd=%d,module=%s,tfd=%d,argp=0x%x,ret=%d ",
                     fd, nstack_get_module_name_by_idx(modInx), tfd, argp,
                     curRet);
        if (modInx == nstack_get_linux_mid())
        {
            ret = curRet;
            /*errno is thread safe, but stackpool is not, so save it first */
            lerror = errno;
        }
    }
    /*errno is thread safe, but stackpool is not, so save it first */
    if (0 == flag)
    {
        nstack_set_errno(EBADF);
    }
    if ((0 != lerror) && (ns_success != ret))
    {
        nstack_set_errno(lerror);
    }
    /*errno is thread safe, but stackpool is not, so save it first */

    NSSOC_LOGINF("fd=%d,ret=%d[return]", fd, ret);

    UNLOCK_COMMON(fd, fdInf, local_lock);
    return ret;
}

int nstack_fcntl(int fd, int cmd, unsigned long argp)
{
    nstack_fd_Inf *fdInf;
    nstack_socket_ops *ops = NULL;
    int ret = -1;
    int noProOpt = 0;
    int tfd;
    int modInx = 0;
    int curRet = -1;
    int lerror = 0;
    int flag = 0;

    NSTACK_INIT_CHECK_RET(fcntl, fd, cmd, argp);

    NSSOC_LOGINF("fd=%d,cmd=%d[Caller]", fd, cmd);
    if (fd < 0)
    {
        nstack_set_errno(EBADF);
        NSSOC_LOGERR("invalid input]fd=%d[return]", fd);
        return -1;
    }

    NSTACK_FD_LINUX_CHECK_RETURN(fd, fcntl, fdInf, (fd, cmd, argp));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_COMMON(fd, fdInf, local_lock);

    /*have already bind */
    if (fdInf->ops)
    {
        tfd = fdInf->rlfd;
        NSTACK_CAL_FUN(fdInf->ops, fcntl, (tfd, cmd, argp), ret);
        NSSOC_LOGINF("fd=%d,cmd=%d,mod=%s,tfd=%d,argp=0x%x,ret=%d",
                     fd, cmd, nstack_get_module_name_by_idx(fdInf->rmidx),
                     tfd, argp, ret);
        if ((-1 == ret) && (fdInf->rmidx != nstack_get_linux_mid()))
        {
            NSSOC_LOGERR("return fail]mudle=%d,fd=%d", fdInf->rmidx, tfd);
        }
    }
    else
    {
        /*set cmd call all module, and return just linux */
        if (F_SETFL == cmd)
        {
            nstack_each_mod_ops(modInx, ops)
            {
                tfd = nstack_get_proto_fd(fdInf, modInx);
                if (-1 == tfd)
                {
                    continue;
                }
                flag = 1;
                noProOpt = 0;
                NSTACK_CAL_FUN(ops, fcntl, (tfd, cmd, argp), curRet);
                NSSOC_LOGINF("fd=%d,module=%s,tfd=%d,argp=0x%x,ret=%d ",
                             fd, nstack_get_module_name_by_idx(modInx), tfd,
                             argp, curRet);
                if (modInx == nstack_get_linux_mid())
                {
                    ret = curRet;
                    lerror = errno;
                }
            }
            /*errno is thread safe, but stackpool is not, so save it first */
            if (0 == flag)
            {
                nstack_set_errno(EBADF);
            }
            if ((0 != lerror) && (ns_success != ret))
            {
                nstack_set_errno(lerror);
            }
            /*errno is thread safe, but stackpool is not, so save it first */
        }                       /*other cmd call default */
        else if (g_nstack_modules.defMod)
        {
            tfd = nstack_get_proto_fd(fdInf, g_nstack_modules.defMod->modInx);
            if (tfd >= 0)
            {
                ops = nstack_def_ops();
                NSTACK_CAL_FUN(ops, fcntl, (tfd, cmd, argp), ret);
                NSSOC_LOGINF("fd=%d,cmd=%d,mod=%s,tfd=%d,argp=0x%x,ret=%d",
                             fd, cmd, g_nstack_modules.defMod->modulename,
                             tfd, argp, ret);
                if ((-1 == ret) && (fdInf->rmidx != nstack_get_linux_mid()))
                {
                    NSSOC_LOGERR("return fail]mudle=%d,fd=%d",
                                 g_nstack_modules.defMod->modInx, tfd);
                }
            }
            else
            {
                noProOpt = 1;
            }
        }
        else
        {
            noProOpt = 1;
        }
    }

    if (noProOpt)
    {
        nstack_set_errno(EBADF);
        NSSOC_LOGINF("fd=%d,ret=%d", fd, ret);
    }

    NSSOC_LOGINF("fd=%d,cmd=%d,ret=%d[return]", fd, cmd, ret);
    UNLOCK_COMMON(fd, fdInf, local_lock);
    return ret;
}

int nstack_select(int nfds, fd_set * readfds, fd_set * writefds,
                  fd_set * exceptfds, struct timeval *timeout)
{
    struct select_module_info *select_module = get_select_module();

    NSTACK_INIT_CHECK_RET(select, nfds, readfds, writefds, exceptfds,
                          timeout);

    if (NFDS_NOT_VALID(nfds) || TIMEVAL_NOT_VALID(timeout))
    {
        NSSOC_LOGERR("paremeter of nfds or timeout are no correct]nfds=%d \
                                sec=%ld usec=%ld", nfds, timeout->tv_sec, timeout->tv_usec);
        errno = EINVAL;
        return -1;
    }

    print_select_dbg(nfds, readfds, writefds, exceptfds);

    /*check the module had regist or not */
    if (TRUE != NSTACK_SELECT_LINUX_CHECK())
    {
        return nsfw_base_select(nfds, readfds, writefds, exceptfds, timeout);
    }

    /*nstack select not support timer function and not check nfds so calling dufault select */
    if (is_select_used_as_timer(nfds, readfds, writefds, exceptfds))
    {
        if ((select_module) && (select_module->default_fun))
        {
            return select_module->default_fun(nfds, readfds, writefds,
                                              exceptfds, timeout);
        }
        else
        {
            return nsfw_base_select(nfds, readfds, writefds, exceptfds,
                                    timeout);
        }
    }

    return nstack_select_processing(nfds, readfds, writefds, exceptfds,
                                    timeout);

}

/* epfd?fd maybe is from kernel or stackpool,should take care */
int nstack_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    int ret = ns_fail;
    struct eventpoll *ep = NULL;
    nstack_fd_Inf *epInf;
    struct epoll_event ep_event = { 0 };
    struct epitem *epi = NULL;

    NSTACK_INIT_CHECK_RET(epoll_ctl, epfd, op, fd, event);

    NSSOC_LOGINF("epfd=%d,op=%d,fd=%d,event=%p[Caller]", epfd, op, fd, event);
    if (event)
    {
        NSSOC_LOGINF("event->data.fd=%d,event->events=%u", event->data.fd,
                     event->events);
    }

    NSTACK_FD_LINUX_CHECK_RETURN(epfd, epoll_ctl, epInf,
                                 (epfd, op, fd, event));

    nstack_fd_local_lock_info_t *epoll_local_lock = &epInf->local_lock;
    LOCK_EPOLL(epfd, epInf, epoll_local_lock);
    nstack_fd_local_lock_info_t *local_lock = get_fd_local_lock_info(fd);
    LOCK_EPOLL_CTRL_RETURN(fd, local_lock, epfd, epoll_local_lock);

    if (!NSTACK_IS_FD_EPOLL_SOCKET(epInf) || fd == epfd)        /* `man epoll_ctl` tells me to do this check :) */
    {
        NSSOC_LOGWAR("epfd=%d is not a epoll fd[return]", epfd);
        errno = EINVAL;
        goto err_return;
    }

    if (!nstack_is_nstack_sk(fd))
    {
        NSSOC_LOGWAR("epfd=%d ,fd %d is not a supported [return]", epfd, fd);
        errno = EBADF;
        goto err_return;
    }

    nsep_epollInfo_t *epInfo = nsep_get_info_by_sock(epfd);
    if (NULL == epInfo)
    {
        NSSOC_LOGWAR("epInfo of epfd=%d is NULL[return]", epfd);
        errno = EINVAL;
        goto err_return;
    }

    ep = SHMEM_ADDR_SHTOL(epInfo->ep);
    if (NULL == ep)
    {
        NSSOC_LOGWAR("ep of epfd=%d is NULL[return]", epfd);
        errno = EINVAL;
        goto err_return;
    }

    if (NULL != event)
    {
        ep_event.data = event->data;
        ep_event.events = event->events;
    }
    else
    {
        if (op != EPOLL_CTL_DEL)
        {
            NSSOC_LOGWAR("events epfd=%d is NULL[return]", epfd);
            errno = EFAULT;
            goto err_return;
        }
    }

    dmm_spin_lock_with_pid((dmm_spinlock_t *) (&ep->sem));      /*do not need return value */

    epi = nsep_find_ep(ep, fd);
    switch (op)
    {
        case EPOLL_CTL_ADD:
            if (!epi)
            {

                ep_event.events |= (EPOLLERR | EPOLLHUP);       // Check `man epoll_ctl` if you don't understand , smile :)

                dmm_read_lock(get_fork_lock()); /* to ensure that there is no fd to create and close when fork. */
                ret = nsep_epctl_add(ep, epInfo, fd, &ep_event);
                dmm_read_unlock(get_fork_lock());
            }
            else
            {
                NSSOC_LOGWAR("fd already in eventpoll");
                errno = EEXIST;
                ret = -1;
            }
            break;
        case EPOLL_CTL_DEL:
            if (epi)
            {
                dmm_read_lock(get_fork_lock());
                ret = nsep_epctl_del(ep, epi);
                dmm_read_unlock(get_fork_lock());
            }
            else
            {
                NSSOC_LOGWAR("fd not registed before");
                errno = ENOENT;
                ret = -1;
            }
            break;
        case EPOLL_CTL_MOD:
            if (epi)
            {

                ep_event.events |= (EPOLLERR | EPOLLHUP);       // Look up ?

                ret =
                    nsep_epctl_mod(ep, nsep_get_info_by_sock(fd), epi,
                                   &ep_event);
            }
            else
            {
                NSSOC_LOGWAR("fd not registed before");
                errno = ENOENT;
                ret = -1;
            }
            break;
        default:
            NSSOC_LOGERR("epfd=%d,fd=%d,opt=%d not supported", epfd, fd, op);
            errno = EINVAL;
            ret = -1;
    }

    dmm_spin_unlock((dmm_spinlock_t *) (&ep->sem));
    NSSOC_LOGINF("epfd=%d,op=%d,fd=%d,ret=%d[return]", epfd, op, fd, ret);

  err_return:
    UNLOCK_EPOLL_CTRL(fd, local_lock);
    UNLOCK_EPOLL(epfd, epoll_local_lock);
    return ret;
}

int nstack_epoll_create(int size)
{
    nstack_fd_Inf *fdInf = NULL;
    struct eventpoll *ep = NULL;
    struct spl_conn_pool *ep_conn = NULL;
    int epfd = -1;

    NSTACK_INIT_CHECK_RET(epoll_create, size);
    NSSOC_LOGINF("size=%d[Caller]", size);

    if (size <= 0)
    {
        errno = EINVAL;
        NSSOC_LOGERR("invalid input,param]size=%d[return]", size);
        return -1;
    }
#ifdef KERNEL_FD_SUPPORT
    epfd = nsfw_base_epoll_create(size);

    if (!nstack_is_nstack_sk(epfd))
    {
        nsfw_base_close(epfd);  /*do not need return value */
        NSSOC_LOGERR("kernel fd alloced is too larger]kernel_fd=%d[return]",
                     epfd);
        errno = EMFILE;
        return -1;
    }

    nstack_fd_local_lock_info_t *lock_info = get_fd_local_lock_info(epfd);
    LOCK_FOR_EP(lock_info);
    fdInf = nstack_lk_fd_alloc_with_kernel(epfd);
#else
    fdInf = nstack_lk_fd_alloc_without_kernel();
#endif
    if (NULL == fdInf)
    {
        NSSOC_LOGERR("create fdInf fail[return]");
        errno = ENOMEM;
#ifdef KERNEL_FD_SUPPORT
        nsfw_base_close(epfd);  /*do not need return value */
        UNLOCK_FOR_EP(lock_info);
#endif
        return -1;
    }

#ifndef KERNEL_FD_SUPPORT
    epfd = fdInf->fd;
    nstack_fd_local_lock_info_t *lock_info = get_fd_local_lock_info(epfd);
    LOCK_FOR_EP(lock_info);
#endif

    /* here can't check return value, because if daemon-stack is old version, then here will fail, it is normal scenario */
    (void) nsep_alloc_ep_spl_conn_ring(&ep_conn);

    int pesudoEpIdx = nsep_alloc_eventpoll(&ep);
    if (pesudoEpIdx < 0)
    {
        nsep_free_info_with_sock(epfd); /*do not need return value */
        NSSOC_LOGERR("Alloc eventpoll fail[return]");
#ifdef KERNEL_FD_SUPPORT
        nstack_fd_free_with_kernel(fdInf);      /*do not need return value */
#else
        nstack_fd_free(fdInf);
#endif
        (void) nsep_free_ep_spl_conn_ring(ep_conn);
        errno = ENOMEM;
        UNLOCK_FOR_EP(lock_info);
        return -1;
    }

    ep->epfd = epfd;
    nsep_set_info_ep_resource(epfd, ep, ep_conn);
    NSTACK_SET_FD_EPOLL_SOCKET(fdInf);

    NSSOC_LOGINF("fd=%d[return]", epfd);
    set_fd_status_lock_fork(epfd, FD_OPEN);
    UNLOCK_FOR_EP(lock_info);
    return epfd;
}

int nstack_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                      int timeout)
{
    nstack_fd_Inf *fdInf = NULL;
    nsep_epollInfo_t *epInfo = NULL;
    struct eventpoll *ep = NULL;
    struct spl_conn_pool *ep_conn = NULL;
    int evt = 0;
    int ret = 0;
    int evt_ns = 0;

    NSTACK_INIT_CHECK_RET(epoll_wait, epfd, events, maxevents, timeout);

    NSTACK_FD_LINUX_CHECK_RETURN(epfd, epoll_wait, fdInf,
                                 (epfd, events, maxevents, timeout));

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_EPOLL(epfd, fdInf, local_lock);

    if (!NSTACK_IS_FD_EPOLL_SOCKET(fdInf))
    {
        NSSOC_LOGWAR("epfd=%d is not a epoll fd", epfd);
        errno = EINVAL;
        UNLOCK_EPOLL(epfd, local_lock);
        return -1;
    }

    /* should check input paramter's validity */
    if (NULL == events)
    {
        NSSOC_LOGWAR("events is NULL");
        errno = EINVAL;
        UNLOCK_EPOLL(epfd, local_lock);
        return -1;
    }

    epInfo = nsep_get_info_by_sock(epfd);
    if (NULL == epInfo)
    {
        NSSOC_LOGWAR("epInfo is NULL]epinfo=%p,epfd=%d", epInfo, epfd);
        errno = EINVAL;
        UNLOCK_EPOLL(epfd, local_lock);
        return -1;
    }

    ep = SHMEM_ADDR_SHTOL(epInfo->ep);
    if (NULL == ep)
    {
        NSSOC_LOGWAR("fdInf->ep is NULL]epinfo=%p,epfd=%d", epInfo, epfd);
        errno = EINVAL;
        UNLOCK_EPOLL(epfd, local_lock);
        return -1;
    }

    if (maxevents <= 0)
    {
        NSSOC_LOGWAR("maxevent less than zero]maxevents=%d", maxevents);
        errno = EINVAL;
        UNLOCK_EPOLL(epfd, local_lock);
        return -1;
    }

    NSTACK_GET_SYS_TICK(&ep->epoll_wait_tick);
    ep->epoll_wait_pending = 1;
    /* only if this ep is forked before, then set to 1 */
    if (epInfo->pidinfo.pid_used_size > 1)
    {
        ep->epoll_fork_flag = 1;
    }

    /* step1: get kernel epoll events and add them to epInfo */
#ifdef KERNEL_FD_SUPPORT
    NSTACK_CAL_FUN(nstack_module_ops(nstack_get_linux_mid()), epoll_wait,
                   (epfd, events, maxevents, 0), ret);
    if (ret > 0)
    {
        /* here we should refill event.data from epi,which is revised by nstack_epoll_ctl */
        int i = 0;
        nsep_epollInfo_t *fd_epinfo = NULL;
        struct list_node *fd_epi_head = NULL;
        struct list_node *node = NULL;
        struct epitem *epi = NULL;
        struct eventpoll *epfd_ep = NULL;

        for (i = 0; i < ret; i++)
        {
            fd_epinfo = nsep_get_info_by_sock(events[i].data.fd);
            if (!fd_epinfo)
            {
                NSSOC_LOGERR("get null epInfo err]protoFD=%d",
                             events[i].data.fd);
                continue;
            }

            dmm_spin_lock_with_pid((dmm_spinlock_t *) (&fd_epinfo->epiLock));   /*do not need return value */
            fd_epi_head =
                (struct list_node *) SHMEM_ADDR_SHTOL(fd_epinfo->
                                                      epiList.head);
            node = (struct list_node *) SHMEM_ADDR_SHTOL(fd_epi_head->next);
            while (node)
            {

                epi =
                    (struct epitem *) ep_list_entry(node, struct epitem,
                                                    fllink);
                epfd_ep = (struct eventpoll *) SHMEM_ADDR_SHTOL(epi->ep);

                if (epfd_ep->epfd == epfd)
                {
                    NSSOC_LOGDBG("Kernel got one event]i=%d,fd=%d,events=%u",
                                 evt, events[i].data.fd, events[i].events);
                    events[evt].events = events[i].events;
                    events[evt].data = epi->event.data;
                    evt++;
                    break;
                }

                node = (struct list_node *) SHMEM_ADDR_SHTOL(node->next);
            }
            if (!node)
            {
                NSSOC_LOGINF("fd was not added to this epfd]fd=%d, epfd=%d",
                             events[i].data.fd, epfd);
            }
            dmm_spin_unlock((dmm_spinlock_t *) (&fd_epinfo->epiLock));
        }
        /* end refill event.data */
    }
#endif
    /* step2: get events from epInfo(nstack's events).
       1)If have events, just return.
       2)If no event,wait and record new events. */

    ep_conn = SHMEM_ADDR_SHTOL(epInfo->ep_conn);
    evt_ns = nsep_ep_poll(ep, &events[evt], (maxevents - evt), ep_conn);
    if (evt_ns > 0)
    {
        evt += evt_ns;
    }
    if (evt)
    {
        NSSOC_LOGDBG("Got event]epfd=%d,maxevents=%d,ret=%d", epfd,
                     maxevents, evt);
        goto out;
    }

#ifdef KERNEL_FD_SUPPORT
    /* step3: if no event, add epfd to g_ksInfo.epfd epoll list and ks_ep_thread will record the new kernel epoll events to epinf */
    struct epoll_event ep_event;
    ep_event.data.fd = epfd;

    ep_event.events = EPOLLIN | EPOLLET;

    /* Here we don't check return value, because epfd maybe already in ks_ep_thread */
    NSTACK_CAL_FUN(nstack_module_ops(nstack_get_linux_mid()), epoll_ctl,
                   (0, EPOLL_CTL_ADD, epfd, &ep_event), ret);
#endif

    do
    {
        /*ns_sync_sem_timedwait need to deal timeout == 0 timeout < 0 timeout > 0 */
        ret =
            g_ns_sync_ops.ns_sync_sem_timedwait(&ep->waitSem, timeout,
                                                epInfo->sleepTime);
        if (ret)
        {
            nsep_notify_fd_epoll_wait_fail(ep);
            break;
        }
        evt = nsep_ep_poll(ep, events, maxevents, ep_conn);
        if (evt)
        {
            NSSOC_LOGDBG("Got event]epfd=%d,maxevents=%d,ret=%d", epfd,
                         maxevents, evt);
            break;
        }
    }
    while (1);

    /* step5: del epfd from g_ksInfo.epfd epoll list to make sure epoll_wait duration is the same as app */
#ifdef KERNEL_FD_SUPPORT

    NSTACK_CAL_FUN(nstack_module_ops(nstack_get_linux_mid()), epoll_ctl,
                   (0, EPOLL_CTL_DEL, epfd, &ep_event), ret);
#endif

  out:
    UNLOCK_EPOLL(epfd, local_lock);
    ep->epoll_wait_pending = 0;
    return evt;
}

pid_t nstack_fork(void)
{
    pid_t pid;
    pid_t ppid = sys_get_hostpid_from_file(getpid());

    NSTACK_INIT_CHECK_RET(fork);

    if (ppid >= NSFW_MAX_PID || ppid <= 0)
    {
        NSSOC_LOGERR("ppid over MAX_PID or not over 0]ppid=%d", ppid);
        return -1;
    }
    dmm_write_lock(get_fork_lock());
    if (NSTACK_MODULE_SUCCESS == g_nStackInfo.fwInited)
    {
        fork_parent_start(ppid);
        pid = nsfw_base_fork();
        if (pid == 0)
        {
            fork_child_start(ppid);

            /* when fork, the child process need
               relese the lock in glog */
            nstack_log_lock_release();
            nstack_fork_init_child(ppid);
            (void) nstack_for_epoll_init();
            nstack_fork_fd(ppid);
            nsep_fork(ppid);
            fork_child_done(ppid);
        }
        else if (pid > 0)
        {
            fork_wait_child_done(ppid);
        }
        else
        {
            fork_parent_failed(ppid);
        }
    }
    else
    {
        pid = nsfw_base_fork();
        if (pid == 0)
        {
            updata_sys_pid();
        }
        NSSOC_LOGERR("g_nStackInfo has not initialized]ppid=%d, pid=%d",
                     ppid, pid);
    }

    dmm_write_unlock(get_fork_lock());
    return pid;
}

int nstack_custom_peak(int fd)
{
    nstack_fd_Inf *fdInf = NULL;
    int ret = 0;
    int modInx = 0;

    fdInf = nstack_get_valid_inf(fd);
    if (NULL == fdInf)
    {
        nstack_set_errno(EINVAL);
        NSSOC_LOGERR("invalid fd]fd=%d", fd);
        return -1;
    }

    nstack_fd_local_lock_info_t *local_lock = &fdInf->local_lock;
    LOCK_RECV(fd, fdInf, local_lock);

    if (!NSTACK_IS_FD_ATTR(fdInf, fdInf->rd_item.type_data.attr))
    {
        nstack_set_errno(EBADFD);
        NSSOC_LOGERR("fd is not custom socket]fd=%d", fd);
        UNLOCK_RECV(fd, fdInf, local_lock);
        return -1;
    }

    nstack_fd_dfx_update_dfx_data(fd, fdInf->rlfd, fdInf->rmidx,
                                  DMM_STAT_LONGEST_RECV_INTERVAL, NULL);
    nstack_each_mod_inx(modInx)
    {
        if (nstack_fd_deal[modInx].peak)
        {
            ret = nstack_fd_deal[modInx].peak(fdInf->rlfd);
        }
        NSSOC_LOGDBG("Peak packet size]fd=%d,ret=%d", fd, ret);
    }
    UNLOCK_RECV(fd, fdInf, local_lock);

    return ret;
}
