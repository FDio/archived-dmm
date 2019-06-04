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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <math.h>
#include <string.h>

#include "nstack.h"
#include "nstack_fd_mng.h"
#include "nstack_socket.h"
#include "nstack_securec.h"
#include "nsfw_base_linux_api.h"
#include "nstack_dmm_dfx.h"

static inline void nstack_reset_fd_dfx(int fd)
{
    if (dmm_fd_dfx_pool && fd >= 0 && (u32_t) fd < NSTACK_KERNEL_FD_MAX)
    {
        if (memset_s
            (&dmm_fd_dfx_pool[fd], sizeof(nstack_fd_dfx_t), 0,
             sizeof(nstack_fd_dfx_t)))
        {
            NSSOC_LOGERR("memset failed");
        }
    }
    return;
}

/* test_epollCtl_004_001_trial : both 32bit and 64bit members of 'ops' and 'conn'
   need to reset, otherwise it will be invalid address in 32bit APP case */
/*no need to check null pointer here*/
void nstack_reset_fd_inf(nstack_fd_Inf * fdInf)
{
    int loop;
    fdInf->isBound = NSTACK_FD_NOBIND;
    fdInf->rlfd = -1;
    fdInf->rmidx = -1;
#ifdef KERNEL_FD_SUPPORT
    fdInf->nxtfd = -1;
    fdInf->fd = -1;
#else
    fdInf->stat = NSTACK_FD_DISCARD;
#endif
    fdInf->attr = 0;
    fdInf->ops = 0;             /*opers of the fd, for save space we user opIdx here */
    fdInf->type = 0;            /*the fd type like SOCK_STREAM|SOCK_NONBLOCK ... */

    NSTACK_SET_FD_BLOKING(fdInf);
    for (loop = 0; loop < NSTACK_MAX_MODULE_NUM; loop++)
    {
        fdInf->protoFD[loop].fd = -1;
        fdInf->protoFD[loop].errCode = 0;
        fdInf->protoFD[loop].pad = 0;
        fdInf->protoFD[loop].liststate = NSTACK_NO_LISENING;
    }

    nstack_reset_fd_local_lock_info(&(fdInf->local_lock));
    return;
}

nstack_fd_Inf *nstack_fd2inf(int fd)
{
    /*if nstack init not finished, just return null */
    if (NSTACK_MODULE_SUCCESS != g_nStackInfo.fwInited)
    {
        return NULL;
    }
    if (nstack_is_nstack_sk(fd) && g_nStackInfo.lk_sockPool)
    {
        return &(g_nStackInfo.lk_sockPool[fd]);
    }
    return NULL;
}

/*no need to check null pointer here*/
void nstack_set_proto_fd(nstack_fd_Inf * fdInf, int modInx, int protofd)
{

    if (protofd < nstack_get_minfd_id(modInx)
        || protofd > nstack_get_maxfd_id(modInx))
    {
        NSSOC_LOGDBG("module:%d protofd invalid] protofd=%d", modInx,
                     protofd);
        return;
    }

    nstack_get_proto_fd(fdInf, modInx) = protofd;

    nsep_set_info_proto_fd(fdInf->fd, modInx, protofd);

    nssct_create(fdInf->fd, protofd, modInx);   /*do not need return value */
    return;
}

/* pass app info to struct netconn */
void nstack_set_app_info(nstack_fd_Inf * fdInf, int modInx)
{
    if (nstack_fd_deal[modInx].set_app_info)
    {
        struct nsfw_app_info appinfo;

        appinfo.hostpid = get_sys_pid();
        appinfo.pid = getpid();
        appinfo.ppid = getppid();
        appinfo.tid = (int) syscall(SYS_gettid);
        appinfo.nsocket_fd = fdInf->fd;
        appinfo.sbr_fd = nstack_get_proto_fd(fdInf, modInx);

        nstack_fd_deal[modInx].set_app_info(appinfo.sbr_fd,
                                            (void *) &appinfo);
    }

    return;
}

#ifdef KERNEL_FD_SUPPORT

/* release sockets when app exit */
nstack_fd_Inf *nstack_lk_fd_alloc_with_kernel(int nfd)
{
    nstack_fd_Inf *retInf = NULL;

    if ((nfd < 0) || (nfd >= (int) NSTACK_KERNEL_FD_MAX)
        || (!g_nStackInfo.lk_sockPool))
    {
        NSSOC_LOGERR
            ("nfd < 0 or nfd>= NSTACK_KERNEL_FD_MAX, parameter not valid");
        return NULL;
    }

    retInf = &g_nStackInfo.lk_sockPool[nfd];

    if (FD_OPEN == retInf->local_lock.fd_status)
    {
        NSSOC_LOGERR("nstack_lk_fd_alloc_with_kernel fd:%d already create",
                     nfd);
    }

    retInf->fd = nfd;
    if (-1 == nsep_alloc_info_with_sock(nfd))
    {
        NSSOC_LOGERR("Can't alloc epInfo for nfd=%d]", nfd);
        nstack_reset_fd_inf(retInf);
        nstack_reset_fd_dfx(nfd);
        return NULL;
    }

    nstack_set_proto_fd(retInf, nstack_get_linux_mid(), nfd);
    NSSOC_LOGDBG("nfd=%d,retInf_fd=%d", nfd, retInf->fd);
    return retInf;
}
#else
nstack_fd_Inf *nstack_fd_alloc(void)
{
    int tfd;
    int LoopCount = 0;
    if (!g_nStackInfo.lk_sockPool)
    {
        return NULL;
    }

    /*begin using SpinLock instead CAS, to avoid ABA problem */
    dmm_spin_lock_with_pid((dmm_spinlock_t *) & g_nStackInfo.fdlock);
    /* [Add memory alloc state] */
    do
    {
        /* loop count should not be more than NSTACK_MAX_NON_LK_SOCK_NUM */
        if (LoopCount > NSTACK_MAX_SOCK_NUM)
        {
            dmm_spin_unlock((dmm_spinlock_t *) (&g_nStackInfo.fdlock));
            NSSOC_LOGERR("some err happen in alloc one fdInf");
            return NULL;
        }

        /* add tfd rang check */
        if (0 > (tfd = g_nStackInfo.fdhead) || tfd >= NSTACK_MAX_SOCK_NUM)
        {
            dmm_spin_unlock((dmm_spinlock_t *) (&g_nStackInfo.fdlock));
            NSSOC_LOGERR("fdinfo was empty");
            return NULL;
        }
        g_nStackInfo.fdhead = g_nStackInfo.lk_sockPool[tfd].nxtfd;
        if (NSTACK_FD_DISCARD == g_nStackInfo.lk_sockPool[tfd].stat)
        {
            g_nStackInfo.lk_sockPool[tfd].stat = NSTACK_FD_INUSING;
            break;
        }
        else
        {
            NSSOC_LOGWAR("Alloc one fdInf with stat %d [not correct]",
                         g_nStackInfo.lk_sockPool[tfd].stat);

        }
        LoopCount++;
    }
    while (1);
    /* [Add memory alloc state] */
    dmm_spin_unlock((dmm_spinlock_t *) (&g_nStackInfo.fdlock));
    /*end using SpinLock instead CAS, to avoid ABA problem */

    return &g_nStackInfo.lk_sockPool[tfd];
}

void nstack_fd_free(nstack_fd_Inf * fdInf)
{
    int nfd;

    nfd = fdInf->fd;

    if (nfd < NSTACK_MAX_SOCK_NUM && nfd > -1)
    {
        dmm_spin_lock_with_pid((dmm_spinlock_t *) & g_nStackInfo.fdlock);
        if (NSTACK_FD_INUSING != fdInf->stat)
        {
            NSSOC_LOGERR("fdInf not alloced yet!");
            dmm_spin_unlock((dmm_spinlock_t *) (&g_nStackInfo.fdlock));
            return;
        }
        nstack_reset_fd_inf(fdInf);
        nstack_reset_fd_dfx(nfd);
        g_nStackInfo.lk_sockPool[nfd].nxtfd = g_nStackInfo.fdhead;
        g_nStackInfo.fdhead = nfd;
        dmm_spin_unlock((dmm_spinlock_t *) (&g_nStackInfo.fdlock));
    }
    return;
}

nstack_fd_Inf *nstack_lk_fd_alloc_without_kernel()
{
    nstack_fd_Inf *retInf = NULL;

    retInf = nstack_fd_alloc();
    if (!retInf)
    {
        NSSOC_LOGERR("nstack_lk_fd_alloc_without_kernel fail");
        return NULL;
    }

    if (FD_OPEN == retInf->local_lock.fd_status)
    {
        NSSOC_LOGWAR
            ("nstack_lk_fd_alloc_without_kernel fd:%d already create",
             retInf->fd);

    }

    if (-1 == nsep_alloc_info_with_sock(retInf->fd))
    {
        NSSOC_LOGERR("Can't alloc epInfo for nfd=%d]", retInf->fd);
        nstack_reset_fd_inf(retInf);
        nstack_reset_fd_dfx(retInf->fd);
        return NULL;
    }

    NSSOC_LOGDBG("retInf->fd=%d", retInf->fd);
    return retInf;
}
#endif

/* should release resource for kernel */
static int nstack_close_kernel_socket(int fd)
{
    return nsfw_base_close(fd);
}

int nstack_fd_free_with_kernel(nstack_fd_Inf * fdInf)
{
    int closeRet = 0;
    ns_int32 fd;

    if (!fdInf)
    {
        NSSOC_LOGERR("fdInf is NULL");
        return 0;
    }
    fd = fdInf->protoFD[nstack_get_linux_mid()].fd;
    nstack_reset_fd_dfx(fd);
    nstack_reset_fd_inf(fdInf);

    if (fd >= 0 && fd < (int) NSTACK_KERNEL_FD_MAX)
    {
        closeRet = nstack_close_kernel_socket(fd);
        NSSOC_LOGINF("close]fd=%d,ret=%d", fd, closeRet);
    }
    return closeRet;
}

void nstack_fork_fd(pid_t ppid)
{
    int i;
    int fd;
    nstack_fd_Inf *fdInf = NULL;
    pid_t cpid = get_sys_pid();
    for (fd = 0; fd < (int) NSTACK_KERNEL_FD_MAX; fd++)
    {
        fdInf = nstack_get_valid_inf(fd);
        if (fdInf)
        {
            if (!((u32_t) (fdInf->type) & SOCK_CLOEXEC))
            {
                nstack_fork_fd_local_lock_info(&fdInf->local_lock);
                nstack_each_mod_inx(i)
                {
                    if ((nstack_fd_deal[i].fork_fd)
                        && (fdInf->protoFD[i].fd >= 0))
                    {
                        nstack_fd_deal[i].fork_fd(fdInf->protoFD[i].fd, ppid,
                                                  cpid);
                    }
                }
            }
            else
            {
                nstack_reset_fd_local_lock_info(&fdInf->local_lock);
                nsep_set_info_sock_map(fd, NULL);
                nstack_each_mod_inx(i)
                {
                    if ((nstack_fd_deal[i].fork_free_fd)
                        && (fdInf->protoFD[i].fd >= 0))
                    {
                        nstack_fd_deal[i].fork_free_fd(fdInf->protoFD[i].fd);
                    }
                }
            }
        }
    }
}

void nstack_fork_init_parent(pid_t ppid)
{
    int fd;
    nstack_fd_Inf *fdInf = NULL;
    for (fd = 0; fd < (int) NSTACK_KERNEL_FD_MAX; fd++)
    {
        fdInf = nstack_get_valid_inf(fd);
        if ((NULL != fdInf) && (!((u32_t) (fdInf->type) & SOCK_CLOEXEC)))
        {
            int i;
            nstack_each_mod_inx(i)
            {
                if ((nstack_fd_deal[i].fork_parent_fd)
                    && (fdInf->protoFD[i].fd >= 0))
                {
                    nstack_fd_deal[i].fork_parent_fd(fdInf->protoFD[i].fd,
                                                     ppid);
                }
            }
        }
    }
}

void nstack_fork_init_child(pid_t ppid)
{
    pid_t cpid = updata_sys_pid();
    NSSOC_LOGDBG("parent_pid=%d, child_pid=%d", ppid, cpid);

    nsfw_mgr_clr_fd_lock();
    if (FALSE == nsfw_recycle_fork_init())
    {
        NSFW_LOGERR("init rec zone failed!]ppid=%d,cpid=%d", ppid, cpid);
    }

    int i;
    nstack_each_mod_inx(i)
    {
        if (nstack_fd_deal[i].fork_init_child)
        {
            nstack_fd_deal[i].fork_init_child(ppid, cpid);
        }
    }
}
