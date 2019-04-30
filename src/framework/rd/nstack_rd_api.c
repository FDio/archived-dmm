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

#include <stdlib.h>
#include <arpa/inet.h>
#include "nstack_rd_api.h"
#include "nstack_rd_data.h"
#include "nsfw_mem_api.h"
#include "nsfw_recycle_api.h"
#include "nstack_log.h"
#include "nstack_securec.h"
#include "nsfw_common_defs.h"
#include "nstack_ip_addr.h"

#define RD_AGE_MAX_TIME   3

rd_route_table *g_rd_table_handle[NSTACK_MAX_MODULE_NUM];

void *nstack_rd_malloc(const char *name)
{
    void *p = NULL;

    if (!name)
    {
        NSSOC_LOGERR("NULL pointer is not allowed!");
        return NULL;
    }
    if (strlen(name) >= NSFW_MEM_NAME_LENTH)
    {
        NSSOC_LOGERR("name length overflow!");
        return NULL;
    }

    nsfw_mem_zone zone = {
        {NSFW_SHMEM, NSFW_PROC_APP, {0}
         }
        ,
        sizeof(rd_route_table),
        NSFW_SOCKET_ANY,
        0
    };

    if (EOK != strcpy_s(zone.stname.aname, NSFW_MEM_NAME_LENTH, name))
    {
        NSSOC_LOGERR("strcpy_s failed!");
        return NULL;
    }

    p = nsfw_mem_zone_create(&zone);
    if (!p)
    {
        NSSOC_LOGERR("nstack_rd_malloc failed!");
        return NULL;
    }

    nstack_rd_table_clear(p);

    return p;
}

void *nstack_local_rd_malloc(void)
{
    void *p;

    p = malloc(sizeof(rd_route_table));
    if (!p)
    {
        return NULL;
    }
    nstack_rd_table_clear(p);
    return p;
}

void nstack_local_rd_free(void *p)
{
    if (p)
        free(p);
}

int nstack_rd_free(const char *name)
{
    if (!name)
    {
        NSSOC_LOGERR("NULL pointer is not allowed!");
        return -1;
    }
    if (strlen(name) >= NSFW_MEM_NAME_LENTH)
    {
        NSSOC_LOGERR("name length overflow!");
        return -1;
    }

    nsfw_mem_name pname = {
        NSFW_SHMEM,
        NSFW_PROC_APP,
        {0}
    };

    if (EOK != strcpy_s(pname.aname, NSFW_MEM_NAME_LENTH, name))
    {
        NSSOC_LOGERR("strcpy_s failed!");
        return -1;
    }

    return nsfw_mem_zone_release(&pname);
}

void nstack_rd_table_clear(void *p)
{
    rd_route_table *table = (rd_route_table *) p;

    (void) memset_s(table, sizeof(rd_route_table), 0, sizeof(rd_route_table));
    table->size = NSTACK_RD_DATA_MAX;
    table->icnt = 0;
    table->rdtbl_ver = 0;
    DMM_SPINLOCK_MALLOC(table->rd_lock, 1);
}

/*****************************************************************************
*   Prototype    : nstack_rd_ip_node_insert
*   Description  : insert a rd_ip_data into list
*   Input        : char *name
*                  rd_ip_data *data
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    : daemon-stack
*****************************************************************************/
int nstack_rd_ip_node_insert(const char *name, rd_ip_data * data, void *table)
{
    rd_route_table *handle = (rd_route_table *) table;
    if (!handle)
    {
        NSSOC_LOGERR("nstack rd mng not inited");
        return -1;
    }
    int iindex = 0;
    rd_route_node *pnode = NULL;
    int agetime = 0;
    int ageindex = -1;
    int freeindex = -1;
    int repeatflag = 0;

    for (iindex = 0; iindex < NSTACK_RD_DATA_MAX; iindex++)
    {
        pnode = &(handle->node[iindex]);
        /*record the index of first free element */
        if (RD_NODE_USELESS == pnode->flag)
        {
            if (-1 == freeindex)
            {
                freeindex = iindex;
                NSSOC_LOGINF("nstack rd ip free element index:%d was found",
                             iindex);
            }
            continue;
        }

        /*if is using, and repeat just set flag */
        if (RD_NODE_USING == pnode->flag)
        {
            if (MASK_V(pnode->data.ipdata.addr, pnode->data.ipdata.masklen)
                == MASK_V(data->addr, data->masklen))
            {
                NSSOC_LOGWAR
                    ("stack=%s, ip addr=*.*.%u.%u, masklen:%u was repeat",
                     name, FUZZY_IP_VAR(&data->addr), data->masklen);
                repeatflag = 1;
            }
            continue;
        }

        /*if flag is deleting, just update the age time, if agetime is on, just set flag to free */
        if (RD_NODE_DELETING == pnode->flag)
        {
            pnode->agetime++;
            if (pnode->agetime >= RD_AGE_MAX_TIME)
            {
                pnode->flag = RD_NODE_USELESS;
                NSSOC_LOGINF
                    ("nstack rd ip element index=%d,addr=*.*.%u.%u,masklen=%u was delete and set to free",
                     iindex, FUZZY_IP_VAR(&pnode->data.ipdata.addr),
                     pnode->data.ipdata.masklen);
            }
            /*record delete time */
            if (agetime < pnode->agetime)
            {
                agetime = pnode->agetime;
                ageindex = iindex;
            }
            continue;
        }
    }

    /*if repeat, just return */
    if (1 == repeatflag)
    {
        return 0;
    }
    if (-1 == freeindex)
    {
        if (-1 != ageindex)
        {
            freeindex = ageindex;
        }
        else
        {
            NSSOC_LOGERR
                ("the rd table is full,nstack=%s, rd addr=*.*.%u.%u, masklen=%u can't be inserted",
                 name, FUZZY_IP_VAR(&data->addr), data->masklen);
            return -1;
        }
    }
    pnode = &(handle->node[freeindex]);
    /*if no free found, just reuse the big agetime */
    dmm_spin_lock_with_pid(&handle->rd_lock);
    if (EOK != strcpy_s(pnode->data.stack_name, RD_PLANE_NAMELEN, name))
    {
        NSSOC_LOGERR("strcpy_s failed]copy_name=%s", name);
    }
    pnode->data.type = RD_DATA_TYPE_IP;
    pnode->agetime = 0;
    pnode->data.ipdata.addr = data->addr;
    pnode->data.ipdata.masklen = data->masklen;
    pnode->data.ipdata.resev[0] = 0;
    pnode->data.ipdata.resev[1] = 0;
    pnode->flag = RD_NODE_USING;        /*last set */
    handle->icnt++;
    __sync_fetch_and_add(&handle->rdtbl_ver, 1);        /*[MISRA 2004 Rule 14.2] */
    dmm_spin_unlock(&handle->rd_lock);
    NSSOC_LOGINF
        ("nstack=%s, rd addr=*.*.%u.%u, masklen=%u index was inserted", name,
         FUZZY_IP_VAR(&data->addr), data->masklen);
    return 0;
}

/*****************************************************************************
*   Prototype    : nstack_rd_ip_node_delete
*   Description  : rd data delete
*   Input        : rd_ip_data *data
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    : daemon-stack
*****************************************************************************/
int nstack_rd_ip_node_delete(rd_ip_data * data, void *table)
{
    int iindex = 0;
    rd_route_table *handle = (rd_route_table *) table;
    rd_route_node *pnode = NULL;

    if (!handle)
    {
        NSSOC_LOGERR("nstack rd mng not inited");
        return -1;
    }

    for (iindex = 0; iindex < NSTACK_RD_DATA_MAX; iindex++)
    {
        pnode = &(handle->node[iindex]);
        if ((RD_NODE_USING == pnode->flag)
            && (MASK_V(pnode->data.ipdata.addr, pnode->data.ipdata.masklen)
                == MASK_V(data->addr, data->masklen)))
        {
            dmm_spin_lock_with_pid(&handle->rd_lock);
            pnode->flag = RD_NODE_DELETING;     /*just set deleting state */
            pnode->agetime = 0;
            handle->icnt--;
            NSSOC_LOGINF
                ("nstack rd delete:%s, addr=*.*.%u.%u, masklen=%u index:%d was delete",
                 pnode->data.stack_name, FUZZY_IP_VAR(&data->addr),
                 data->masklen, iindex);
            __sync_fetch_and_add(&handle->rdtbl_ver, 1);
            dmm_spin_unlock(&handle->rd_lock);
            NSSOC_LOGINF
                ("nstack rd delete:%s, addr:0x%x, masklen:%u index:%d was delete",
                 pnode->data.stack_name, ntohl(data->addr), data->masklen,
                 iindex);
            return 0;
        }
    }
    NSSOC_LOGINF
        ("nstack rd delete, addr=*.*.%u.%u, masklen=%u index was not found",
         FUZZY_IP_VAR(&data->addr), data->masklen);
    return 0;
}

char *ipv6_ntop(ip6_addr_t host_addr)
{
    static char buf[INET6_ADDRSTRLEN];
    ip6_addr_t net_addr;

    net_addr = host_addr;
    if (inet_ntop(AF_INET6, &net_addr.addr32, buf, INET6_ADDRSTRLEN) == NULL)
    {
        return "invalid IPv6 address";
    }
    return buf;
}

/*****************************************************************************
*   Description  : insert a rd_ip6_data into list
*   Called By    : daemon-stack
*   Notice       : the IP insert is in network order byte
*****************************************************************************/
int nstack_rd_ip6_node_insert(const char *name, rd_ip6_data * data,
                              void *table)
{
    rd_route_table *handle = (rd_route_table *) table;
    if (!handle)
    {
        NSSOC_LOGERR("nstack rd mng not inited");
        return -1;
    }
    int iindex = 0;
    rd_route_node *pnode = NULL;
    int agetime = 0;
    int ageindex = -1;
    int freeindex = -1;
    int repeatflag = 0;

    for (iindex = 0; iindex < NSTACK_RD_DATA_MAX; iindex++)
    {
        pnode = &(handle->node[iindex]);
        /*record the index of first free element */
        if (RD_NODE_USELESS == pnode->flag)
        {
            if (-1 == freeindex)
            {
                freeindex = iindex;
                NSSOC_LOGINF("nstack rd ip free element index:%d was found",
                             iindex);
            }
            continue;
        }

        /*if is using, and repeat just set flag */
        if (RD_NODE_USING == pnode->flag)
        {
            if (ip6_addr_match
                (&pnode->data.ip6data.addr, &data->addr, data->masklen))
            {
                NSSOC_LOGWAR
                    ("nstack:%s, index:%d, old_addr:%s, masklen:%u was repeat",
                     name, iindex, ipv6_ntop(pnode->data.ip6data.addr),
                     data->masklen);
                repeatflag = 1;
            }
            continue;
        }

        /*if flag is deleting, just update the age time, if agetime is on, just set flag to free */
        if (RD_NODE_DELETING == pnode->flag)
        {
            pnode->agetime++;
            if (pnode->agetime >= RD_AGE_MAX_TIME)
            {
                pnode->flag = RD_NODE_USELESS;
                NSSOC_LOGINF
                    ("nstack rd ip element index:%d addr:%s, masklen:%u was delete and set to free",
                     iindex, ipv6_ntop(pnode->data.ip6data.addr),
                     pnode->data.ipdata.masklen);
            }
            /*record delete time */
            if (agetime < pnode->agetime)
            {
                agetime = pnode->agetime;
                ageindex = iindex;
            }
            continue;
        }
    }

    /*if repeat, just return */
    if (1 == repeatflag)
    {
        return 0;
    }
    if (-1 == freeindex)
    {
        if (-1 != ageindex)
        {
            freeindex = ageindex;
        }
        else
        {
            NSSOC_LOGERR
                ("the rd table is full,nstack:%s, rd addr:%s, masklen:%u can't be inserted",
                 name, ipv6_ntop(data->addr), data->masklen);
            return -1;
        }
    }
    pnode = &(handle->node[freeindex]);
    /*if no free found, just reuse the big agetime */
    dmm_spin_lock_with_pid(&handle->rd_lock);
    if (EOK != strcpy_s(pnode->data.stack_name, RD_PLANE_NAMELEN, name))
    {
        NSSOC_LOGERR("strcpy_s failed]copy_name=%s", name);
    }
    pnode->data.type = RD_DATA_TYPE_IP6;
    pnode->agetime = 0;
    pnode->data.ip6data.addr.addr32[0] = data->addr.addr32[0];
    pnode->data.ip6data.addr.addr32[1] = data->addr.addr32[1];
    pnode->data.ip6data.addr.addr32[2] = data->addr.addr32[2];
    pnode->data.ip6data.addr.addr32[3] = data->addr.addr32[3];
    pnode->data.ip6data.masklen = data->masklen;
    pnode->flag = RD_NODE_USING;        /*last set */
    handle->icnt++;
    __sync_fetch_and_add(&handle->rdtbl_ver, 1);
    dmm_spin_unlock(&handle->rd_lock);
    NSSOC_LOGINF("nstack:%s, rd addr:%s, masklen:%u index was inserted",
                 name, ipv6_ntop(data->addr), data->masklen);
    return 0;
}

/*****************************************************************************
*   Prototype    : nstack_rd_ip6_node_delete
*   Description  : rd data delete, only set flag
*   Called By    : daemon-stack
*   Notice       : the IP delete is in network order byte
*****************************************************************************/
int nstack_rd_ip6_node_delete(rd_ip6_data * data, void *table)
{
    int iindex = 0;
    rd_route_table *handle = (rd_route_table *) table;
    rd_route_node *pnode = NULL;

    if (!handle)
    {
        NSSOC_LOGERR("nstack rd mng not inited");
        return -1;
    }

    for (iindex = 0; iindex < NSTACK_RD_DATA_MAX; iindex++)
    {
        pnode = &(handle->node[iindex]);
        if ((RD_NODE_USING == pnode->flag)
            &&
            (ip6_addr_match
             (&pnode->data.ip6data.addr, &data->addr, data->masklen)))
        {
            dmm_spin_lock_with_pid(&handle->rd_lock);
            pnode->flag = RD_NODE_DELETING;     /*just set deleting state */
            pnode->agetime = 0;
            handle->icnt--;
            __sync_fetch_and_add(&handle->rdtbl_ver, 1);
            dmm_spin_unlock(&handle->rd_lock);
            NSSOC_LOGINF
                ("nstack rd delete:%s, addr:%s, masklen:%u index:%d was delete",
                 pnode->data.stack_name, ipv6_ntop(data->addr),
                 data->masklen, iindex);
            return 0;
        }
    }
    NSSOC_LOGINF("nstack rd delete, addr:%s, masklen:%u index was not found",
                 ipv6_ntop(data->addr), data->masklen);
    return 0;
}

NSTACK_STATIC nsfw_rcc_stat rd_recyle_lock(u32 pid, void *pdata, u16 rec_type)
{
    int i;

    for (i = 0; i < NSTACK_MAX_MODULE_NUM; i++)
    {
        if (g_rd_table_handle[i] && pid == g_rd_table_handle[i]->rd_lock.lock)
        {
            (void)
                __sync_bool_compare_and_swap(&g_rd_table_handle[i]->rd_lock.
                                             lock, pid, 0);
            NSFW_LOGWAR("rd locked]pid=%u", pid);
        }
    }

    return NSFW_RCC_CONTINUE;
}

REGIST_RECYCLE_LOCK_REL(rd_recyle_lock, NULL, NSFW_PROC_NULL)
     int nstack_rd_type_node_insert(const char *name, rd_type_data * data,
                                    void *table)
{
    rd_route_table *handle = (rd_route_table *) table;
    if (!handle || !data)
    {
        NSSOC_LOGERR("invalid parameters!");
        return -1;
    }
    int iindex = 0;
    rd_route_node *pnode = NULL;
    int agetime = 0;
    int ageindex = -1;
    int freeindex = -1;
    int repeatflag = 0;

    for (iindex = 0; iindex < NSTACK_RD_DATA_MAX; iindex++)
    {
        pnode = &(handle->node[iindex]);
        /*record the index of first free element */
        if (RD_NODE_USELESS == pnode->flag)
        {
            if (-1 == freeindex)
            {
                freeindex = iindex;
                NSSOC_LOGINF("free element index:%d was found", iindex);
            }
            continue;
        }

        /*if is using, and repeat just set flag */
        if (RD_NODE_USING == pnode->flag)
        {
            if (pnode->data.type_data.value == data->value
                && pnode->data.type_data.attr == data->attr)
            {
                NSSOC_LOGWAR("find duplicate node, type:%u", data->value);
                repeatflag = 1;
            }
            continue;
        }

        /*if flag is deleting, just update the age time, if agetime is on, just set flag to free */
        if (RD_NODE_DELETING == pnode->flag)
        {
            pnode->agetime++;
            if (pnode->agetime >= RD_AGE_MAX_TIME)
            {
                pnode->flag = RD_NODE_USELESS;
                NSSOC_LOGINF("goint to free node at index:%d", iindex);
            }
            /*record delete time */
            if (agetime < pnode->agetime)
            {
                agetime = pnode->agetime;
                ageindex = iindex;
            }
            continue;
        }
    }

    /*if repeat, just return */
    if (1 == repeatflag)
    {
        return 0;
    }
    if (-1 == freeindex)
    {
        if (-1 != ageindex)
        {
            freeindex = ageindex;
        }
        else
        {
            NSSOC_LOGERR("the rd route table:%p is full", handle);
            return -1;
        }
    }
    pnode = &(handle->node[freeindex]);
    /*if no free found, just reuse the big agetime */
    dmm_spin_lock_with_pid(&handle->rd_lock);
    if (EOK != strcpy_s(pnode->data.stack_name, RD_PLANE_NAMELEN, name))
    {
        NSSOC_LOGERR("strcpy_s failed]copy_name=%s", name);
    }
    pnode->data.type = RD_DATA_TYPE_TYPE;
    pnode->data.type_data.value = data->value;
    pnode->data.type_data.attr = data->attr;
    pnode->data.type_data.reserved[0] = data->reserved[0];
    pnode->data.type_data.reserved[1] = data->reserved[1];
    pnode->data.type_data.reserved[2] = data->reserved[2];
    pnode->data.type_data.reserved[3] = data->reserved[3];
    pnode->flag = RD_NODE_USING;        /*last set */
    handle->icnt++;
    __sync_fetch_and_add(&handle->rdtbl_ver, 1);        /*[MISRA 2004 Rule 14.2] */
    dmm_spin_unlock(&handle->rd_lock);
    NSSOC_LOGINF("nstack=%s, type:%u attr:%u was inserted", name,
                 data->value, data->attr);
    return 0;
}

int nstack_rd_type_node_delete(rd_type_data * data, void *table)
{
    int iindex = 0;
    rd_route_table *handle = (rd_route_table *) table;
    rd_route_node *pnode = NULL;

    if (!handle || !data)
    {
        NSSOC_LOGERR("invalid parameters");
        return -1;
    }

    for (iindex = 0; iindex < NSTACK_RD_DATA_MAX; iindex++)
    {
        pnode = &(handle->node[iindex]);
        if ((RD_NODE_USING == pnode->flag)
            && pnode->data.type_data.value == data->value
            && pnode->data.type_data.attr == data->attr)
        {
            dmm_spin_lock_with_pid(&handle->rd_lock);
            pnode->flag = RD_NODE_DELETING;     /*just set deleting state */
            pnode->agetime = 0;
            handle->icnt--;
            NSSOC_LOGINF
                ("nstack rd:%s, type:%u, attr:%u at index:%d will be deleted",
                 pnode->data.stack_name, data->value, data->attr, iindex);
            __sync_fetch_and_add(&handle->rdtbl_ver, 1);
            dmm_spin_unlock(&handle->rd_lock);
            NSSOC_LOGINF
                ("nstack rd:%s, type:%u, attr:%u at index:%d was deleted",
                 pnode->data.stack_name, data->value, data->attr, iindex);
            return 0;
        }
    }
    NSSOC_LOGINF("nstack rd delete, type:%u attr:%u was not found",
                 data->value, data->attr);
    return 0;
}

int nstack_rd_proto_node_insert(const char *name, rd_proto_data * data,
                                void *table)
{
    rd_route_table *handle = (rd_route_table *) table;
    if (!handle || !data)
    {
        NSSOC_LOGERR("invalid parameters!");
        return -1;
    }
    int iindex = 0;
    rd_route_node *pnode = NULL;
    int agetime = 0;
    int ageindex = -1;
    int freeindex = -1;
    int repeatflag = 0;

    for (iindex = 0; iindex < NSTACK_RD_DATA_MAX; iindex++)
    {
        pnode = &(handle->node[iindex]);
        /*record the index of first free element */
        if (RD_NODE_USELESS == pnode->flag)
        {
            if (-1 == freeindex)
            {
                freeindex = iindex;
                NSSOC_LOGINF("free element index:%d was found", iindex);
            }
            continue;
        }

        /*if is using, and repeat just set flag */
        if (RD_NODE_USING == pnode->flag)
        {
            if (pnode->data.proto_data.value == data->value
                && pnode->data.proto_data.attr == data->attr)
            {
                NSSOC_LOGWAR("find duplicate node, proto:%u", data->value);
                repeatflag = 1;
            }
            continue;
        }

        /*if flag is deleting, just update the age time, if agetime is on, just set flag to free */
        if (RD_NODE_DELETING == pnode->flag)
        {
            pnode->agetime++;
            if (pnode->agetime >= RD_AGE_MAX_TIME)
            {
                pnode->flag = RD_NODE_USELESS;
                NSSOC_LOGINF("goint to free node at index:%d", iindex);
            }
            /*record delete time */
            if (agetime < pnode->agetime)
            {
                agetime = pnode->agetime;
                ageindex = iindex;
            }
            continue;
        }
    }

    /*if repeat, just return */
    if (1 == repeatflag)
    {
        return 0;
    }
    if (-1 == freeindex)
    {
        if (-1 != ageindex)
        {
            freeindex = ageindex;
        }
        else
        {
            NSSOC_LOGERR("the rd route table:%p is full", handle);
            return -1;
        }
    }
    pnode = &(handle->node[freeindex]);
    /*if no free found, just reuse the big agetime */
    dmm_spin_lock_with_pid(&handle->rd_lock);
    if (EOK != strcpy_s(pnode->data.stack_name, RD_PLANE_NAMELEN, name))
    {
        NSSOC_LOGERR("strcpy_s failed]copy_name=%s", name);
    }
    pnode->data.type = RD_DATA_TYPE_PROTO;
    pnode->data.proto_data.value = data->value;
    pnode->data.proto_data.attr = data->attr;
    pnode->flag = RD_NODE_USING;        /*last set */
    handle->icnt++;
    __sync_fetch_and_add(&handle->rdtbl_ver, 1);
    dmm_spin_unlock(&handle->rd_lock);
    NSSOC_LOGINF("nstack=%s, proto:%u attr:%u was inserted", name,
                 data->value, data->attr);
    return 0;
}

int nstack_rd_proto_node_delete(rd_proto_data * data, void *table)
{
    int iindex = 0;
    rd_route_table *handle = (rd_route_table *) table;
    rd_route_node *pnode = NULL;

    if (!handle || !data)
    {
        NSSOC_LOGERR("invalid parameters");
        return -1;
    }

    for (iindex = 0; iindex < NSTACK_RD_DATA_MAX; iindex++)
    {
        pnode = &(handle->node[iindex]);
        if ((RD_NODE_USING == pnode->flag)
            && pnode->data.proto_data.value == data->value
            && pnode->data.proto_data.attr == data->attr)
        {
            dmm_spin_lock_with_pid(&handle->rd_lock);
            pnode->flag = RD_NODE_DELETING;     /*just set deleting state */
            pnode->agetime = 0;
            handle->icnt--;
            NSSOC_LOGINF
                ("nstack rd:%s, proto:%u, attr:%u at index:%d will be deleted",
                 pnode->data.stack_name, data->value, data->attr, iindex);
            __sync_fetch_and_add(&handle->rdtbl_ver, 1);
            dmm_spin_unlock(&handle->rd_lock);
            NSSOC_LOGINF
                ("nstack rd:%s, proto:%u, attr:%u at index:%d was deleted",
                 pnode->data.stack_name, data->value, data->attr, iindex);
            return 0;
        }
    }
    NSSOC_LOGINF("nstack rd delete, proto:%u attr:%u was not found",
                 data->value, data->attr);
    return 0;
}
