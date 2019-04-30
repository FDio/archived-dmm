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
#include "nstack_rd.h"
#include "nstack_rd_priv.h"
#include "nstack_rd_ip.h"
#include "nstack_rd_ip6.h"
#include "nstack_rd_type.h"
#include "nstack_rd_proto.h"
#include "nstack_log.h"
#include "nstack_securec.h"
#include <arpa/inet.h>

extern rd_route_table *g_rd_table_handle[];

rd_local_data *g_rd_local_data = NULL;

rd_data_proc g_rd_cpy[RD_DATA_TYPE_MAX] = {
    {
     nstack_rd_ip_data_cpy,
     nstack_rd_ip_item_insert,
     nstack_rd_ip_item_age,
     nstack_rd_ip_item_clean,
     nstack_rd_ip_item_find,
     nstack_rd_ip_spec,
     },
    {
     nstack_rd_ip6_data_cpy,
     nstack_rd_ip6_item_insert,
     nstack_rd_ip6_item_age,
     nstack_rd_ip6_item_clean,
     nstack_rd_ip6_item_find,
     nstack_rd_ip6_spec,
     },
    {
     nstack_rd_type_data_cpy,
     nstack_rd_type_item_insert,
     nstack_rd_type_item_age,
     nstack_rd_type_item_clean,
     nstack_rd_type_item_find,
     nstack_rd_type_spec,
     },
    {
     nstack_rd_proto_data_cpy,
     nstack_rd_proto_item_insert,
     nstack_rd_proto_item_age,
     nstack_rd_proto_item_clean,
     nstack_rd_proto_item_find,
     nstack_rd_proto_spec,
     }
};

int nstack_choose_highest_prio()
{
    int i;
    int ret = 0;
    int highest = 0x7FFFFFFF;
    nstack_rd_stack_info *stack_info = g_rd_local_data->pstack_info;

    for (i = 0; i < NSTACK_NUM; i++)
    {
        if (stack_info[i].priority < highest)
        {
            highest = stack_info[i].priority;
            ret = i;
        }
    }
    return ret;
}

/*****************************************************************************
*   Prototype    : nstack_rd_get_stackid
*   Description  : choose the stack by key, type is the most important
*   Input        : nstack_rd_key* pkey
*                  int *stackid
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int nstack_rd_get_stackid(nstack_rd_key * pkey, rd_data_item * item)
{
    int accumulate = 0;
    int icnt = 0;
    int type = 0;
    int ret = NSTACK_RD_SUCCESS;
    int rdtbl_ver = 0;
    if ((!pkey) || (!item) || (pkey->type >= RD_DATA_TYPE_MAX))
    {
        NSSOC_LOGERR("input get stackid fail]addr=%p,item=%p,addr->type=%d",
                     pkey, item, !pkey ? RD_DATA_TYPE_MAX : pkey->type);
        return NSTACK_RD_FAIL;
    }
    /*add return value check */
    int retVal =
        memset_s(item, sizeof(rd_data_item), 0, sizeof(rd_data_item));
    if (EOK != retVal)
    {
        NSSOC_LOGERR("memset_s failed]retVal=%d", retVal);
        return NSTACK_RD_FAIL;
    }
    item->stack_id = -1;
    type = pkey->type;

    /*specfic key find, for ip example: stackpool was chose if the key is multicast ip */
    if (g_rd_cpy[type].rd_item_spec)
    {
        ret = g_rd_cpy[type].rd_item_spec((void *) pkey);
        if (ret >= 0)
        {
            item->stack_id = ret;
            return NSTACK_RD_SUCCESS;
        }
    }

    /*check ver */
    for (icnt = 0; icnt < NSTACK_NUM; icnt++)
    {
        retVal =
            g_rd_local_data->rdtbl_ver_get_fun(&rdtbl_ver,
                                               g_rd_table_handle[icnt]);
        if (retVal)
        {
            NSSOC_LOGWAR("stackid=%d get rd table ver failed!",
                         g_rd_local_data->pstack_info->stack_id);
            if (++accumulate < NSTACK_NUM)
            {
                continue;
            }
            NSSOC_LOGERR("rd table ver get failed");
            return NSTACK_RD_FAIL;
        }
        if (g_rd_local_data->rdlocal_ver[icnt] != rdtbl_ver)
        {
            NSSOC_LOGINF
                ("RD table ver unmatch]new rd tlbver:%d,local rd tblver:%d,resync now",
                 rdtbl_ver, g_rd_local_data->rdlocal_ver[icnt]);
            ret = nstack_rd_sys();
            if (ret != NSTACK_RD_SUCCESS)
            {
                item->stack_id = nstack_choose_highest_prio();
                NSSOC_LOGERR
                    ("sync RD INF failed, choose highest priority stack, stackid=%d",
                     item->stack_id);
                return NSTACK_RD_SUCCESS;
            }
        }
    }

    /*search the list */
    ret =
        g_rd_cpy[type].rd_item_find(NSTACK_RD_LIST(type), (void *) pkey,
                                    item);
    if (NSTACK_RD_SUCCESS == ret)
    {
        NSSOC_LOGDBG("item type=%d stackid=%d was found", pkey->type,
                     item->stack_id);
        return NSTACK_RD_SUCCESS;
    }
    item->stack_id = nstack_choose_highest_prio();
    NSSOC_LOGINF
        ("item type=%d was not found, choose highest priority stack by default, stackid=%d",
         pkey->type, item->stack_id);
    return NSTACK_RD_SUCCESS;
}

static char *nstack_rd_parse_ip(char *pos, unsigned int *ip)
{
    char buf[16];
    char *p;
    int len, ret;

    if (!pos)
        return NULL;

    p = strchr(pos, '/');
    if (!p)
        return NULL;

    len = p - pos;
    if (len >= 16)
        return NULL;

    ret = memcpy_s(buf, sizeof(buf), pos, len);
    if (EOK != ret)
    {
        return NULL;
    }

    buf[len] = 0;

    ret = inet_pton(AF_INET, buf, ip);
    if (ret == 1)
        return p + 1;

    return NULL;

}

static char *nstack_rd_parse_ip6(char *pos, unsigned int ip[4])
{
    char buf[46];
    char *p;
    int len, ret;

    p = strchr(pos, '/');
    if (!p)
        return NULL;

    len = p - pos;
    if (len >= 46)
        return NULL;

    (void) memcpy_s(buf, sizeof(buf), pos, len);
    buf[len] = 0;

    ret = inet_pton(AF_INET6, buf, ip);
    if (ret == 1)
        return p + 1;

    return NULL;
}

static char *nstack_rd_parse_stackid(char *pos, int *stack_id)
{
    size_t n = 0;
    int i;

    while (pos[n] != ':' && pos[n] != 0)
        n++;
    if (n == 0 || n >= RD_PLANE_NAMELEN)
        return NULL;

    for (i = 0; i < g_rd_local_data->stack_num; ++i)
    {
        /* params are not NULL */
        if (0 == strncmp(pos, g_rd_local_data->pstack_info[i].name, n))
        {
            *stack_id = g_rd_local_data->pstack_info[i].stack_id;
            return pos + n;
        }
    }

    return NULL;
}

static void nstack_rd_sys_load_default()
{
    char *env, *pos;

    env = getenv("NSTACK_RD");  /*this func can be used */

    if (!env || !env[0])
        return;

    pos = env;
    while (*pos)
    {
        rd_data_item item;
        char *pos6 = pos;

        pos = nstack_rd_parse_ip(pos, &item.ipdata.addr);
        if (pos)
        {
            item.type = RD_DATA_TYPE_IP;
            item.agetime = NSTACK_RD_AGETIME_MAX;
            item.ipdata.resev[0] = 0;
            item.ipdata.resev[1] = 0;
            item.ipdata.masklen = (unsigned int) strtoul(pos, &pos, 10);
            if (item.ipdata.masklen > 32 || *pos++ != '=')
            {
                NSSOC_LOGERR("nstack rd sys config error '%s'", env);
                return;
            }
        }
        else if (NULL !=
                 (pos = nstack_rd_parse_ip6(pos6, item.ip6data.addr.addr32)))
        {
            item.type = RD_DATA_TYPE_IP6;
            item.agetime = NSTACK_RD_AGETIME_MAX;
            item.ip6data.masklen = (unsigned int) strtoul(pos, &pos, 10);
            if (item.ip6data.masklen > 128 || *pos++ != '=')
            {
                NSSOC_LOGERR("nstack rd sys config error '%s'", env);
                return;
            }
        }
        else
        {
            NSSOC_LOGERR("nstack rd sys config error '%s'", env);
            return;
        }

        pos = nstack_rd_parse_stackid(pos, &item.stack_id);
        if (!pos)
        {
            NSSOC_LOGERR("nstack rd sys config error '%s'", env);
            return;
        }

        (void) g_rd_cpy[item.type].rd_item_insert(NSTACK_RD_LIST(item.type),
                                                  &item);

        if (item.type == RD_DATA_TYPE_IP6)
        {
            char buf[46];
            NSSOC_LOGINF("insert one RD %d=%s/%u", item.stack_id,
                         inet_ntop(AF_INET6, &item.ip6data.addr, buf,
                                   sizeof(buf)), item.ip6data.masklen);
        }
        else
        {
            NSSOC_LOGINF("insert one RD %d:%u.%u.%u.%u/%u", item.stack_id,
                         item.ipdata.addr >> 24,
                         (item.ipdata.addr >> 16) & 255,
                         (item.ipdata.addr >> 8) & 255,
                         item.ipdata.addr & 255, item.ipdata.masklen);
        }

        if (*pos == ':')
            pos++;
    }
}

static void nstack_rd_sys_clean()
{
    int type;
    for (type = 0; type < RD_DATA_TYPE_MAX; type++)
    {
        if (!hlist_empty(&(NSTACK_RD_LIST(type)->headlist)))
        {
            g_rd_cpy[type].rd_item_clean(NSTACK_RD_LIST(type));
        }
    }
}

static int nstack_rd_ip_get(rd_route_data ** data, int *num, int *ver,
                            rd_route_table * handle)
{
    rd_route_data *pdata = NULL;
    rd_route_node *pnode = NULL;
    size_t size = 0;
    int icnt = 0;
    int idex = 0;
    int ret;
    int rdver = 0;

    if (!handle || !data || !num || !ver)
    {
        NSSOC_LOGERR("nstack rd mng not inited or input err");
        return -1;
    }
    dmm_spin_lock_with_pid(&handle->rd_lock);
    size = sizeof(rd_route_data) * handle->size;
    pdata = (rd_route_data *) malloc(size);
    if (!pdata)
    {
        dmm_spin_unlock(&handle->rd_lock);
        NSSOC_LOGERR("rd route data malloc fail");
        return -1;
    }
    ret = memset_s(pdata, size, 0, size);
    if (EOK != ret)
    {
        dmm_spin_unlock(&handle->rd_lock);
        NSSOC_LOGERR("memset_s failed]ret=%d", ret);
        free(pdata);
        return -1;
    }
    for (icnt = 0; icnt < handle->size; icnt++)
    {
        pnode = &(handle->node[icnt]);
        if (RD_NODE_USING == pnode->flag)
        {
            pdata[idex] = pnode->data;
            idex++;
        }
    }
    rdver = handle->rdtbl_ver;
    dmm_spin_unlock(&handle->rd_lock);
    /*if no data fetched , just return fail */
    if (idex == 0)
    {
        free(pdata);
        return -1;
    }
    *data = pdata;
    *num = idex;
    *ver = rdver;
    return 0;
}

static int nstack_rd_tblver_get(int *ver, rd_route_table * handle)
{
    if (!handle || !ver)
    {
        NSSOC_LOGERR("nstack rd mng not inited or input err");
        return -1;
    }
    *ver = handle->rdtbl_ver;
    return 0;
}

int nstack_rd_init(nstack_rd_stack_info * pstack, int num)
{
    int icnt = 0;
    nstack_rd_stack_info *ptemstack = NULL;
    int *rd_ver = NULL;

    if (!pstack)
    {
        NSSOC_LOGERR("input err pstack:%p", pstack);
        return NSTACK_RD_FAIL;
    }
    g_rd_local_data = (rd_local_data *) malloc(sizeof(rd_local_data));
    if (!g_rd_local_data)
    {
        NSSOC_LOGERR("g_rd_local_data alloc fail");
        return NSTACK_RD_FAIL;
    }

    /*add return value check */
    if (EOK !=
        memset_s((void *) g_rd_local_data, sizeof(rd_local_data), 0,
                 sizeof(rd_local_data)))
    {
        NSSOC_LOGERR("memset_s fail");
        goto ERR;
    }

    g_rd_local_data->sys_fun = nstack_rd_ip_get;
    g_rd_local_data->rdtbl_ver_get_fun = nstack_rd_tblver_get;

    ptemstack =
        (nstack_rd_stack_info *) malloc(sizeof(nstack_rd_stack_info) * num);
    if (!ptemstack)
    {
        NSSOC_LOGERR("rd stack info malloc fail");
        goto ERR;
    }

    if (EOK !=
        memcpy_s(ptemstack, sizeof(nstack_rd_stack_info) * num, pstack,
                 sizeof(nstack_rd_stack_info) * num))
    {
        NSSOC_LOGERR("memcpy_s failed!");
        goto ERR;
    }

    g_rd_local_data->pstack_info = ptemstack;
    g_rd_local_data->stack_num = num;

    rd_ver = (int *) malloc(sizeof(int) * NSTACK_NUM);  /*this function is necessary */
    if (!rd_ver)
    {
        NSSOC_LOGERR("rd_ver alloc failed!");
        goto ERR;
    }
    if (EOK !=
        memset_s((void *) rd_ver, sizeof(int) * NSTACK_NUM, 0,
                 sizeof(int) * NSTACK_NUM))
    {
        NSSOC_LOGERR("memset_s failed!");
        goto ERR;
    }
    g_rd_local_data->rdlocal_ver = rd_ver;

    for (icnt = 0; icnt < RD_DATA_TYPE_MAX; icnt++)
    {
        INIT_HLIST_HEAD(&(g_rd_local_data->route_list[icnt].headlist));
    }
    return NSTACK_RD_SUCCESS;

  ERR:
    if (g_rd_local_data)
    {
        free(g_rd_local_data);
        g_rd_local_data = NULL;
    }
    if (ptemstack)
    {
        free(ptemstack);
    }
    if (rd_ver)
    {
        free(rd_ver);           /*this function is necessary */
    }
    return NSTACK_RD_FAIL;
}

/*****************************************************************************
*   Prototype    : nstack_rd_sys
*   Description  : sys rd data from rd table,
*   Input        : None
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int nstack_rd_sys()
{
    rd_route_data *rd_data = NULL;
    nstack_rd_stack_info *prdstack = NULL;
    int icnt = 0;
    int inum = 0;
    int iver = 0;
    int iret = 0;
    int iindex = 0;
    rd_data_item item;
    rd_data_type type = RD_DATA_TYPE_MAX;

    if (!g_rd_local_data)
    {
        NSSOC_LOGERR("rd have not been inited");
        return NSTACK_RD_FAIL;
    }
    /*add return value check */
    int retVal = memset_s(&item, sizeof(item), 0, sizeof(item));
    if (EOK != retVal)
    {
        NSSOC_LOGERR("memset_s failed]retVal=%d", retVal);
        return NSTACK_RD_FAIL;
    }
    nstack_rd_sys_clean();

    nstack_rd_sys_load_default();

    prdstack = g_rd_local_data->pstack_info;
    for (icnt = 0; icnt < NSTACK_NUM; icnt++)
    {
        if (!g_rd_table_handle[icnt])
        {
            continue;
        }
        /*get from rd table */
        iret =
            g_rd_local_data->sys_fun(&rd_data, &inum, &iver,
                                     g_rd_table_handle[icnt]);
        if (NSTACK_RD_SUCCESS != iret)
        {
            NSSOC_LOGERR("nstack rd sys rd info stack fail] stack=%s",
                         prdstack[icnt].name);
            return NSTACK_RD_FAIL;
        }
        NSSOC_LOGINF
            ("nstack rd sync sucess] stack=%s, rdtable ver:%d, rdtable size:%d",
             prdstack[icnt].name, iver, inum);

        g_rd_local_data->rdlocal_ver[icnt] = iver;
        if (inum <= 0)
        {
            NSSOC_LOGDBG("no rd data got");
            if (rd_data)
            {
                free(rd_data);  /*this function is necessary */
                rd_data = NULL;
            }
            continue;
        }
        for (iindex = 0; iindex < inum; iindex++)
        {
            if (rd_data[iindex].type >= RD_DATA_TYPE_MAX)
            {
                NSSOC_LOGERR("rd data type=%d unkown", rd_data[iindex].type);
                continue;
            }
            type = rd_data[iindex].type;
            if (NSTACK_RD_SUCCESS ==
                g_rd_cpy[type].rd_item_copy((void *) &item,
                                            (void *) &rd_data[iindex]))
            {
                item.agetime = NSTACK_RD_AGETIME_MAX;
                item.stack_id = prdstack[icnt].stack_id;
                /*insert to the list */
                g_rd_cpy[type].rd_item_insert(NSTACK_RD_LIST(type), &item);     /*do not need return value */
                continue;
            }
            NSSOC_LOGERR("rd data type=%d cpy fail", rd_data[iindex].type);
        }
        free(rd_data);          /*this function is necessary */
        rd_data = NULL;
    }
    /*age after sys */
    nstack_rd_age();            /*do not need return value */
    return NSTACK_RD_SUCCESS;
}

/*****************************************************************************
*   Prototype    : nstack_rd_age
*   Description  : delete all rd item from the list that not been add again
                   for at least one time
*   Input        : None
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int nstack_rd_age()
{
    int icnt = 0;
    for (icnt = 0; icnt < RD_DATA_TYPE_MAX; icnt++)
    {
        if (g_rd_cpy[icnt].rd_item_age)
            (void) g_rd_cpy[icnt].rd_item_age(NSTACK_RD_LIST(icnt));
    }
    return NSTACK_RD_SUCCESS;
}

int nstack_rd_match_pre(int domain, int type, int protocol,
                        rd_data_item * item)
{
    int ret = -1;
    nstack_rd_key key = { 0 };

    key.type = RD_DATA_TYPE_TYPE;
    key.socket_type = type;
    ret =
        g_rd_cpy[key.type].rd_item_find(NSTACK_RD_LIST(key.type),
                                        (void *) &key, (void *) item);
    if (ret == NSTACK_RD_SUCCESS)
    {
        return item->stack_id;
    }

    key.type = RD_DATA_TYPE_PROTO;
    key.proto = protocol;
    ret =
        g_rd_cpy[key.type].rd_item_find(NSTACK_RD_LIST(key.type),
                                        (void *) &key, (void *) item);
    if (ret == NSTACK_RD_SUCCESS)
    {
        return item->stack_id;
    }

    return -1;
}
