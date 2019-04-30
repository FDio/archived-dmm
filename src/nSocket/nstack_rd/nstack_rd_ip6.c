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
#include "nstack_rd_data.h"
#include "nstack_rd.h"
#include "nstack_rd_priv.h"
#include "nstack_rd_ip6.h"
#include "nstack_log.h"
#include "nstack_securec.h"
#include "nstack_ip_addr.h"

inline static const char *ip6_ntoa(const ip6_addr_t * addr)
{
#define IP6_NTOA_NUM (1 << 3)
#define IP6_NTOA_LEN 46
    static __thread char ip6_ntoa_buf[IP6_NTOA_NUM][IP6_NTOA_LEN];
    static __thread unsigned int ip6_ntoa_index = 0;

    char *buf = ip6_ntoa_buf[(ip6_ntoa_index++) & (IP6_NTOA_NUM - 1)];
    return inet_ntop(AF_INET, addr, buf, IP6_NTOA_LEN);
}

int nstack_rd_ip6_data_cpy(void *destdata, void *srcdata)
{
    rd_data_item *pitem = (rd_data_item *) destdata;
    rd_route_data *pdata = (rd_route_data *) srcdata;

    pitem->type = pdata->type;
    pitem->ip6data = pdata->ip6data;
    return NSTACK_RD_SUCCESS;
}

/*
 * Add an ip segment to the list and sort it in descending order of ip mask length
 * If the list already exists in the same list of ip side, then stack_id update
 * ip is network byte order
 */
/*vars are used in macro*/
int nstack_rd_ip6_item_insert(nstack_rd_list * hlist, void *rditem)
{
    nstack_rd_node *pdatanode = NULL;
    nstack_rd_node *tempdata = NULL;
    struct hlist_node *tempnode = NULL;
    struct hlist_node *tem = NULL;
    rd_data_item *pitem = (rd_data_item *) rditem;
    char buf[52];

    NSSOC_LOGDBG("stackid:%d, ip6addr:%s masklen:0x%x was inserted",
                 pitem->stack_id, inet_ntop(AF_INET6, &pitem->ip6data.addr,
                                            buf, sizeof(buf)),
                 pitem->ip6data.masklen);

    pdatanode = (nstack_rd_node *) malloc(sizeof(nstack_rd_node));      /*this function is necessary */
    if (!pdatanode)
    {
        NSSOC_LOGERR("nstack rd item malloc fail");
        return NSTACK_RD_FAIL;
    }

    int retVal = memset_s(pdatanode, sizeof(nstack_rd_node), 0,
                          sizeof(nstack_rd_node));
    if (EOK != retVal)
    {
        NSSOC_LOGERR("memset_s failed]retVal=%d", retVal);
        free(pdatanode);        /*this function is necessary */
        return NSTACK_RD_FAIL;
    }

    INIT_HLIST_NODE(&pdatanode->rdnode);
    pdatanode->item = *pitem;

    if (hlist_empty(&(hlist->headlist)))
    {
        hlist_add_head(&(pdatanode->rdnode), &(hlist->headlist));

        return NSTACK_RD_SUCCESS;

    }

    hlist_for_each_entry(tempdata, tempnode, &(hlist->headlist), rdnode)
    {
        tem = tempnode;
        if (pitem->ip6data.masklen < tempdata->item.ip6data.masklen)
        {
            continue;
        }

        /*if already exist, just return success */
        if (pitem->ip6data.masklen == tempdata->item.ip6data.masklen &&
            ip6_addr_match(&pitem->ip6data.addr,
                           &tempdata->item.ip6data.addr,
                           pitem->ip6data.masklen))
        {
            NSSOC_LOGDBG
                ("insert ip6:%s, mask:0x%x, stack_id:%d, exist orgid:%d",
                 inet_ntop(AF_INET6, &pitem->ip6data.addr, buf,
                           sizeof(buf)), pitem->ip6data.masklen,
                 pitem->stack_id, tempdata->item.stack_id);

            tempdata->item.stack_id = pitem->stack_id;
            tempdata->item.agetime = NSTACK_RD_AGETIME_MAX;
            free(pdatanode);    /*this function is necessary */
            return NSTACK_RD_SUCCESS;
        }
        hlist_add_before(&(pdatanode->rdnode), tempnode);

        return NSTACK_RD_SUCCESS;

    }
    hlist_add_after(tem, &(pdatanode->rdnode));

    return NSTACK_RD_SUCCESS;

}

int nstack_rd_ip6_item_age(nstack_rd_list * hlist)
{
    struct hlist_node *tempnode = NULL;
    nstack_rd_node *tempdata = NULL;
    nstack_rd_node *prevdata = NULL;
    struct hlist_node *prevnode = NULL;
    char buf[46];

    NSSOC_LOGINF("nstack rd ip age begin");
    hlist_for_each_entry(tempdata, tempnode, &(hlist->headlist), rdnode)
    {
        /*if agetime equal 0, remove it */
        if (tempdata->item.agetime <= 0)
        {
            if (prevdata)
            {
                NSSOC_LOGDBG("stackid:%d, addrip6:%s, masklen:0x%x was aged",
                             tempdata->item.stack_id,
                             inet_ntop(AF_INET6,
                                       &tempdata->item.ip6data.addr, buf,
                                       sizeof(buf)),
                             tempdata->item.ip6data.masklen);

                hlist_del_init(prevnode);
                free(prevdata); /*this function is necessary */
            }
            prevdata = tempdata;
            prevnode = tempnode;
        }
        else
        {
            tempdata->item.agetime--;
        }
    }
    if (prevdata)
    {
        if (tempdata)
        {
            NSSOC_LOGDBG
                ("stackid:%d, addrip6:%s, masklen:0x%x was last aged",
                 tempdata->item.stack_id, inet_ntop(AF_INET6,
                                                    &tempdata->item.
                                                    ip6data.addr, buf,
                                                    sizeof(buf)),
                 tempdata->item.ip6data.masklen);
        }
        hlist_del_init(prevnode);
        free(prevdata);         /*this function is necessary */
    }

    NSSOC_LOGINF("nstack rd ip age end");
    return NSTACK_RD_SUCCESS;
}

void nstack_rd_ip6_item_clean(nstack_rd_list * hlist)
{
    struct hlist_node *tempnode = NULL;
    nstack_rd_node *tempdata = NULL;
    nstack_rd_node *prevdata = NULL;
    struct hlist_node *prevnode = NULL;
    char buf[46];

    NSSOC_LOGINF("nstack rd ip clean begin");
    hlist_for_each_entry(tempdata, tempnode, &(hlist->headlist), rdnode)
    {
        if (prevdata)
        {
            NSSOC_LOGDBG("stackid:%d, addrip6:%s, masklen:0x%x was aged",
                         tempdata->item.stack_id,
                         inet_ntop(AF_INET6, &tempdata->item.ip6data.addr,
                                   buf, sizeof(buf)),
                         tempdata->item.ip6data.masklen);

            hlist_del_init(prevnode);
            free(prevdata);     /*this function is necessary */
        }

        prevdata = tempdata;
        prevnode = tempnode;
    }
    if (prevdata)
    {
        if (tempdata)
        {
            NSSOC_LOGDBG
                ("stackid:%d, addrip6:%s, masklen:0x%x was last aged",
                 tempdata->item.stack_id, inet_ntop(AF_INET6,
                                                    &tempdata->item.
                                                    ip6data.addr, buf,
                                                    sizeof(buf)),
                 tempdata->item.ip6data.masklen);
        }
        hlist_del_init(prevnode);
        free(prevdata);         /*this function is necessary */
    }

    NSSOC_LOGINF("nstack rd ip clean end");
}

int nstack_rd_ip6_item_find(nstack_rd_list * hlist, void *rdkey,
                            void *outitem)
{
    struct hlist_node *tempnode = NULL;
    nstack_rd_node *tempdata = NULL;
    nstack_rd_key *key = (nstack_rd_key *) rdkey;
    char buf[46];

    hlist_for_each_entry(tempdata, tempnode, &(hlist->headlist), rdnode)
    {
        rd_data_item *tempitem = &tempdata->item;

        /*if already exist, just return success */
        if (ip6_addr_match
            ((struct ip6_addr *) &key->in6_addr, &tempitem->ip6data.addr,
             tempitem->ip6data.masklen))
        {
            *(rd_data_item *) outitem = *tempitem;
            return NSTACK_RD_SUCCESS;
        }
    }

    NSSOC_LOGDBG("ip6=%s item not found",
                 inet_ntop(AF_INET6, &key->in6_addr, buf, sizeof(buf)));

    return NSTACK_RD_FAIL;
}

int nstack_rd_ip6_spec(void *rdkey)
{
    return -1;
}
