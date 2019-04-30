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

#ifndef __NSTACK_RD_H
#define __NSTACK_RD_H

#include <sys/socket.h>
#include <netinet/in.h>
#include "nstack_rd_priv.h"

/*look up chose info by key*/
typedef struct __nstack_rd_key
{
    int type;
    union
    {
        unsigned int ip_addr;
        int socket_type;
        int proto;
        struct in6_addr in6_addr;
    };
} nstack_rd_key;

/*
 *rd synchronism
 *
 */
int nstack_rd_init(nstack_rd_stack_info * pstack, int num);
int nstack_rd_sys();
int nstack_rd_age();
int nstack_rd_match_pre(int domain, int type, int protocol,
                        rd_data_item * item);

/*
 *get stackid by some info
 *if input is ip, the value must be net order
 *
 */
int nstack_rd_get_stackid(nstack_rd_key * addr, rd_data_item * item);

#endif
