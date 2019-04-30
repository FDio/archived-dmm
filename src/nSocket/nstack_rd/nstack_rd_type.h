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

#ifndef __NSTACK_RD_TYPE_H
#define __NSTACK_RD_TYPE_H

#include "nstack_rd_priv.h"

#define NSTACK_RD_TYPE_ITEM_COPY(destitem, srcitem){  \
        (destitem)->agetime = (srcitem)->agetime;  \
        (destitem)->stack_id = (srcitem)->stack_id;  \
        (destitem)->type = (srcitem)->type;   \
        (destitem)->type_data.value = (srcitem)->type_data.value;  \
        (destitem)->type_data.attr = (srcitem)->type_data.attr;   \
        (destitem)->type_data.reserved[0] = (srcitem)->type_data.reserved[0];   \
        (destitem)->type_data.reserved[1] = (srcitem)->type_data.reserved[1];   \
        (destitem)->type_data.reserved[2] = (srcitem)->type_data.reserved[2];   \
        (destitem)->type_data.reserved[3] = (srcitem)->type_data.reserved[3];   \
}

int nstack_rd_type_data_cpy(void *destdata, void *srcdata);
int nstack_rd_type_item_insert(nstack_rd_list * hlist, void *rditem);
int nstack_rd_type_item_find(nstack_rd_list * hlist, void *rdkey,
                             void *outitem);
int nstack_rd_type_item_age(nstack_rd_list * hlist);
void nstack_rd_type_item_clean(nstack_rd_list * hlist);
int nstack_rd_type_spec(void *rdkey);

#endif
