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

#include "nstack_securec.h"
#include "nsfw_snapshot_api.h"
#include "nstack_log.h"
#include "fw_snapshot.h"

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C"{
/* *INDENT-ON* */
#endif /* __cplusplus */

nsfw_ss_obj_desc_manager_t g_nsfw_ss_obj_desc_manager =
    {.g_nsfw_ss_obj_des_num = 0 };

void nsfw_ss_register_obj_desc(nsfw_ss_obj_desc_t * objDesc)
{
    if (objDesc == NULL)
        return;

    nsfw_ss_obj_desc_manager_t *manager = nsfw_ss_get_obj_desc_manager_inst();

    if (manager->g_nsfw_ss_obj_des_num >= NSFW_SS_MAX_OBJDESC_NUM)
        return;

    manager->g_nsfw_ss_obj_descs[manager->g_nsfw_ss_obj_des_num++] = objDesc;
}

static nsfw_ss_obj_desc_t *nsfw_ss_get_obj_desc_from_type(u16 objType)
{
    nsfw_ss_obj_desc_manager_t *manager = nsfw_ss_get_obj_desc_manager_inst();
    int i;
    for (i = 0;
         i < manager->g_nsfw_ss_obj_des_num && i < NSFW_SS_MAX_OBJDESC_NUM;
         i++)
    {
        if (manager->g_nsfw_ss_obj_descs[i]->objType == objType)
            return manager->g_nsfw_ss_obj_descs[i];
    }
    return NULL;
}

static nsfw_ss_obj_mem_desc_t *nsfw_ss_get_mem_desc_from_type(u16 objType,
                                                              nsfw_ss_obj_desc_t
                                                              * objDesc)
{
    int i;
    for (i = 0; i < objDesc->memNum; i++)
    {
        if (objDesc->memDesc[i].type == objType)
        {
            return &objDesc->memDesc[i];
        }
    }
    return NULL;
}

/**
 * @Function    nsfw_ss_store
 * @Description store object to memory
 * @param (in)  objType - type of object with member description
 * @param (in)  obj - adderss of object memory
 * @param (in)  storeMem - address of memory to store object data
 * @param (in)  storeMemLen - maximal length of storage memory
 * @return positive integer means length of memory cost on success. return -1 if error
 */
int nsfw_ss_store_obj_mem(u16 objMemType, void *obj, void *storeMem,
                          u32 storeMemLen)
{
    if (NULL == obj || NULL == storeMem)
    {
        return -1;
    }

    // example of object
    /* struct A{                                                        */
    /*           int a1;                                                */
    /*           struct A2 a2;  --> struct A2 {int a2}                  */
    /*           struct A3 a3[2]; --> struct A3 [{int a3}, {int a3}]    */
    /* }                                                                */

    /* -------------------------------------------- */
    /* |     type(object)     |       length      | */
    /* |  --------------------------------------  | */// --
    /* |  |   type(item)      |       length   |  | */// member a1
    /* |  |   item value (object->member)      |  | */// --
    /* |  --------------------------------------  | */// object a2
    /* |  |   type(object)    |     length     |  | *///  --
    /* |  |  -------------------------------   |  | *///   member a2
    /* |  |  | type(item)   |       length |   |  | *///  --
    /* |  |  | item value (object->member) |   |  | */// --
    /* |  |  -------------------------------   |  | */
    /* |  --------------------------------------  | */
    /* |  |  type(object array)  |    length   |  | */// array member a3
    /* |  |  -------------------------------   |  | *///  --
    /* |  |  | type(object)   |   length   |   |  | *///  object a3_1
    /* |  |  | ----------------------------|   |  | *///    --
    /* |  |  | type(item)   |       length |   |  | *///     member a3_1_1
    /* |  |  | item value (object->member) |   |  | */
    /* |  |  | ----------------------------|   |  | */
    /* |  |  -------------------------------   |  | */
    /* |  |  | type(object)   |   length   |   |  | */
    /* |  |  | ----------------------------|   |  | */
    /* |  |  | type(item)   |       length |   |  | */
    /* |  |  | item value (object->member) |   |  | */
    /* |  |  | ----------------------------|   |  | */
    /* |  |  -------------------------------   |  | */
    /* |  |------------------------------------|  | */
    /* -------------------------------------------- */

    nsfw_ss_obj_desc_t *objDesc =
        nsfw_ss_get_obj_desc_from_type(NSFW_SS_TYPE_GETOBJ(objMemType));
    if (NULL == objDesc)
        return -1;

    /* Get object header tlv */
    if (storeMemLen < tlv_header_length())
        return -1;
    nsfw_ss_tlv_t *tlv = (nsfw_ss_tlv_t *) storeMem;
    tlv->type = objMemType;
    tlv->length = 0;

    tlv_header(storeMem);
    storeMemLen -= tlv_header_length();

    /* Search every object member */

    /* For base item(including array of base item), it should start with a tlv header */
    /* For object array, it should start with one tlv header including array information */
    /* For object, it should call nsfw_ss_store recursively */

    int i;
    for (i = 0; i < objDesc->memNum; i++)
    {
        nsfw_ss_obj_mem_desc_t *memDesc = &objDesc->memDesc[i];

        if (NSFW_SS_TYPE_IS_MEMBER_OBJ(memDesc->type))
        {

            if (NSFW_SS_TYPE_IS_MEMBER_ARRAY(memDesc->type))
            {
                /* array object should includes one array tlv header, shows the array informations */

                if (storeMemLen < tlv_header_length())
                    return -1;

                nsfw_ss_tlv_t *arrayTlv = (nsfw_ss_tlv_t *) storeMem;
                arrayTlv->type = memDesc->type;
                arrayTlv->length = 0;

                tlv_header(storeMem);
                storeMemLen -= tlv_header_length();

                nsfw_ss_obj_desc_t *memObjDesc =
                    nsfw_ss_get_obj_desc_from_type(NSFW_SS_TYPE_GETOBJ
                                                   (memDesc->type));
                if (NULL == memObjDesc)
                    return -1;

                u32 arraySize = memDesc->length / memObjDesc->objSize;
                u32 j;
                for (j = 0; j < arraySize; j++)
                {
                    int ret =
                        nsfw_ss_store_obj_mem(NSFW_SS_TYPE_SET_MEMBER_OBJ
                                              (NSFW_SS_TYPE_GETOBJ
                                               (memDesc->type), 0),
                                              (char *) obj +
                                              (u64) (memDesc->offset) +
                                              (u64) j * memObjDesc->objSize,
                                              storeMem,
                                              storeMemLen);

                    if ((-1 == ret) || (storeMemLen < (u32) ret))
                        return -1;

                    tlv_mem_forward(storeMem, ret);
                    storeMemLen -= (u32) ret;
                    arrayTlv->length += (u32) ret;
                }

                tlv->length += (arrayTlv->length + (u32) tlv_header_length());
            }
            else
            {
                int ret = nsfw_ss_store_obj_mem(memDesc->type,
                                                ((char *) obj +
                                                 memDesc->offset),
                                                storeMem, storeMemLen);
                if (ret < 0 || (storeMemLen < (u32) ret))
                    return -1;

                storeMemLen -= (u32) ret;
                tlv_mem_forward(storeMem, ret);
                tlv->length += (u32) ret;
            }
        }
        else
        {
            // Base Item
            if (storeMemLen < tlv_header_length())
            {
                return -1;
            }

            nsfw_ss_tlv_t *curtlv = (nsfw_ss_tlv_t *) storeMem; // curTlv means next tlv elem
            curtlv->type = memDesc->type;
            curtlv->length = memDesc->length;

            tlv_header(storeMem);
            storeMemLen -= tlv_header_length();

            if (storeMemLen < curtlv->length)
                return -1;

            if (EOK !=
                memcpy_s(storeMem, (size_t) storeMemLen,
                         ((char *) obj + memDesc->offset),
                         (size_t) memDesc->length))
            {
                return -1;
            }
            tlv_mem_forward(storeMem, memDesc->length);
            storeMemLen -= memDesc->length;
            tlv->length += (curtlv->length + (u32) tlv_header_length());
        }
    }

    return (int) (tlv->length + tlv_header_length());
}

/**
 * @Function    nsfw_ss_store
 * @Description store object to memory
 * @param (in)  objType - type of object
 * @param (in)  obj - adderss of object memory
 * @param (in)  storeMem - address of memory to store object data
 * @param (in)  storeMemLen - maximal length of storage memory
 * @return positive integer means length of memory cost on success. return -1 if error
 */
int nsfw_ss_store(u16 objType, void *obj, void *storeMem, u32 storeMemLen)
{
    return nsfw_ss_store_obj_mem(NSFW_SS_TYPE_SET_MEMBER_OBJ(objType, 0),
                                 obj, storeMem, storeMemLen);
}

/**
 * @Function        nsfw_ss_restore_obj_array
 * @Description     restore array of objects
 * @param (in)      objType - type of object
 * @param (in)      obj_update - memory of object/storage memory info
 * @return          0 on succss , -1 on error
 */
NSTACK_STATIC int nsfw_ss_restore_obj_array(int objType,
                                            nsfw_ss_obj_restore_t *
                                            obj_update)
{
    if (obj_update->storeMemLen < tlv_header_length())
        return -1;

    nsfw_ss_obj_restore_t obj_res = { NULL, NULL, 0, 0 };
    nsfw_ss_tlv_t *arrayTlv = (nsfw_ss_tlv_t *) (obj_update->mem);
    obj_update->storeMemLen -= tlv_header_length();
    tlv_header(obj_update->mem);
    if (0 == arrayTlv->length || obj_update->storeMemLen < arrayTlv->length)
        return -1;
    obj_update->storeMemLen = arrayTlv->length; // Only cares tlv->value

    nsfw_ss_obj_desc_t *objDesc =
        nsfw_ss_get_obj_desc_from_type((u16) objType);
    if (NULL == objDesc)
        return -1;

    /* Now we are going to iterate every object */
    u32 objCnt = 0;
    while (obj_update->storeMemLen)
    {
        if (obj_update->storeMemLen < tlv_header_length())
            return -1;          // Format error

        nsfw_ss_tlv_t *objTlv = (nsfw_ss_tlv_t *) (obj_update->mem);
        if ((int) NSFW_SS_TYPE_GETOBJ(objTlv->type) != objType)
        {
            return -1;
        }

        obj_res.objMem =
            (void *) ((char *) (obj_update->objMem) +
                      (u64) objDesc->objSize * objCnt);
        obj_res.mem = obj_update->mem;
        obj_res.storeMemLen = obj_update->storeMemLen;

        int ret = nsfw_ss_restore(&obj_res);
        if (-1 == ret)
            return -1;
        objCnt++;
        tlv_mem_forward(obj_update->mem,
                        (objTlv->length + tlv_header_length()));
        obj_update->storeMemLen -= (objTlv->length + tlv_header_length());
    }

    return 0;
}

/**
 * @Function    nsfw_ss_restore
 * @Description restore object from memory
 * @param (in)  obj_res - memory of object/storage memory info
 * @return  positive integer stands on object type, -1 on error
 */
int nsfw_ss_restore(nsfw_ss_obj_restore_t * obj_res)
{
    if (NULL == obj_res || NULL == obj_res->objMem || NULL == obj_res->mem
        || 0 == obj_res->storeMemLen)
        return -1;

    // example of object
    /* struct A{                                                        */
    /*           int a1;                                                */
    /*           struct A2 a2;  --> struct A2 {int a2}                  */
    /*           struct A3 a3[2]; --> struct A3 [{int a3}, {int a3}]    */
    /* }                                                                */

    /* -------------------------------------------- */// --
    /* |     type(object)     |       length      | */// type length
    /* |  --------------------------------------  | */// --
    /* |  |   type(item)      |       length   |  | */// member a1
    /* |  |   item value (object->member)      |  | */// --
    /* |  --------------------------------------  | */// object a2
    /* |  |   type(object)    |     length     |  | *///  --
    /* |  |  -------------------------------   |  | *///   member a2
    /* |  |  | type(item)   |       length |   |  | *///  --
    /* |  |  | item value (object->member) |   |  | */// --
    /* |  |  -------------------------------   |  | */
    /* |  --------------------------------------  | */
    /* |  |  type(object array)  |    length   |  | */// array member a3
    /* |  |  -------------------------------   |  | *///  --
    /* |  |  | type(object)   |   length   |   |  | *///  object a3_1
    /* |  |  | ----------------------------|   |  | *///    --
    /* |  |  | type(item)   |       length |   |  | *///     member a3_1_1
    /* |  |  | item value (object->member) |   |  | */
    /* |  |  | ----------------------------|   |  | */
    /* |  |  -------------------------------   |  | */
    /* |  |  | type(object)   |   length   |   |  | */
    /* |  |  | ----------------------------|   |  | */
    /* |  |  | type(item)   |       length |   |  | */
    /* |  |  | item value (object->member) |   |  | */
    /* |  |  | ----------------------------|   |  | */
    /* |  |  -------------------------------   |  | */
    /* |  |------------------------------------|  | */
    /* -------------------------------------------- */

    if (obj_res->storeMemLen < tlv_header_length())
        return -1;

    nsfw_ss_tlv_t *tlv = (nsfw_ss_tlv_t *) (obj_res->mem);
    obj_res->storeMemLen -= tlv_header_length();
    tlv_header(obj_res->mem);

    nsfw_ss_obj_restore_t obj_update = { NULL, NULL, 0, 0 };
    nsfw_ss_obj_desc_t *objDesc =
        nsfw_ss_get_obj_desc_from_type(NSFW_SS_TYPE_GETOBJ(tlv->type));
    if (NULL == objDesc)
    {
        return -1;
    }

    if (!NSFW_SS_TYPE_IS_MEMBER_OBJ(tlv->type))
        return -1;

    if (0 == tlv->length || obj_res->storeMemLen < tlv->length)
        return -1;

    /* Now we go to inner of object */
    obj_res->storeMemLen = tlv->length; /* Only care about tlv values */
    while (obj_res->storeMemLen)
    {
        if (obj_res->storeMemLen < tlv_header_length())
            return -1;          // Format error

        nsfw_ss_tlv_t *curtlv = (nsfw_ss_tlv_t *) (obj_res->mem);

        nsfw_ss_obj_mem_desc_t *memDesc =
            nsfw_ss_get_mem_desc_from_type(curtlv->type, objDesc);
        if (NULL == memDesc)
        {                       // This type not support
            obj_res->storeMemLen -= tlv_header_length();
            tlv_header(obj_res->mem);
            if (obj_res->storeMemLen < curtlv->length)
                return -1;
            tlv_mem_forward(obj_res->mem, curtlv->length);
            obj_res->storeMemLen -= curtlv->length;
            continue;
        }

        obj_update.objMem =
            (void *) ((char *) (obj_res->objMem) + memDesc->offset);
        obj_update.mem = obj_res->mem;
        obj_update.storeMemLen = obj_res->storeMemLen;

        if (NSFW_SS_TYPE_IS_MEMBER_OBJ(curtlv->type))
        {
            if (NSFW_SS_TYPE_IS_MEMBER_ARRAY(curtlv->type))
            {
                int ret =
                    nsfw_ss_restore_obj_array((int)
                                              NSFW_SS_TYPE_GETOBJ
                                              (curtlv->type),
                                              &obj_update);
                if (-1 == ret)
                    return -1;
            }
            else
            {
                int ret = nsfw_ss_restore(&obj_update);
                if (-1 == ret)
                    return -1;
            }

            tlv_mem_forward(obj_res->mem,
                            (curtlv->length + tlv_header_length()));
            obj_res->storeMemLen -= (curtlv->length + tlv_header_length());
        }
        else
        {
            tlv_header(obj_res->mem);
            obj_res->storeMemLen -= tlv_header_length();

            NSFW_LOGDBG
                ("curtlv->type(%u), curtlv->length(%u), memDesc->offset(%u), memDesc->length(%u), mem(%u)",
                 curtlv->type, curtlv->length, memDesc->offset,
                 memDesc->length, *(u32 *) (obj_res->mem));

            if (obj_res->storeMemLen < curtlv->length)
                return -1;
            if (EOK !=
                memcpy_s((void *) ((char *) (obj_res->objMem) +
                                   memDesc->offset),
                         (size_t) memDesc->length, obj_res->mem,
                         (size_t) curtlv->length))
            {
                return -1;
            }

            tlv_mem_forward(obj_res->mem, curtlv->length);
            obj_res->storeMemLen -= curtlv->length;
        }
    }

    return (int) tlv->type;
}

/**
 * @Function        nsfw_ss_get_obj_store_mem_len
 * @Description     Get the maximal memory it needs
 * @param (in)  objType - type of object
 * @return  length of memory needs, -1 if error
 */
int nsfw_ss_get_obj_store_mem_len(int objType)
{
    u32 maxlength = tlv_header_length();
    u32 i;

    nsfw_ss_obj_desc_t *objDesc =
        nsfw_ss_get_obj_desc_from_type((u16) objType);
    if (!objDesc)
        return -1;
    for (i = 0; i < objDesc->memNum; i++)
    {
        nsfw_ss_obj_mem_desc_t *memDesc = &objDesc->memDesc[i];
        int temp_len;
        if (NSFW_SS_TYPE_IS_MEMBER_OBJ(memDesc->type))
        {
            nsfw_ss_obj_desc_t *curObjDesc =
                nsfw_ss_get_obj_desc_from_type(NSFW_SS_TYPE_GETOBJ
                                               (memDesc->type));
            if (NULL == curObjDesc)
                return -1;

            if (NSFW_SS_TYPE_IS_MEMBER_ARRAY(memDesc->type))
            {
                maxlength += tlv_header_length();       // array length

                u32 arrSize = memDesc->length / curObjDesc->objSize;
                u32 j;
                for (j = 0; j < arrSize; j++)
                {
                    temp_len =
                        nsfw_ss_get_obj_store_mem_len((int)
                                                      curObjDesc->objType);
                    if (temp_len < 0)
                        return -1;
                    maxlength += (u32) temp_len;
                }
            }
            else
            {
                temp_len =
                    nsfw_ss_get_obj_store_mem_len((int) curObjDesc->objType);
                if (temp_len < 0)
                    return -1;
                maxlength += (u32) temp_len;
            }
        }
        else
        {
            maxlength += ((u32) tlv_header_length() + memDesc->length);
        }
    }
    return (int) maxlength;
}

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif /* __cplusplus */
