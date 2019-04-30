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
#include "nstack_log_auto_suppress.h"
#include "nstack_log_auto_suppress_rb_tree.h"

#define RB_RED 0
#define RB_BLACK 1

NSTACK_STATIC void ___RB_rotate_left(log_sup_node * X, log_sup_node ** root)
{
    /**************************
     *  rotate Node X to left *
     **************************/

    log_sup_node *Y = X->rb_right;

    /* estblish X->Right link */
    X->rb_right = Y->rb_left;
    if (Y->rb_left != NULL)
        Y->rb_left->rb_parent = X;

    /* estblish Y->Parent link */
    Y->rb_parent = X->rb_parent;
    if (X->rb_parent)
    {
        if (X == X->rb_parent->rb_left)
            X->rb_parent->rb_left = Y;
        else
            X->rb_parent->rb_right = Y;
    }
    else
    {
        *root = Y;
    }

    /* link X and Y */
    Y->rb_left = X;
    X->rb_parent = Y;

    return;
}

NSTACK_STATIC void ___RB_rotate_right(log_sup_node * X, log_sup_node ** root)
{
    /****************************
     *  rotate Node X to right  *
     ****************************/

    log_sup_node *Y = X->rb_left;

    /* estblish X->Left link */
    X->rb_left = Y->rb_right;
    if (Y->rb_right != NULL)
        Y->rb_right->rb_parent = X;

    /* estblish Y->Parent link */
    Y->rb_parent = X->rb_parent;
    if (X->rb_parent)
    {
        if (X == X->rb_parent->rb_right)
            X->rb_parent->rb_right = Y;
        else
            X->rb_parent->rb_left = Y;
    }
    else
    {
        *root = Y;
    }

    /* link X and Y */
    Y->rb_right = X;
    X->rb_parent = Y;

    return;
}

static inline int ___RB_is_color(log_sup_node * node, int color)
{
    return (!node || node->color == color);
}

static inline void ___RB_set_color(log_sup_node * node, int color)
{
    if (node != NULL)
    {
        node->color = color;
    }
}

/* Oops... What's the proper name? */
static inline void ___RB_adjust(log_sup_node * X, log_sup_node ** root,
                                log_sup_node * node)
{
    log_sup_node *Parent = node->rb_parent;
    if (Parent)
    {
        if (Parent->rb_left == node)
        {
            Parent->rb_left = X;
        }
        else
        {
            Parent->rb_right = X;
        }
    }
    else
    {
        *root = X;
    }
}

/* X, Y are for application */
NSTACK_STATIC void ___RB_erase_color(log_sup_node * X, log_sup_node * Parent,
                                     log_sup_node ** root)
{
    /*************************************
     *  maintain red-black tree balance  *
     *  after deleting node X            *
     *************************************/

    while (X != *root && ___RB_is_color(X, RB_BLACK))
    {

        if (Parent == NULL)
        {
            break;
        }

        if (X == Parent->rb_left)
        {
            log_sup_node *W = Parent->rb_right;
            if (W->color == RB_RED)
            {
                W->color = RB_BLACK;
                Parent->color = RB_RED; /* Parent != NIL? */
                ___RB_rotate_left(Parent, root);
                W = Parent->rb_right;
            }

            if (___RB_is_color(W->rb_left, RB_BLACK)
                && ___RB_is_color(W->rb_right, RB_BLACK))
            {
                W->color = RB_RED;
                X = Parent;
                Parent = X->rb_parent;
            }
            else
            {
                if (___RB_is_color(W->rb_right, RB_BLACK))
                {
                    ___RB_set_color(W->rb_left, RB_BLACK);
                    W->color = RB_RED;
                    ___RB_rotate_right(W, root);
                    W = Parent->rb_right;
                }

                W->color = Parent->color;
                Parent->color = RB_BLACK;
                if (W->rb_right->color != RB_BLACK)
                {
                    W->rb_right->color = RB_BLACK;
                }
                ___RB_rotate_left(Parent, root);
                X = *root;
                break;
            }
        }
        else
        {

            log_sup_node *W = Parent->rb_left;
            if (W->color == RB_RED)
            {
                W->color = RB_BLACK;
                Parent->color = RB_RED; /* Parent != NIL? */
                ___RB_rotate_right(Parent, root);
                W = Parent->rb_left;
            }

            if (___RB_is_color(W->rb_left, RB_BLACK)
                && ___RB_is_color(W->rb_right, RB_BLACK))
            {
                W->color = RB_RED;
                X = Parent;
                Parent = X->rb_parent;
            }
            else
            {
                if (___RB_is_color(W->rb_left, RB_BLACK))
                {
                    ___RB_set_color(W->rb_right, RB_BLACK);
                    W->color = RB_RED;
                    ___RB_rotate_left(W, root);
                    W = Parent->rb_left;
                }

                W->color = Parent->color;
                Parent->color = RB_BLACK;
                if (W->rb_left->color != RB_BLACK)
                {
                    W->rb_left->color = RB_BLACK;
                }
                ___RB_rotate_right(Parent, root);
                X = *root;
                break;
            }
        }
    }

    if (X)
    {
        X->color = RB_BLACK;
    }

    return;
}

static void ___RB_insert_color(log_sup_node * X, log_sup_node ** root)
{
    /*************************************
     *  maintain red-black tree balance  *
     *  after inserting node X           *
     *************************************/

    /* check red-black properties */
    while (X != *root && X->rb_parent->color == RB_RED)
    {
        /* we have a violation */
        if (X->rb_parent == X->rb_parent->rb_parent->rb_left)
        {
            log_sup_node *Y = X->rb_parent->rb_parent->rb_right;
            if (!___RB_is_color(Y, RB_BLACK))
            {

                /* uncle is red */
                X->rb_parent->color = RB_BLACK;
                Y->color = RB_BLACK;
                X->rb_parent->rb_parent->color = RB_RED;
                X = X->rb_parent->rb_parent;
            }
            else
            {

                /* uncle is black */
                if (X == X->rb_parent->rb_right)
                {
                    /* make X a left child */
                    X = X->rb_parent;
                    ___RB_rotate_left(X, root);
                }

                /* recolor and rotate */
                X->rb_parent->color = RB_BLACK;
                X->rb_parent->rb_parent->color = RB_RED;
                ___RB_rotate_right(X->rb_parent->rb_parent, root);
            }
        }
        else
        {

            /* miror image of above code */
            log_sup_node *Y = X->rb_parent->rb_parent->rb_left;
            if (!___RB_is_color(Y, RB_BLACK))
            {

                /* uncle is red */
                X->rb_parent->color = RB_BLACK;
                Y->color = RB_BLACK;
                X->rb_parent->rb_parent->color = RB_RED;
                X = X->rb_parent->rb_parent;
            }
            else
            {

                /* uncle is black */
                if (X == X->rb_parent->rb_left)
                {
                    X = X->rb_parent;
                    ___RB_rotate_right(X, root);
                }
                X->rb_parent->color = RB_BLACK;
                X->rb_parent->rb_parent->color = RB_RED;
                ___RB_rotate_left(X->rb_parent->rb_parent, root);
            }
        }
    }

    (*root)->color = RB_BLACK;

    return;
}

static void ___RB_erase(log_sup_node * node, log_sup_node ** root)
{
    log_sup_node *child, *parent;
    bool color;

    if (!node->rb_left)
    {
        child = node->rb_right;
    }
    else if (!node->rb_right)
    {
        child = node->rb_left;
    }
    else
    {
        log_sup_node *old = node, *left;

        node = node->rb_right;
        while ((left = node->rb_left) != NULL)
        {
            node = left;
        }

        ___RB_adjust(node, root, old);

        child = node->rb_right;
        parent = node->rb_parent;
        color = node->color;

        if (parent == old)
        {
            parent = node;
        }
        else
        {
            if (child)
            {
                child->rb_parent = parent;
            }

            parent->rb_left = child;

            node->rb_right = old->rb_right;
            old->rb_right->rb_parent = node;
        }

        node->color = old->color;
        node->rb_parent = old->rb_parent;
        node->rb_left = old->rb_left;
        old->rb_left->rb_parent = node;

        if (color == RB_BLACK)
        {
            ___RB_erase_color(child, parent, root);
        }

        return;

    }

    parent = node->rb_parent;
    color = node->color;

    if (child)
    {
        child->rb_parent = parent;
    }

    ___RB_adjust(child, root, node);

    if (color == RB_BLACK)
    {
        ___RB_erase_color(child, parent, root);
    }

    return;
}

inline log_sup_node *__log_sup_rb_insert(log_entry * entry,
                                         log_sup_node ** root)
{
    log_sup_node *node = *root;
    log_sup_node *parent = NULL;
    int ret = 0;
    while (node)
    {
        parent = node;
        ret = log_entry_cmp(&node->entry, entry);
        if (0 < ret)
        {
            node = node->rb_left;
        }
        else if (0 > ret)
        {
            node = node->rb_right;
        }
        else
        {
            return NULL;
        }
    }

    node = malloc_one_node();
    if (!node)
    {
        return NULL;
    }
    node->entry = *entry;       //copy the content, not the ptr
    node->rb_parent = parent;
    node->rb_left = node->rb_right = NULL;
    node->color = RB_RED;

    if (parent)
    {
        if (ret > 0)
        {
            parent->rb_left = node;
        }
        else
        {
            parent->rb_right = node;
        }
    }
    else
    {
        *root = node;
    }

    ___RB_insert_color(node, root);
    return node;
}

inline log_sup_node *__log_sup_rb_search(const log_entry * entry,
                                         log_sup_node * root)
{
    log_sup_node *node = root;
    int ret;
    while (node)
    {
        ret = log_entry_cmp(&node->entry, entry);
        if (0 < ret)
        {
            node = node->rb_left;
        }
        else if (0 > ret)
        {
            node = node->rb_right;
        }
        else
        {
            return node;
        }
    }

    return NULL;
}

inline void __log_sup_rb_erase(log_sup_node * node, log_sup_node ** root)
{
    ___RB_erase(node, root);
    free_one_node(node);
}

void __log_sup_rb_traversal_preorder(log_sup_node * root,
                                     log_entry_worker_fn foo,
                                     log_sup_node ** resnode, int *recur_cnt)
{
    /* avoid infinite recursion or empty tree */
    if (!recur_cnt || (0 > *recur_cnt) || !root)
    {
        return;
    }

    /* NOTE: recur_cnt decreases along with foo call and does not bounce back,
     * so it should be the numbur of nodes, not the depth */
    (*recur_cnt)--;

    int ret = foo(&(root->entry));
    if (0 != ret)
    {
        if (resnode)
        {
            *recur_cnt = 0;     /* immediate return */
            *resnode = root;
        }
        return;
    }

    if ((root->rb_left) != NULL)
    {
        __log_sup_rb_traversal_preorder(root->rb_left, foo, resnode,
                                        recur_cnt);
    }
    if ((root->rb_right) != NULL)
    {
        __log_sup_rb_traversal_preorder(root->rb_right, foo, resnode,
                                        recur_cnt);
    }
}
