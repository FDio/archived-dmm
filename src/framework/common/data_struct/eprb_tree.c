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

#include "eprb_tree.h"
#include "nsfw_mem_api.h"

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
#endif

/*
 * This function returns the first node (in sort order) of the tree.
 */
struct ep_rb_node *ep_rb_first(const struct ep_rb_root *root)
{
    if (NULL == root)
        return NULL;

    struct ep_rb_node *n;

    n = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(root->rb_node);

    if (!n)
    {
        return NULL;
    }

    while (n->rb_left)
    {
        n = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(n->rb_left);
    }

    return n;
}

void __ep_rb_rotate_left(struct ep_rb_node *X, struct ep_rb_root *root)
{
    /**************************
     *  rotate Node X to left *
     **************************/

    struct ep_rb_node *Y =
        (struct ep_rb_node *) SHMEM_ADDR_SHTOL(X->rb_right);

    /* estblish X->Right link */
    X->rb_right = Y->rb_left;

    if (Y->rb_left != NULL)
    {
        ((struct ep_rb_node *) SHMEM_ADDR_SHTOL(Y->rb_left))->rb_parent =
            (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(X);
    }

    /* estblish Y->Parent link */
    Y->rb_parent = X->rb_parent;

    if (X->rb_parent)
    {
        struct ep_rb_node *xParent =
            (struct ep_rb_node *) SHMEM_ADDR_SHTOL(X->rb_parent);

        if (X == SHMEM_ADDR_SHTOL(xParent->rb_left))
        {
            xParent->rb_left = (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(Y);
        }
        else
        {
            xParent->rb_right = (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(Y);
        }
    }
    else
    {
        root->rb_node = (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(Y);
    }

    /* link X and Y */
    Y->rb_left = (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(X);
    X->rb_parent = (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(Y);

    return;
}

void __ep_rb_rotate_right(struct ep_rb_node *X, struct ep_rb_root *root)
{
    /****************************
     *  rotate Node X to right  *
     ****************************/

    struct ep_rb_node *Y = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(X->rb_left);

    /* estblish X->Left link */
    X->rb_left = Y->rb_right;

    if (Y->rb_right != NULL)
    {
        ((struct ep_rb_node *) SHMEM_ADDR_SHTOL(Y->rb_right))->rb_parent =
            (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(X);
    }

    /* estblish Y->Parent link */
    Y->rb_parent = X->rb_parent;

    if (X->rb_parent)
    {
        struct ep_rb_node *xParent =
            (struct ep_rb_node *) SHMEM_ADDR_SHTOL(X->rb_parent);

        if (X == (struct ep_rb_node *) SHMEM_ADDR_SHTOL(xParent->rb_right))
        {
            xParent->rb_right = (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(Y);
        }
        else
        {
            xParent->rb_left = (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(Y);
        }
    }
    else
    {
        root->rb_node = (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(Y);
    }

    /* link X and Y */
    Y->rb_right = (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(X);
    X->rb_parent = (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(Y);

    return;
}

static inline int __ep_rb_is_color_local(struct ep_rb_node *node, int color)
{
    return (!node || node->color == color);
}

static inline int __ep_rb_is_color(struct ep_rb_node *node, int color)
{
    return (!node
            || ((struct ep_rb_node *) SHMEM_ADDR_SHTOL(node))->color ==
            color);
}

static inline void __ep_rb_set_color(struct ep_rb_node *node, int color)
{
    if (node != NULL)
    {
        ((struct ep_rb_node *) SHMEM_ADDR_SHTOL(node))->color = color;
    }
}

/* Oops... What's the proper name? */
static inline void __ep_rb_adjust(struct ep_rb_node *X,
                                  struct ep_rb_root *root,
                                  struct ep_rb_node *node)
{
    struct ep_rb_node *Parent =
        (struct ep_rb_node *) SHMEM_ADDR_SHTOL(node->rb_parent);
    if (Parent)
    {
        if (Parent->rb_left ==
            (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(node))
        {
            Parent->rb_left = (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(X);
        }
        else
        {
            Parent->rb_right = (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(X);
        }
    }
    else
    {
        root->rb_node = (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(X);
    }

}

#define EP_RBTREE_PARENT(X) ((struct ep_rb_node*) SHMEM_ADDR_SHTOL((X)->rb_parent))
#define EP_RBTREE_GRANDF(X) EP_RBTREE_PARENT(EP_RBTREE_PARENT(X))

/* X, Y are for application */
void ep_rb_insert_color(struct ep_rb_node *X, struct ep_rb_root *root)
{
    /*************************************
     *  maintain red-black tree balance  *
     *  after inserting node X           *
     *************************************/

    /* check red-black properties */
    while (X != (struct ep_rb_node *) SHMEM_ADDR_SHTOL(root->rb_node)
           && EP_RBTREE_PARENT(X)->color == EP_RB_RED)
    {
        /* we have a violation */
        if (X->rb_parent == EP_RBTREE_GRANDF(X)->rb_left)
        {
            struct ep_rb_node *Y =
                (struct ep_rb_node *)
                SHMEM_ADDR_SHTOL(EP_RBTREE_GRANDF(X)->rb_right);

            if (!__ep_rb_is_color_local(Y, EP_RB_BLACK))
            {

                /* uncle is red */
                EP_RBTREE_PARENT(X)->color = EP_RB_BLACK;
                Y->color = EP_RB_BLACK;
                EP_RBTREE_GRANDF(X)->color = EP_RB_RED;
                X = EP_RBTREE_GRANDF(X);
            }
            else
            {

                /* uncle is black */
                if (X ==
                    (struct ep_rb_node *)
                    SHMEM_ADDR_SHTOL(EP_RBTREE_PARENT(X)->rb_right))
                {
                    /* make X a left child */
                    X = EP_RBTREE_PARENT(X);
                    __ep_rb_rotate_left(X, root);
                }

                /* recolor and rotate */
                EP_RBTREE_PARENT(X)->color = EP_RB_BLACK;
                EP_RBTREE_GRANDF(X)->color = EP_RB_RED;
                __ep_rb_rotate_right(EP_RBTREE_GRANDF(X), root);
            }
        }
        else
        {
            /* miror image of above code */
            struct ep_rb_node *Y =
                (struct ep_rb_node *)
                SHMEM_ADDR_SHTOL(EP_RBTREE_GRANDF(X)->rb_left);

            if (!__ep_rb_is_color_local(Y, EP_RB_BLACK))
            {

                /* uncle is red */
                EP_RBTREE_PARENT(X)->color = EP_RB_BLACK;
                Y->color = EP_RB_BLACK;
                EP_RBTREE_GRANDF(X)->color = EP_RB_RED;
                X = EP_RBTREE_GRANDF(X);
            }
            else
            {

                /* uncle is black */
                if (X ==
                    (struct ep_rb_node *)
                    SHMEM_ADDR_SHTOL(EP_RBTREE_PARENT(X)->rb_left))
                {
                    X = EP_RBTREE_PARENT(X);
                    __ep_rb_rotate_right(X, root);
                }

                EP_RBTREE_PARENT(X)->color = EP_RB_BLACK;
                EP_RBTREE_GRANDF(X)->color = EP_RB_RED;
                __ep_rb_rotate_left(EP_RBTREE_GRANDF(X), root);
            }
        }
    }

    ((struct ep_rb_node *) SHMEM_ADDR_SHTOL(root->rb_node))->color =
        EP_RB_BLACK;

    return;
}

void __ep_rb_erase_color(struct ep_rb_node *X, struct ep_rb_node *Parent,
                         struct ep_rb_root *root)
{
    /*************************************
     *  maintain red-black tree balance  *
     *  after deleting node X            *
     *************************************/

    while (X != (struct ep_rb_node *) SHMEM_ADDR_SHTOL(root->rb_node)
           && __ep_rb_is_color_local(X, EP_RB_BLACK))
    {

        if (Parent == NULL)
        {
            break;
        }

        if (X == (struct ep_rb_node *) SHMEM_ADDR_SHTOL(Parent->rb_left))
        {
            struct ep_rb_node *W =
                (struct ep_rb_node *) SHMEM_ADDR_SHTOL(Parent->rb_right);

            if (W->color == EP_RB_RED)
            {
                W->color = EP_RB_BLACK;
                Parent->color = EP_RB_RED;      /* Parent != NIL? */
                __ep_rb_rotate_left(Parent, root);
                W = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(Parent->rb_right);
            }

            if (__ep_rb_is_color(W->rb_left, EP_RB_BLACK)
                && __ep_rb_is_color(W->rb_right, EP_RB_BLACK))
            {
                W->color = EP_RB_RED;
                X = Parent;
                Parent = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(X->rb_parent);
            }
            else
            {
                if (__ep_rb_is_color(W->rb_right, EP_RB_BLACK))
                {
                    __ep_rb_set_color(W->rb_left, EP_RB_BLACK);

                    W->color = EP_RB_RED;
                    __ep_rb_rotate_right(W, root);
                    W = (struct ep_rb_node *)
                        SHMEM_ADDR_SHTOL(Parent->rb_right);
                }

                W->color = Parent->color;
                Parent->color = EP_RB_BLACK;

                ((struct ep_rb_node *) SHMEM_ADDR_SHTOL(W->rb_right))->color
                    = EP_RB_BLACK;

                __ep_rb_rotate_left(Parent, root);
                X = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(root->rb_node);
                break;
            }
        }
        else
        {

            struct ep_rb_node *W =
                (struct ep_rb_node *) SHMEM_ADDR_SHTOL(Parent->rb_left);

            if (W->color == EP_RB_RED)
            {
                W->color = EP_RB_BLACK;
                Parent->color = EP_RB_RED;      /* Parent != NIL? */
                __ep_rb_rotate_right(Parent, root);
                W = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(Parent->rb_left);
            }

            if (__ep_rb_is_color(W->rb_left, EP_RB_BLACK)
                && __ep_rb_is_color(W->rb_right, EP_RB_BLACK))
            {
                W->color = EP_RB_RED;
                X = Parent;
                Parent = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(X->rb_parent);
            }
            else
            {
                if (__ep_rb_is_color(W->rb_left, EP_RB_BLACK))
                {
                    __ep_rb_set_color(W->rb_right, EP_RB_BLACK);
                    W->color = EP_RB_RED;
                    __ep_rb_rotate_left(W, root);
                    W = (struct ep_rb_node *)
                        SHMEM_ADDR_SHTOL(Parent->rb_left);
                }

                W->color = Parent->color;
                Parent->color = EP_RB_BLACK;

                ((struct ep_rb_node *) SHMEM_ADDR_SHTOL(W->rb_left))->color =
                    EP_RB_BLACK;

                __ep_rb_rotate_right(Parent, root);
                X = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(root->rb_node);
                break;
            }
        }
    }

    if (X)
    {
        X->color = EP_RB_BLACK;
    }

    return;
}

void ep_rb_erase(struct ep_rb_node *node, struct ep_rb_root *root)
{
    struct ep_rb_node *child, *parent;
    int color;

    if (!node->rb_left)
    {
        child = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(node->rb_right);
    }
    else if (!node->rb_right)
    {
        child = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(node->rb_left);
    }
    else
    {
        struct ep_rb_node *old = node, *left;

        node = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(node->rb_right);

        while ((left =
                (struct ep_rb_node *) SHMEM_ADDR_SHTOL(node->rb_left)) !=
               NULL)
        {
            node = left;
        }

        __ep_rb_adjust(node, root, old);

        child = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(node->rb_right);
        parent = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(node->rb_parent);
        color = node->color;

        if (parent == old)
        {
            parent = node;
        }
        else
        {
            if (child)
            {
                child->rb_parent =
                    (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(parent);
            }

            parent->rb_left =
                (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(child);

            node->rb_right = old->rb_right;
            ((struct ep_rb_node *)
             SHMEM_ADDR_SHTOL(old->rb_right))->rb_parent =
(struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(node);
        }

        node->color = old->color;
        node->rb_parent = old->rb_parent;
        node->rb_left = old->rb_left;
        ((struct ep_rb_node *) SHMEM_ADDR_SHTOL(old->rb_left))->rb_parent =
            (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(node);

        if (color == EP_RB_BLACK)
        {
            __ep_rb_erase_color(child, parent, root);
        }

        return;

    }

    parent = (struct ep_rb_node *) SHMEM_ADDR_SHTOL(node->rb_parent);
    color = node->color;

    if (child)
    {
        child->rb_parent = (struct ep_rb_node *) SHMEM_ADDR_LTOSH_EXT(parent);
    }

    __ep_rb_adjust(child, root, node);

    if (color == EP_RB_BLACK)
    {
        __ep_rb_erase_color(child, parent, root);
    }

    return;
}

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif
