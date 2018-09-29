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

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
#endif

/*
 * This function returns the first node (in sort order) of the tree.
 */
struct ep_rb_node *
ep_rb_first (const struct ep_rb_root *root)
{
  if (NULL == root)
    return NULL;

  struct ep_rb_node *n;
  n = root->rb_node;

  if (!n)
    {
      return NULL;
    }

  while (n->rb_left)
    {
      n = n->rb_left;
    }

  return n;
}

void
__ep_rb_rotate_left (struct ep_rb_node *X, struct ep_rb_root *root)
{
    /**************************
     *  rotate Node X to left *
     **************************/
  struct ep_rb_node *Y = X->rb_right;

  /* establish X->Right link */
  X->rb_right = Y->rb_left;

  if (Y->rb_left != NULL)
    {
      Y->rb_left->rb_parent = X;
    }

  /* establish Y->Parent link */
  Y->rb_parent = X->rb_parent;

  if (X->rb_parent)
    {
      struct ep_rb_node *xParent = X->rb_parent;

      if (X == xParent->rb_left)
        {
          xParent->rb_left = Y;
        }
      else
        {
          xParent->rb_right = Y;
        }
    }
  else
    {
      root->rb_node = Y;
    }

  /* link X and Y */
  Y->rb_left = X;
  X->rb_parent = Y;

  return;
}

void
__ep_rb_rotate_right (struct ep_rb_node *X, struct ep_rb_root *root)
{
    /****************************
     *  rotate Node X to right  *
     ****************************/
  struct ep_rb_node *Y = X->rb_left;

  /* establish X->Left link */
  X->rb_left = Y->rb_right;

  if (Y->rb_right != NULL)
    {
      Y->rb_right->rb_parent = X;
    }

  /* establish Y->Parent link */
  Y->rb_parent = X->rb_parent;

  if (X->rb_parent)
    {
      struct ep_rb_node *xParent = X->rb_parent;

      if (X == xParent->rb_right)
        {
          xParent->rb_right = Y;
        }
      else
        {
          xParent->rb_left = Y;
        }
    }
  else
    {
      root->rb_node = Y;
    }

  /* link X and Y */
  Y->rb_right = X;
  X->rb_parent = Y;

  return;
}

#define EP_RBTREE_PARENT(X) ((X)->rb_parent)
#define EP_RBTREE_GRANDF(X) EP_RBTREE_PARENT(EP_RBTREE_PARENT(X))

/* X, Y are for application */
void
ep_rb_insert_color (struct ep_rb_node *X, struct ep_rb_root *root)
{
    /*************************************
     *  maintain red-black tree balance  *
     *  after inserting node X           *
     *************************************/
  /* check red-black properties */
  while (X != root->rb_node && EP_RBTREE_PARENT (X)->color == EP_RB_RED)
    {
      /* we have a violation */
      if (X->rb_parent == EP_RBTREE_GRANDF (X)->rb_left)
        {
          struct ep_rb_node *Y = EP_RBTREE_GRANDF (X)->rb_right;

          if (Y && Y->color == EP_RB_RED)
            {

              /* uncle is red */
              EP_RBTREE_PARENT (X)->color = EP_RB_BLACK;
              Y->color = EP_RB_BLACK;
              EP_RBTREE_GRANDF (X)->color = EP_RB_RED;
              X = EP_RBTREE_GRANDF (X);
            }
          else
            {

              /* uncle is black */
              if (X == EP_RBTREE_PARENT (X)->rb_right)
                {
                  /* make X a left child */
                  X = EP_RBTREE_PARENT (X);
                  __ep_rb_rotate_left (X, root);
                }

              /* recolor and rotate */
              EP_RBTREE_PARENT (X)->color = EP_RB_BLACK;
              EP_RBTREE_GRANDF (X)->color = EP_RB_RED;
              __ep_rb_rotate_right (EP_RBTREE_GRANDF (X), root);
            }
        }
      else
        {
          /* mirror image of above code */
          struct ep_rb_node *Y = EP_RBTREE_GRANDF (X)->rb_left;

          if (Y && (Y->color == EP_RB_RED))
            {

              /* uncle is red */
              EP_RBTREE_PARENT (X)->color = EP_RB_BLACK;
              Y->color = EP_RB_BLACK;
              EP_RBTREE_GRANDF (X)->color = EP_RB_RED;
              X = EP_RBTREE_GRANDF (X);
            }
          else
            {

              /* uncle is black */
              if (X == EP_RBTREE_PARENT (X)->rb_left)
                {
                  X = EP_RBTREE_PARENT (X);
                  __ep_rb_rotate_right (X, root);
                }

              EP_RBTREE_PARENT (X)->color = EP_RB_BLACK;
              EP_RBTREE_GRANDF (X)->color = EP_RB_RED;
              __ep_rb_rotate_left (EP_RBTREE_GRANDF (X), root);
            }
        }
    }

  root->rb_node->color = EP_RB_BLACK;

  return;
}

void
__ep_rb_erase_color (struct ep_rb_node *X, struct ep_rb_node *Parent,
                     struct ep_rb_root *root)
{
    /*************************************
     *  maintain red-black tree balance  *
     *  after deleting node X            *
     *************************************/
  while (X != root->rb_node && (!X || X->color == EP_RB_BLACK))
    {

      if (Parent == NULL)
        {
          break;
        }

      if (X == Parent->rb_left)
        {
          struct ep_rb_node *W = Parent->rb_right;

          if (W->color == EP_RB_RED)
            {
              W->color = EP_RB_BLACK;
              Parent->color = EP_RB_RED;        /* Parent != NIL? */
              __ep_rb_rotate_left (Parent, root);
              W = Parent->rb_right;
            }

          if ((!W->rb_left || W->rb_left->color == EP_RB_BLACK)
              && (!W->rb_right || W->rb_right->color == EP_RB_BLACK))
            {
              W->color = EP_RB_RED;
              X = Parent;
              Parent = X->rb_parent;
            }
          else
            {
              if (!W->rb_right || W->rb_right->color == EP_RB_BLACK)
                {
                  if (W->rb_left != NULL)
                    {
                      W->rb_left->color = EP_RB_BLACK;
                    }

                  W->color = EP_RB_RED;
                  __ep_rb_rotate_right (W, root);
                  W = Parent->rb_right;
                }

              W->color = Parent->color;
              Parent->color = EP_RB_BLACK;

              if (W->rb_right->color != EP_RB_BLACK)
                {
                  W->rb_right->color = EP_RB_BLACK;
                }

              __ep_rb_rotate_left (Parent, root);
              X = root->rb_node;
              break;
            }
        }
      else
        {

          struct ep_rb_node *W = Parent->rb_left;

          if (W->color == EP_RB_RED)
            {
              W->color = EP_RB_BLACK;
              Parent->color = EP_RB_RED;        /* Parent != NIL? */
              __ep_rb_rotate_right (Parent, root);
              W = Parent->rb_left;
            }

          if ((!W->rb_left || (W->rb_left->color == EP_RB_BLACK))
              && (!W->rb_right || (W->rb_right->color == EP_RB_BLACK)))
            {
              W->color = EP_RB_RED;
              X = Parent;
              Parent = X->rb_parent;
            }
          else
            {
              if (!W->rb_left || W->rb_left->color == EP_RB_BLACK)
                {
                  if (W->rb_right != NULL)
                    {
                      W->rb_right->color = EP_RB_BLACK;
                    }

                  W->color = EP_RB_RED;
                  __ep_rb_rotate_left (W, root);
                  W = Parent->rb_left;
                }

              W->color = Parent->color;
              Parent->color = EP_RB_BLACK;

              if (W->rb_left->color != EP_RB_BLACK)
                {
                  W->rb_left->color = EP_RB_BLACK;
                }

              __ep_rb_rotate_right (Parent, root);
              X = root->rb_node;
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

void
ep_rb_erase (struct ep_rb_node *node, struct ep_rb_root *root)
{
  struct ep_rb_node *child, *parent;
  int color;

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
      struct ep_rb_node *old = node, *left;

      node = node->rb_right;

      while ((left = node->rb_left) != NULL)
        {
          node = left;
        }

      if (old->rb_parent)
        {
          struct ep_rb_node *oldParent = old->rb_parent;

          if (oldParent->rb_left == old)
            {
              oldParent->rb_left = node;
            }
          else
            {
              oldParent->rb_right = node;
            }
        }
      else
        {
          root->rb_node = node;
        }

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

      if (color == EP_RB_BLACK)
        {
          __ep_rb_erase_color (child, parent, root);
        }

      return;

    }

  parent = node->rb_parent;
  color = node->color;

  if (child)
    {
      child->rb_parent = parent;
    }

  if (parent)
    {
      if (parent->rb_left == node)
        {
          parent->rb_left = child;
        }
      else
        {
          parent->rb_right = child;
        }
    }
  else
    {
      root->rb_node = child;
    }

  if (color == EP_RB_BLACK)
    {
      __ep_rb_erase_color (child, parent, root);
    }
  return;
}

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif
