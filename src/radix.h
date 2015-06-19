/*-
 * Copyright (c) 1988, 1989, 1993
 * The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef _RADIX_H_
#define _RADIX_H_

#include <jemalloc/jemalloc.h>

#define RNF_NORMAL 1 /* leaf contains normal route */
#define RNF_ROOT   2 /* leaf is root leaf for tree */
#define RNF_ACTIVE 4 /* This node is alive (for rtfree) */

/*
 * Radix search tree node layout.
 */
struct radix_node {
    struct          radix_mask* rn_mklist;   /* list of masks contained in subtree */
    struct          radix_node* rn_parent;   /* parent */
    short           rn_bit;                  /* bit offset; -1-index(netmask) */
    char            rn_bmask;                /* node: mask for bit test*/
    u_char          rn_flags;                /* enumerated next */
    union {
        /* leaf only data: */
        struct {
            caddr_t rn_Key;                  /* object of search */
            caddr_t rn_Mask;                 /* netmask, if present */
            struct  radix_node *rn_Dupedkey;
        } rn_leaf;
        /* node only data: */
        struct {
            int     rn_Off;                  /* where to start compare */
            struct  radix_node* rn_L;        /* progeny */
            struct  radix_node* rn_R;        /* progeny */
        } rn_node;
    } rn_u;
#ifdef RN_DEBUG
    int    rn_info;
    struct radix_node* rn_twin;
    struct radix_node* rn_ybro;
#endif
};

#define rn_dupedkey rn_u.rn_leaf.rn_Dupedkey
#define rn_key      rn_u.rn_leaf.rn_Key
#define rn_mask     rn_u.rn_leaf.rn_Mask
#define rn_offset   rn_u.rn_node.rn_Off
#define rn_left     rn_u.rn_node.rn_L
#define rn_right    rn_u.rn_node.rn_R

/*
 * Annotations to tree concerning potential routes applying to subtrees.
 */
struct radix_mask {
    short       rm_bit;                /* bit offset; -1-index(netmask) */
    char        rm_unused;             /* cf. rn_bmask */
    u_char      rm_flags;              /* cf. rn_flags */
    struct      radix_mask *rm_mklist; /* more masks to try */
    union {
        caddr_t rmu_mask;              /* the mask */
        struct  radix_node *rmu_leaf;  /* for normal routes */
    } rm_rmu;
    int rm_refs;                       /* # of references to this struct */
};

/* extra field would make 32 bytes */
#define rm_mask rm_rmu.rmu_mask
#define rm_leaf rm_rmu.rmu_leaf

typedef int walktree_f_t(struct radix_node*, void*);

struct radix_node_head {
    struct radix_node* rnh_treetop;
    u_int  rnh_gen;                 /* generation counter */
    int    rnh_multipath;           /* multipath capable ? */
    /* add based on sockaddr */
    struct radix_node* (*rnh_addaddr) (void *v, void *mask, struct radix_node_head *head, struct radix_node nodes[]);
    /* remove based on sockaddr */
    struct radix_node* (*rnh_deladdr) (void *v, void *mask, struct radix_node_head *head);
    /* longest match for sockaddr */
    struct radix_node* (*rnh_matchaddr) (void *v, struct radix_node_head *head);
    /* exact match for sockaddr */
    struct radix_node* (*rnh_lookup) (void *v, void *mask, struct radix_node_head *head);
    /* traverse tree */
    int    (*rnh_walktree) (struct radix_node_head *head, walktree_f_t *f, void *w);
    /* traverse tree below a */
    int    (*rnh_walktree_from) (struct radix_node_head *head, void *a, void *m, walktree_f_t *f, void *w);
    /* do something when the last ref drops */
    void   (*rnh_close) (struct radix_node *rn, struct radix_node_head *head);
    struct radix_node rnh_nodes[3];    /* empty tree for common case */
    struct radix_node_head* rnh_masks; /* Storage for our masks */
};

/* BEGIN PROTOTYPES */

int rn_refines(void* m_arg, void* n_arg);
struct radix_node* rn_lookup(void* v_arg, void* m_arg, struct radix_node_head* head);
struct radix_node* rn_match(void* v_arg, struct radix_node_head* head);
struct radix_node* rn_addmask(void* n_arg, struct radix_node_head* maskhead, int search, int skip);
struct radix_node* rn_addroute(void* v_arg, void* n_arg, struct radix_node_head* head, struct radix_node treenodes[2]);
struct radix_node* rn_delete(void* v_arg, void* netmask_arg, struct radix_node_head* head);
int rn_inithead(void* *head, int off);
int rn_detachhead(void* *head);

/* END PROTOTYPES */

#endif /* _RADIX_H_ */
