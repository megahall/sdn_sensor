#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "ip_utils.h"

typedef void (*void_fn_t)();

struct ss_radix_node_s {
   uint          bit;    /* flag if this node used */
   ip_addr_t*    prefix; /* who we are in radix tree */
   struct ss_radix_node_s* l;
   struct ss_radix_node_s* r;      /* left and right children */
   struct ss_radix_node_s* parent; /* may be used */
   void* data;           /* pointer to data */
   void* user1;          /* pointer to usr data (ex. route flap info) */
};

typedef struct ss_radix_node_s ss_radix_node_t;

struct ss_radix_tree_s {
   ss_radix_node_t* head;
   uint          maxbits;         /* for IP, 32 bit addresses */
   int           num_active_node; /* for debug purpose */
};

typedef struct ss_radix_tree_s ss_radix_tree_t;

#define SS_RADIX_MAXBITS 128
#define SS_RADIX_NBIT(x)        (0x80 >> ((x) & 0x7f))
#define SS_RADIX_NBYTE(x)       ((x) >> 3)

#define SS_RADIX_DATA_GET(node, type) (type *)((node)->data)
#define SS_RADIX_DATA_SET(node, value) ((node)->data = (void *)(value))

#define SS_RADIX_WALK(Xhead, Xnode) \
    do { \
        ss_radix_node_t *Xstack[SS_RADIX_MAXBITS+1]; \
        ss_radix_node_t **Xsp = Xstack; \
        ss_radix_node_t *Xrn = (Xhead); \
        while ((Xnode = Xrn)) { \
            if (Xnode->prefix)

#define SS_RADIX_WALK_ALL(Xhead, Xnode) \
do { \
        ss_radix_node_t *Xstack[SS_RADIX_MAXBITS+1]; \
        ss_radix_node_t **Xsp = Xstack; \
        ss_radix_node_t *Xrn = (Xhead); \
        while ((Xnode = Xrn)) { \
        if (1)

#define SS_RADIX_WALK_BREAK { \
        if (Xsp != Xstack) { \
        Xrn = *(--Xsp); \
         } else { \
        Xrn = (ss_radix_node_t *) 0; \
        } \
        continue; }

#define SS_RADIX_WALK_END \
            if (Xrn->l) { \
                if (Xrn->r) { \
                    *Xsp++ = Xrn->r; \
                } \
                Xrn = Xrn->l; \
            } else if (Xrn->r) { \
                Xrn = Xrn->r; \
            } else if (Xsp != Xstack) { \
                Xrn = *(--Xsp); \
            } else { \
                Xrn = (ss_radix_node_t *) 0; \
            } \
        } \
    } while (0)

/* BEGIN PROTOTYPES */

ss_radix_tree_t* ss_radix_tree_create(uint maxbits);
void ss_radix_tree_clear(ss_radix_tree_t* radix, void_fn_t func);
void ss_radix_tree_destroy(ss_radix_tree_t* radix, void_fn_t func);
void ss_radix_tree_iterate(ss_radix_tree_t* radix, void_fn_t func);
ss_radix_node_t* ss_radix_search_exact(ss_radix_tree_t* radix, ip_addr_t* prefix);
ss_radix_node_t* ss_radix_search_best(ss_radix_tree_t* radix, ip_addr_t* prefix, _Bool is_inclusive);
ss_radix_node_t* ss_radix_lookup(ss_radix_tree_t* radix, ip_addr_t* prefix);
void ss_radix_remove(ss_radix_tree_t* radix, ss_radix_node_t* node);

/* END PROTOTYPES */
