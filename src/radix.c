#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <jemalloc/jemalloc.h>

#include "radix.h"

#define BIT_TEST(f, b) ((f) & (b))

static int SS_RADIX_DEBUG = 1;

/* these routines support continuous mask only */

ss_radix_tree_t* ss_radix_tree_create(uint maxbits) {
    ss_radix_tree_t* radix = je_malloc(sizeof(ss_radix_tree_t));
    
    radix->maxbits = maxbits;
    radix->head = NULL;
    radix->num_active_node = 0;
    assert(maxbits <= SS_RADIX_MAXBITS); /* XXX */
    return radix;
}

/*
* if func is supplied, it will be called as func(node->data)
* before deleting the node
*/
void ss_radix_tree_clear(ss_radix_tree_t* radix, void_fn_t func) {
    assert(radix);
    if (radix->head) {
        ss_radix_node_t*  Xstack[SS_RADIX_MAXBITS + 1];
        ss_radix_node_t** Xsp = Xstack;
        ss_radix_node_t*  Xrn = radix->head;
        
        while (Xrn) {
            ss_radix_node_t* l = Xrn->l;
            ss_radix_node_t* r = Xrn->r;
            
            if (Xrn->prefix) {
                je_free(Xrn->prefix);
                if (Xrn->data && func)
                    func(Xrn->data);
            }
            else {
                assert(Xrn->data == NULL);
            }
            je_free(Xrn);
            radix->num_active_node--;
            
            if (l) {
                if (r) {
                    *Xsp++ = r;
                }
                Xrn = l;
            }
            else if (r) {
                Xrn = r;
            }
            else if (Xsp != Xstack) {
                Xrn = *(--Xsp);
            }
            else {
                Xrn = (ss_radix_node_t*) 0;
            }
        }
    }
    assert(radix->num_active_node == 0);
    radix->head = NULL;
    /* je_free(radix); */
}

void ss_radix_tree_destroy(ss_radix_tree_t* radix, void_fn_t func) {
    ss_radix_tree_clear(radix, func);
    je_free(radix);
}

/*
* if func is supplied, it will be called as func(node->prefix, node->data)
*/
void ss_radix_tree_iterate(ss_radix_tree_t* radix, void_fn_t func) {
    ss_radix_node_t* node;
    assert(func);
    
    SS_RADIX_WALK (radix->head, node) {
        func(node->prefix, node->data);
    } SS_RADIX_WALK_END;
}

ss_radix_node_t* ss_radix_search_exact(ss_radix_tree_t* radix, ip_addr_t* prefix) {
    ss_radix_node_t* node;
    uint8_t* addr;
    uint bitlen;
    
    assert(radix);
    assert(prefix);
    assert(prefix->cidr <= radix->maxbits);
    
    if (radix->head == NULL)
        return NULL;
    
    node = radix->head;
    addr = (uint8_t*) &prefix->addr;
    bitlen = prefix->cidr;
    
    while (node->bit < bitlen) {
        if (BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
            if (SS_RADIX_DEBUG) {
                if (node->prefix) {
                    fprintf(stderr, "%s: take right %s/%d\n",
                        __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
                }
                else {
                    fprintf(stderr, "%s: take right at %d\n", __func__, node->bit);
                }
            }
            node = node->r;
        }
        else {
            if (SS_RADIX_DEBUG) {
                if (node->prefix) {
                    fprintf(stderr, "%s: take left %s/%d\n",
                        __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
                }
                else {
                    fprintf(stderr, "%s: take left at %d\n", __func__, node->bit);
                }
            }
            node = node->l;
        }
        
        if (node == NULL)
            return NULL;
    }
    
    if (SS_RADIX_DEBUG) {
        if (node->prefix) {
            fprintf(stderr, "%s: stop at %s/%d\n",
                __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
        }
        else {
            fprintf(stderr, "%s: stop at %d\n", __func__, node->bit);
        }
    }
    if (node->bit > bitlen || node->prefix == NULL)
        return NULL;
    assert(node->bit == bitlen);
    assert(node->bit == node->prefix->cidr);
    if (comp_with_mask(&node->prefix, &prefix, bitlen)) {
        if (SS_RADIX_DEBUG) {
            fprintf(stderr, "%s: found %s/%d\n",
            __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
        }
        return node;
    }
    return NULL;
}

/* if inclusive != 0, "best" may be the given prefix itself */
ss_radix_node_t* ss_radix_search_best(ss_radix_tree_t* radix, ip_addr_t* prefix, bool is_inclusive) {
    ss_radix_node_t* node;
    ss_radix_node_t* stack[SS_RADIX_MAXBITS + 1];
    uint8_t* addr;
    uint bitlen;
    int cnt = 0;
    
    assert(radix);
    assert(prefix);
    assert(prefix->cidr <= radix->maxbits);
    
    if (radix->head == NULL)
        return NULL;
    
    node = radix->head;
    addr = (uint8_t*) prefix;
    bitlen = prefix->cidr;
    
    while (node->bit < bitlen) {
        
        if (node->prefix) {
            if (SS_RADIX_DEBUG) {
                fprintf(stderr, "%s: push %s/%d\n",
                __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
            }
            stack[cnt++] = node;
        }
        
        if (BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
            if (SS_RADIX_DEBUG) {
                if (node->prefix) {
                    fprintf(stderr, "%s: take right %s/%d\n",
                        __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
                }
                else {
                    fprintf(stderr, "%s: take right at %d\n", __func__, node->bit);
                }
            }
            node = node->r;
        }
        else {
            if (SS_RADIX_DEBUG) {
                if (node->prefix) {
                    fprintf(stderr, "%s: take left %s/%d\n",
                        __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
                }
                else {
                    fprintf(stderr, "%s: take left at %d\n", __func__, node->bit);
                }
            }
            node = node->l;
        }
        
        if (node == NULL)
            break;
    }
    
    if (is_inclusive && node && node->prefix)
        stack[cnt++] = node;
    
    if (SS_RADIX_DEBUG) {
        if (node == NULL) {
            fprintf(stderr, "%s: stop at null\n", __func__);
        }
        else if (node->prefix) {
            fprintf(stderr, "%s: stop at %s/%d\n",
                __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
        }
        else {
            fprintf(stderr, "%s: stop at %d\n", __func__, node->bit);
        }
    }
    
    if (cnt <= 0)
        return NULL;
    
    while (--cnt >= 0) {
        node = stack[cnt];
        if (SS_RADIX_DEBUG) {
            fprintf(stderr, "%s: pop %s/%d\n",
            __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
        }
        if (comp_with_mask(&node->prefix, &prefix, node->prefix->cidr)) {
            if (SS_RADIX_DEBUG) {
                fprintf(stderr, "%s: found %s/%d\n",
                __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
            }
            return node;
        }
    }
    return NULL;
}

ss_radix_node_t* ss_radix_lookup(ss_radix_tree_t* radix, ip_addr_t* prefix) {
    ss_radix_node_t* node;
    ss_radix_node_t* new_node;
    ss_radix_node_t* parent;
    ss_radix_node_t* glue;
    uint8_t* addr;
    uint8_t* test_addr;
    uint bitlen, check_bit, differ_bit;
    int i, j, r;
    
    assert(radix);
    assert(prefix);
    assert(prefix->cidr <= radix->maxbits);
    
    if (radix->head == NULL) {
        node = je_malloc(sizeof(ss_radix_node_t));
        node->bit = prefix->cidr;
        node->prefix = prefix;
        node->parent = NULL;
        node->l = NULL;
        node->r = NULL;
        node->data = NULL;
        radix->head = node;
        if (SS_RADIX_DEBUG) {
            fprintf(stderr, "%s: new_node #0 %s/%d (head)\n",
            __func__, ss_inet_ntop_tls(prefix), prefix->cidr);
        }
        radix->num_active_node++;
        return node;
    }
    
    addr = (uint8_t*) prefix;
    bitlen = prefix->cidr;
    node = radix->head;
    
    while (node->bit < bitlen || node->prefix == NULL) {
        
        if (node->bit < radix->maxbits &&
        BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
            if (node->r == NULL)
                break;
            if (SS_RADIX_DEBUG) {
                if (node->prefix) {
                    fprintf(stderr, "%s: take right %s/%d\n",
                        __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
                }
                else {
                    fprintf(stderr, "%s: take right at %d\n", __func__, node->bit);
                }
            }
            node = node->r;
        }
        else {
            if (node->l == NULL)
                break;
            if (SS_RADIX_DEBUG) {
                if (node->prefix) {
                    fprintf(stderr, "%s: take left %s/%d\n",
                        __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
                }
                else {
                    fprintf(stderr, "%s: take left at %d\n", __func__, node->bit);
                }
            }
            node = node->l;
        }
        
        assert(node);
    }
    
    assert(node->prefix);
    if (SS_RADIX_DEBUG) {
        fprintf(stderr, "%s: stop at %s/%d\n",
        __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
    }
    
    test_addr = (uint8_t*) &node->prefix->addr;
    /* find the first bit different */
    check_bit = (node->bit < bitlen)? node->bit: bitlen;
    differ_bit = 0;
    for (i = 0; ((uint) i*8) < check_bit; i++) {
        if ((r = (addr[i] ^ test_addr[i])) == 0) {
            differ_bit = (uint) ((i + 1) * 8);
            continue;
        }
        /* I know the better way, but for now */
        for (j = 0; j < 8; j++) {
            if (BIT_TEST(r, (0x80 >> j)))
                break;
        }
        /* must be found */
        assert(j < 8);
        differ_bit = (uint) (i * 8 + j);
        break;
    }
    if (differ_bit > check_bit)
        differ_bit = check_bit;
    if (SS_RADIX_DEBUG) {
        fprintf(stderr, "%s: differ_bit %d\n", __func__, differ_bit);
    }
    
    parent = node->parent;
    while (parent && parent->bit >= differ_bit) {
        node = parent;
        parent = node->parent;
        if (SS_RADIX_DEBUG) {
            if (node->prefix) {
                fprintf(stderr, "%s: up to %s/%d\n",
                    __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
            }
            else {
                fprintf(stderr, "%s: up to %d\n", __func__, node->bit);
            }
        }
    }
    
    if (differ_bit == bitlen && node->bit == bitlen) {
        if (node->prefix) {
            if (SS_RADIX_DEBUG) {
                fprintf(stderr, "%s: found %s/%d\n",
                __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
            }
            return node;
        }
        node->prefix = prefix;
        if (SS_RADIX_DEBUG) {
            fprintf(stderr, "%s: new node #1 %s/%d (glue mod)\n",
            __func__, ss_inet_ntop_tls(prefix), prefix->cidr);
        }
        assert(node->data == NULL);
        return node;
    }
    
    new_node = je_malloc(sizeof(ss_radix_node_t));
    new_node->bit = prefix->cidr;
    new_node->prefix = prefix;
    new_node->parent = NULL;
    new_node->l = NULL;
    new_node->r = NULL;
    new_node->data = NULL;
    radix->num_active_node++;
    
    if (node->bit == differ_bit) {
        new_node->parent = node;
        if (node->bit < radix->maxbits &&
        BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
            //assert(node->r == NULL);
            node->r = new_node;
        }
        else {
            //assert(node->l == NULL);
            node->l = new_node;
        }
        if (SS_RADIX_DEBUG) {
            fprintf(stderr, "%s: new_node #2 %s/%d (child)\n",
            __func__, ss_inet_ntop_tls(prefix), prefix->cidr);
        }
        return new_node;
    }
    
    if (bitlen == differ_bit) {
        if (bitlen < radix->maxbits &&
        BIT_TEST(test_addr[bitlen >> 3], 0x80 >> (bitlen & 0x07))) {
            new_node->r = node;
        }
        else {
            new_node->l = node;
        }
        new_node->parent = node->parent;
        if (node->parent == NULL) {
            assert(radix->head == node);
            radix->head = new_node;
        }
        else if (node->parent->r == node) {
            node->parent->r = new_node;
        }
        else {
            node->parent->l = new_node;
        }
        node->parent = new_node;
        if (SS_RADIX_DEBUG) {
            fprintf(stderr, "%s: new_node #3 %s/%d (parent)\n",
            __func__, ss_inet_ntop_tls(prefix), prefix->cidr);
        }
    }
    else {
        glue = je_malloc(sizeof(ss_radix_node_t));
        glue->bit = differ_bit;
        glue->prefix = NULL;
        glue->parent = node->parent;
        glue->data = NULL;
        radix->num_active_node++;
        if (differ_bit < radix->maxbits &&
        BIT_TEST(addr[differ_bit >> 3], 0x80 >> (differ_bit & 0x07))) {
            glue->r = new_node;
            glue->l = node;
        }
        else {
            glue->r = node;
            glue->l = new_node;
        }
        new_node->parent = glue;
        
        if (node->parent == NULL) {
            assert(radix->head == node);
            radix->head = glue;
        }
        else if (node->parent->r == node) {
            node->parent->r = glue;
        }
        else {
            node->parent->l = glue;
        }
        node->parent = glue;
        if (SS_RADIX_DEBUG) {
            fprintf(stderr, "%s: new_node #4 %s/%d (glue+node)\n",
            __func__, ss_inet_ntop_tls(prefix), prefix->cidr);
        }
    }
    return new_node;
}


void ss_radix_remove(ss_radix_tree_t *radix, ss_radix_node_t *node) {
    ss_radix_node_t *parent, *child;
    
    assert(radix);
    assert(node);
    
    if (node->r && node->l) {
        if (SS_RADIX_DEBUG) {
            fprintf(stderr, "%s: #0 %s/%d (r & l)\n",
            __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
        }
        
        /* this might be a placeholder node -- have to check and make sure
        * there is a prefix aossciated with it ! */
        if (node->prefix != NULL)
            je_free(node->prefix);
        node->prefix = NULL;
        /* Also I needed to clear data pointer -- masaki */
        node->data = NULL;
        return;
    }
    
    if (node->r == NULL && node->l == NULL) {
        if (SS_RADIX_DEBUG) {
            fprintf(stderr, "%s: #1 %s/%d (!r & !l)\n",
            __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
        }
        parent = node->parent;
        je_free(node->prefix);
        je_free(node);
        radix->num_active_node--;
        
        if (parent == NULL) {
            assert(radix->head == node);
            radix->head = NULL;
            return;
        }
        
        if (parent->r == node) {
            parent->r = NULL;
            child = parent->l;
        }
        else {
            assert(parent->l == node);
            parent->l = NULL;
            child = parent->r;
        }
        
        if (parent->prefix)
            return;
        
        /* we need to remove parent too */
        
        if (parent->parent == NULL) {
            assert(radix->head == parent);
            radix->head = child;
        }
        else if (parent->parent->r == parent) {
            parent->parent->r = child;
        }
        else {
            assert(parent->parent->l == parent);
            parent->parent->l = child;
        }
        child->parent = parent->parent;
        je_free(parent);
        radix->num_active_node--;
        return;
    }
    
    if (SS_RADIX_DEBUG) {
        fprintf(stderr, "%s: #2 %s/%d (r ^ l)\n",
        __func__, ss_inet_ntop_tls(node->prefix), node->prefix->cidr);
    }
    if (node->r) {
        child = node->r;
    }
    else {
        assert(node->l);
        child = node->l;
    }
    parent = node->parent;
    child->parent = parent;
    
    je_free(node->prefix);
    je_free(node);
    radix->num_active_node--;
    
    if (parent == NULL) {
        assert(radix->head == node);
        radix->head = child;
        return;
    }
    
    if (parent->r == node) {
        parent->r = child;
    }
    else {
        assert(parent->l == node);
        parent->l = child;
    }
}
