/*
 * Copyright (c) 2004, 2005 Damien Miller <djm@mindrot.org>
 * Copyright (c) 2014 Matthew Hall <mhall@mhcomputing.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Peer tracking and state holding code, see peer.h for details */

#include <sys/types.h>
#include <sys/time.h>

#include <syslog.h>
#include <string.h>
#include <stdio.h>

#include <bsd/sys/queue.h>
#include <bsd/sys/tree.h>

#include <jemalloc/jemalloc.h>

#include "netflow_log.h"
#include "netflow_peer.h"
#include "netflow_format.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"

/* Debugging for general peer tracking */
#define PEER_DEBUG 0

/* Debugging for NetFlow 9 tracking */
#define PEER_DEBUG_NF9 0

/* Debugging for NetFlow 10 tracking */
#define PEER_DEBUG_NF10 0

/* XXX: mhall: global so netflow_peer.c can use the peers_lock */
extern struct peers netflow_peers;

/* NetFlow v.9 specific function */

void peer_nf9_template_delete(struct peer_nf9_source* nf9src,
    struct peer_nf9_template* template) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    TAILQ_REMOVE(&nf9src->templates, template, lp);
    if (template->records != NULL)
        je_free(template->records);
    je_free(template);
    nf9src->num_templates--;
    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
}

void peer_nf9_source_delete(struct peer_state* peer,
    struct peer_nf9_source* nf9src) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_nf9_template* nf9tmpl;

    while ((nf9tmpl = TAILQ_FIRST(&nf9src->templates)) != NULL)
        peer_nf9_template_delete(nf9src, nf9tmpl);
    peer->nf9_num_sources--;
    TAILQ_REMOVE(&peer->nf9, nf9src, lp);
    je_free(nf9src);
    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
}

void peer_nf9_delete(struct peer_state* peer) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_nf9_source* nf9src;

    while ((nf9src = TAILQ_FIRST(&peer->nf9)) != NULL)
        peer_nf9_source_delete(peer, nf9src);
    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
}

struct peer_nf9_source* peer_nf9_lookup_source(struct peer_state* peer, u_int32_t source_id) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_nf9_source* nf9src;

    TAILQ_FOREACH(nf9src, &peer->nf9, lp) {
        if (nf9src->source_id == source_id) {
            rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
            return (nf9src);
        }
    }
    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
    return (NULL);
}

struct peer_nf9_template* peer_nf9_lookup_template(struct peer_nf9_source* nf9src, u_int16_t template_id) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_nf9_template* nf9tmpl;

    TAILQ_FOREACH(nf9tmpl, &nf9src->templates, lp) {
        if (nf9tmpl->template_id == template_id)
            break;
    }
    if (nf9tmpl == NULL)
        return (NULL);

    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
    return (nf9tmpl);
}

struct peer_nf9_template* peer_nf9_find_template(struct peer_state* peer,
    u_int32_t source_id, u_int16_t template_id) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_nf9_source* nf9src;
    struct peer_nf9_template* nf9tmpl;

    nf9src = peer_nf9_lookup_source(peer, source_id);

    if (PEER_DEBUG_NF9) {
        logit(LOG_DEBUG, "%s: Lookup source 0x%08x for peer %s: %sFOUND",
            __func__, source_id, addr_ntop_buf(&peer->from),
            nf9src == NULL ? "NOT " : "");
    }

    if (nf9src == NULL) {
        rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
        return (NULL);
    }

    nf9tmpl = peer_nf9_lookup_template(nf9src, template_id);

    if (PEER_DEBUG_NF9) {
        logit(LOG_DEBUG, "%s: Lookup template 0x%04x: %sFOUND", __func__,
            template_id, nf9tmpl == NULL ? "NOT " : "");
    }

    if (nf9tmpl == NULL) {
        rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
        return (NULL);
    }

    if (PEER_DEBUG_NF9) {
        logit(LOG_DEBUG, "%s: Found template %s/0x%08x/0x%04x: %d records %p",
            __func__, addr_ntop_buf(&peer->from), source_id, template_id,
            nf9tmpl->num_records, nf9tmpl->records);
    }
    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
    return (nf9tmpl);
}

void
peer_nf9_template_update(struct peer_state* peer, u_int32_t source_id,
    u_int16_t template_id) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_nf9_source* nf9src;
    struct peer_nf9_template* nf9tmpl;

    if (PEER_DEBUG_NF9) {
        logit(LOG_DEBUG, "%s: Lookup template %s/0x%08x/0x%04x",
            __func__, addr_ntop_buf(&peer->from), template_id, source_id);
    }
    nf9src = peer_nf9_lookup_source(peer, source_id);
    if (nf9src == NULL) {
        rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
        return;
    }
    nf9tmpl = peer_nf9_lookup_template(nf9src, template_id);
    if (nf9tmpl == NULL) {
        rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
        return;
    }

    if (PEER_DEBUG_NF9) {
        logit(LOG_DEBUG, "%s: found template", __func__);
    }
    /* Move source and template to the head of the list */
    if (nf9src != TAILQ_FIRST(&peer->nf9)) {
        if (PEER_DEBUG_NF9) {
            logit(LOG_DEBUG, "%s: update source", __func__);
        }
        TAILQ_REMOVE(&peer->nf9, nf9src, lp);
        TAILQ_INSERT_HEAD(&peer->nf9, nf9src, lp);
    }
    if (nf9tmpl != TAILQ_FIRST(&nf9src->templates)) {
        if (PEER_DEBUG_NF9) {
            logit(LOG_DEBUG, "%s: update template", __func__);
        }
        TAILQ_REMOVE(&nf9src->templates, nf9tmpl, lp);
        TAILQ_INSERT_HEAD(&nf9src->templates, nf9tmpl, lp);
    }
    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
}

struct peer_nf9_source* peer_nf9_new_source(struct peer_state* peer, u_int32_t source_id) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_nf9_source* nf9src;

    /* If we have too many sources, then kick out the LRU */
    peer->nf9_num_sources++;
    if (peer->nf9_num_sources > netflow_peers.max_sources) {
        nf9src = TAILQ_LAST(&peer->nf9, peer_nf9_list);
        logit(LOG_WARNING, "forced deletion of source 0x%08x "
            "of peer %s", source_id, addr_ntop_buf(&peer->from));
        /* XXX ratelimit errors */
        peer_nf9_source_delete(peer, nf9src);
    }

    if ((nf9src = je_calloc(1, sizeof(*nf9src))) == NULL)
        logerrx("%s: je_calloc failed", __func__);
    nf9src->source_id = source_id;
    TAILQ_INIT(&nf9src->templates);
    TAILQ_INSERT_HEAD(&peer->nf9, nf9src, lp);

    if (PEER_DEBUG_NF9) {
        logit(LOG_DEBUG, "%s: new source %s/0x%08x", __func__,
            addr_ntop_buf(&peer->from), source_id);
    }

    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
    return (nf9src);
}

struct peer_nf9_template* peer_nf9_new_template(struct peer_state* peer, u_int32_t source_id, u_int16_t template_id) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_nf9_source* nf9src;
    struct peer_nf9_template* nf9tmpl;

    nf9src = peer_nf9_lookup_source(peer, source_id);
    if (nf9src == NULL)
        nf9src = peer_nf9_new_source(peer, source_id);

    /* If the source has too many templates, then kick out the LRU */
    nf9src->num_templates++;
    if (nf9src->num_templates > netflow_peers.max_templates) {
        nf9tmpl = TAILQ_LAST(&nf9src->templates,
            peer_nf9_template_list);
        logit(LOG_WARNING, "forced deletion of template 0x%04x from "
            "peer %s/0x%08x", template_id, addr_ntop_buf(&peer->from),
            source_id);
        /* XXX ratelimit errors */
        peer_nf9_template_delete(nf9src, nf9tmpl);
    }

    if ((nf9tmpl = je_calloc(1, sizeof(*nf9tmpl))) == NULL)
        logerrx("%s: je_calloc failed", __func__);
    nf9tmpl->template_id = template_id;
    TAILQ_INSERT_HEAD(&nf9src->templates, nf9tmpl, lp);

    if (PEER_DEBUG_NF9) {
        logit(LOG_DEBUG, "%s: new template %s/0x%08x/0x%04x", __func__,
            addr_ntop_buf(&peer->from), source_id, template_id);
    }

    /* Move source and template to the head of the list */
    if (nf9src != TAILQ_FIRST(&peer->nf9)) {
        TAILQ_REMOVE(&peer->nf9, nf9src, lp);
        TAILQ_INSERT_HEAD(&peer->nf9, nf9src, lp);
    }

    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
    return (nf9tmpl);
}


/* NetFlow v.10 specific function */

void peer_nf10_template_delete(struct peer_nf10_source* nf10src,
    struct peer_nf10_template* template) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    TAILQ_REMOVE(&nf10src->templates, template, lp);
    if (template->records != NULL)
        je_free(template->records);
    je_free(template);
    nf10src->num_templates--;
    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
}

void peer_nf10_source_delete(struct peer_state* peer,
    struct peer_nf10_source* nf10src) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_nf10_template* nf10tmpl;

    while ((nf10tmpl = TAILQ_FIRST(&nf10src->templates)) != NULL)
        peer_nf10_template_delete(nf10src, nf10tmpl);
    peer->nf10_num_sources--;
    TAILQ_REMOVE(&peer->nf10, nf10src, lp);
    je_free(nf10src);
    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
}

void peer_nf10_delete(struct peer_state* peer) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_nf10_source* nf10src;

    while ((nf10src = TAILQ_FIRST(&peer->nf10)) != NULL)
        peer_nf10_source_delete(peer, nf10src);
    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
}

struct peer_nf10_source* peer_nf10_lookup_source(struct peer_state* peer, u_int32_t source_id) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_nf10_source* nf10src;

    TAILQ_FOREACH(nf10src, &peer->nf10, lp) {
        if (nf10src->source_id == source_id) {
            rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
            return (nf10src);
        }
    }
    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
    return (NULL);
}

struct peer_nf10_template* peer_nf10_lookup_template(struct peer_nf10_source* nf10src, u_int16_t template_id) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_nf10_template* nf10tmpl;

    TAILQ_FOREACH(nf10tmpl, &nf10src->templates, lp) {
        if (nf10tmpl->template_id == template_id)
            break;
    }
    if (nf10tmpl == NULL) {
        rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
        return (NULL);
    }

    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
    return (nf10tmpl);
}

struct peer_nf10_template*
peer_nf10_find_template(struct peer_state* peer,
    u_int32_t source_id, u_int16_t template_id) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_nf10_source* nf10src;
    struct peer_nf10_template* nf10tmpl;

    nf10src = peer_nf10_lookup_source(peer, source_id);

    if (PEER_DEBUG_NF10) {
        logit(LOG_DEBUG, "%s: Lookup source 0x%08x for peer %s: %sFOUND",
            __func__, source_id, addr_ntop_buf(&peer->from),
            nf10src == NULL ? "NOT " : "");
    }

    if (nf10src == NULL) {
        rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
        return (NULL);
    }

    nf10tmpl = peer_nf10_lookup_template(nf10src, template_id);

    if (PEER_DEBUG_NF10) {
        logit(LOG_DEBUG, "%s: Lookup template 0x%04x: %sFOUND", __func__,
            template_id, nf10tmpl == NULL ? "NOT " : "");
    }

    if (nf10tmpl == NULL) {
        rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
        return (NULL);
    }

    if (PEER_DEBUG_NF10) {
        logit(LOG_DEBUG, "%s: Found template %s/0x%08x/0x%04x: %d records %p",
            __func__, addr_ntop_buf(&peer->from), source_id, template_id,
            nf10tmpl->num_records, nf10tmpl->records);
    }
    return (nf10tmpl);
}

void
peer_nf10_template_update(struct peer_state* peer, u_int32_t source_id,
    u_int16_t template_id) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_nf10_source* nf10src;
    struct peer_nf10_template* nf10tmpl;

    if (PEER_DEBUG_NF10) {
        logit(LOG_DEBUG, "%s: Lookup template %s/0x%08x/0x%04x",
            __func__, addr_ntop_buf(&peer->from), template_id, source_id);
    }
    nf10src = peer_nf10_lookup_source(peer, source_id);
    if (nf10src == NULL) {
        rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
        return;
    }
    nf10tmpl = peer_nf10_lookup_template(nf10src, template_id);
    if (nf10tmpl == NULL) {
        rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
        return;
    }

    if (PEER_DEBUG_NF10) {
        logit(LOG_DEBUG, "%s: found template", __func__);
    }
    /* Move source and template to the head of the list */
    if (nf10src != TAILQ_FIRST(&peer->nf10)) {
        if (PEER_DEBUG_NF10) {
            logit(LOG_DEBUG, "%s: update source", __func__);
        }
        TAILQ_REMOVE(&peer->nf10, nf10src, lp);
        TAILQ_INSERT_HEAD(&peer->nf10, nf10src, lp);
    }
    if (nf10tmpl != TAILQ_FIRST(&nf10src->templates)) {
        if (PEER_DEBUG_NF10) {
            logit(LOG_DEBUG, "%s: update template", __func__);
        }
        TAILQ_REMOVE(&nf10src->templates, nf10tmpl, lp);
        TAILQ_INSERT_HEAD(&nf10src->templates, nf10tmpl, lp);
    }
    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
}

struct peer_nf10_source* peer_nf10_new_source(struct peer_state* peer, u_int32_t source_id) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_nf10_source* nf10src;

    /* If we have too many sources, then kick out the LRU */
    peer->nf10_num_sources++;
    if (peer->nf10_num_sources > netflow_peers.max_sources) {
        nf10src = TAILQ_LAST(&peer->nf10, peer_nf10_list);
        logit(LOG_WARNING, "forced deletion of source 0x%08x "
            "of peer %s", source_id, addr_ntop_buf(&peer->from));
        /* XXX ratelimit errors */
        peer_nf10_source_delete(peer, nf10src);
    }

    if ((nf10src = je_calloc(1, sizeof(*nf10src))) == NULL)
        logerrx("%s: je_calloc failed", __func__);
    nf10src->source_id = source_id;
    TAILQ_INIT(&nf10src->templates);
    TAILQ_INSERT_HEAD(&peer->nf10, nf10src, lp);

    if (PEER_DEBUG_NF10) {
        logit(LOG_DEBUG, "%s: new source %s/0x%08x", __func__,
            addr_ntop_buf(&peer->from), source_id);
    }

    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
    return (nf10src);
}

struct peer_nf10_template* peer_nf10_new_template(struct peer_state* peer, u_int32_t source_id, u_int16_t template_id) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_nf10_source* nf10src;
    struct peer_nf10_template* nf10tmpl;

    nf10src = peer_nf10_lookup_source(peer, source_id);
    if (nf10src == NULL)
        nf10src = peer_nf10_new_source(peer, source_id);

    /* If the source has too many templates, then kick out the LRU */
    nf10src->num_templates++;
    if (nf10src->num_templates > netflow_peers.max_templates) {
        nf10tmpl = TAILQ_LAST(&nf10src->templates,
            peer_nf10_template_list);
        logit(LOG_WARNING, "forced deletion of template 0x%04x from "
            "peer %s/0x%08x", template_id, addr_ntop_buf(&peer->from),
            source_id);
        /* XXX ratelimit errors */
        peer_nf10_template_delete(nf10src, nf10tmpl);
    }

    if ((nf10tmpl = je_calloc(1, sizeof(*nf10tmpl))) == NULL)
        logerrx("%s: je_calloc failed", __func__);
    nf10tmpl->template_id = template_id;
    TAILQ_INSERT_HEAD(&nf10src->templates, nf10tmpl, lp);

    if (PEER_DEBUG_NF10) {
        logit(LOG_DEBUG, "%s: new template %s/0x%08x/0x%04x", __func__,
            addr_ntop_buf(&peer->from), source_id, template_id);
    }

    /* Move source and template to the head of the list */
    if (nf10src != TAILQ_FIRST(&peer->nf10)) {
        TAILQ_REMOVE(&peer->nf10, nf10src, lp);
        TAILQ_INSERT_HEAD(&peer->nf10, nf10src, lp);
    }

    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
    return (nf10tmpl);
}

/* General peer state housekeeping functions */
int peer_compare(struct peer_state* a, struct peer_state* b) {
    return (addr_cmp(&a->from, &b->from));
}

/* Generate functions for peer state tree */
SPLAY_PROTOTYPE(peer_tree, peer_state, tp, peer_compare);
SPLAY_GENERATE(peer_tree, peer_state, tp, peer_compare);

void delete_peer(struct peer_state* peer) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    TAILQ_REMOVE(&netflow_peers.peer_list, peer, lp);
    SPLAY_REMOVE(peer_tree, &netflow_peers.peer_tree, peer);
    peer_nf9_delete(peer);
    je_free(peer);
    netflow_peers.num_peers--;
    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
}

struct peer_state* new_peer(struct xaddr* addr) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_state* peer;

    /* If we have overflowed our peer table, then kick out the LRU peer */
    netflow_peers.num_peers++;
    if (netflow_peers.num_peers > netflow_peers.max_peers) {
        netflow_peers.num_forced++;
        peer = TAILQ_LAST(&netflow_peers.peer_list, peer_list);
        logit(LOG_WARNING, "forced deletion of peer %s",
            addr_ntop_buf(&peer->from));
        /* XXX ratelimit errors */
        delete_peer(peer);
    }

    if ((peer = je_calloc(1, sizeof(*peer))) == NULL)
        logerrx("%s: je_calloc failed", __func__);
    memcpy(&peer->from, addr, sizeof(peer->from));
    TAILQ_INIT(&peer->nf9);

    if (PEER_DEBUG) {
        logit(LOG_DEBUG, "new peer %s", addr_ntop_buf(addr));
    }

    TAILQ_INSERT_HEAD(&netflow_peers.peer_list, peer, lp);
    SPLAY_INSERT(peer_tree, &netflow_peers.peer_tree, peer);
    gettimeofday(&peer->firstseen, NULL);

    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
    return (peer);
}

void update_peer(struct peer_state* peer, u_int nflows, u_int netflow_version) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    /* Push peer to front of LRU queue, if it isn't there already */
    if (peer != TAILQ_FIRST(&netflow_peers.peer_list)) {
        TAILQ_REMOVE(&netflow_peers.peer_list, peer, lp);
        TAILQ_INSERT_HEAD(&netflow_peers.peer_list, peer, lp);
    }
    gettimeofday(&peer->lastvalid, NULL);
    peer->nflows += nflows;
    peer->npackets++;
    peer->last_version = netflow_version;
    if (PEER_DEBUG) {
        logit(LOG_DEBUG, "update peer %s", addr_ntop_buf(&peer->from));
    }
    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
}

struct peer_state* find_peer(struct xaddr* addr) {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_state tmp;
    struct peer_state* peer;

    bzero(&tmp, sizeof(tmp));
    memcpy(&tmp.from, addr, sizeof(tmp.from));

    peer = SPLAY_FIND(peer_tree, &netflow_peers.peer_tree, &tmp);
    if (PEER_DEBUG) {
        logit(LOG_DEBUG, "%s: found %s", __func__,
            peer == NULL ? "NONE" : addr_ntop_buf(addr));
    }

    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
    return (peer);
}

void dump_peers() {
    rte_spinlock_recursive_lock(&netflow_peers.peers_lock);
    struct peer_state* peer;
    u_int i;

    logit(LOG_INFO, "Peer state: %u of %u in used, %u forced deletions",
        netflow_peers.num_peers, netflow_peers.max_peers, netflow_peers.num_forced);
    i = 0;
    SPLAY_FOREACH(peer, peer_tree, &netflow_peers.peer_tree) {
        logit(LOG_INFO, "peer %u - %s: "
            "packets:%lu flows:%lu invalid:%lu no_template:%lu",
            i, addr_ntop_buf(&peer->from),
            peer->npackets, peer->nflows,
            peer->ninvalid, peer->no_template);
        logit(LOG_INFO, "peer %u - %s: first seen:%s.%03u",
            i, addr_ntop_buf(&peer->from),
            iso_time(peer->firstseen.tv_sec, 0),
            (u_int)(peer->firstseen.tv_usec / 1000));
        logit(LOG_INFO, "peer %u - %s: last valid:%s.%03u netflow v.%u",
            i, addr_ntop_buf(&peer->from),
            iso_time(peer->lastvalid.tv_sec, 0),
            (u_int)(peer->lastvalid.tv_usec / 1000),
            peer->last_version);
        i++;
    }
    rte_spinlock_recursive_unlock(&netflow_peers.peers_lock);
}

#pragma clang diagnostic pop
