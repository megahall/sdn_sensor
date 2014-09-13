/*
 * For inet_ntop() functions:
 *
 * Copyright (c) 1996 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <rte_log.h>

#include "common.h"
#include "ip_utils.h"

int ss_dump_cidr(FILE* fd, const char* label, ip_addr_t* ip_addr) {
    char tmp[SS_ADDR_STR_MAX];
    memset(tmp, 0, sizeof(tmp));
    
    if (fd == NULL) fd = stderr;
    
    if (ip_addr == NULL) {
        fprintf(fd, "cidr %s: null\n", label);
        return -1;
    }
    
    ss_inet_ntop(ip_addr, tmp, sizeof(tmp));
    
    fprintf(fd, "cidr %s: %s\n", label, tmp);
    return 0;
}

int ss_parse_cidr(const char* input, ip_addr_t* ip_addr) {
    unsigned int input_len = 0;
    int rv = -1;
    char ip_str[SS_INET6_ADDRSTRLEN+4+1]; /* '+4' is for prefix (if any) */
    char* prefix_start;
    char* prefix_end;
    long prefix = 0;
    
    if (!input || ! *input || !ip_addr)
        return -1;
    
    input_len = strlen(input);
    
    /* if token is too big... */
    if (input_len >= SS_INET6_ADDRSTRLEN+4)
        return -1;
    
    snprintf(ip_str, input_len+1, "%s", input);
    
    /* convert the network prefix */
    prefix_start = strrchr(ip_str, '/');
    if (prefix_start == NULL) {
        ip_addr->prefix = 0;
    }
    else {
        *prefix_start = '\0';
        prefix_start ++;
        errno = 0;
        prefix = strtol(prefix_start, &prefix_end, 10);
        if (errno || (*prefix_end != '\0') || prefix < 0) {
            return -1;
        }
        ip_addr->prefix = prefix;
    }
    
    /* convert the IP addr */
    /* IPv6 */
    if (strchr(ip_str, ':') &&
        ss_inet_pton(SS_AF_INET6, ip_str, ip_addr) == 1 &&
        prefix <= SS_V6_PREFIX_MAX) {
        ip_addr->family = SS_AF_INET6;
        if (ip_addr->prefix == 0) {
            ip_addr->prefix = SS_V6_PREFIX_MAX;
        }
        rv = 1;
    }
    else if (strchr(ip_str, '.') &&
             ss_inet_pton(SS_AF_INET4, ip_str, ip_addr) == 1 &&
             prefix <= SS_V4_PREFIX_MAX) {
        ip_addr->family = SS_AF_INET4;
        if (ip_addr->prefix == 0) {
            ip_addr->prefix = SS_V4_PREFIX_MAX;
        }
        rv = 1;
    }
    else {
        RTE_LOG(ERR, SS, "could not parse CIDR / IP: %s", ip_str);
        memset(&ip_addr, 0, sizeof(ip_addr));
    }
    
    return rv;
}

/* int
 * ss_inet_pton(af, src, dst)
 *      convert from presentation format (which usually means ASCII printable)
 *      to network format (which is usually some kind of binary format).
 * return:
 *      1 if the address was valid for the specified address family
 *      0 if the address wasn't valid (`dst' is untouched in this case)
 *      -1 if some other error occurred (`dst' is untouched in this case, too)
 * author:
 *      Paul Vixie, 1996.
 */
int ss_inet_pton(int af, const char* src, ip_addr_t* dst) {
    switch (af) {
        case SS_AF_INET4: {
            return (ss_inet_pton4(src, (uint8_t*) &dst->ip4_addr));
        }
        case SS_AF_INET6: {
            return (ss_inet_pton6(src, (uint8_t*) &dst->ip6_addr));
        }
        default: {
            errno = EAFNOSUPPORT;
            return (-1);
        }
    }
    /* NOTREACHED */
}

/* int
 * ss_inet_pton4(src, dst)
 *      like ss_inet_aton() but without all the hexadecimal and shorthand.
 * return:
 *      1 if `src' is a valid dotted quad, else 0.
 * notice:
 *      does not touch `dst' unless it's returning 1.
 * author:
 *      Paul Vixie, 1996.
 */
int ss_inet_pton4(const char* src, uint8_t* dst) {
    static const char digits[] = "0123456789";
    int saw_digit, octets, ch;
    unsigned char tmp[IPV4_ALEN], *tp;

    saw_digit = 0;
    octets = 0;
    *(tp = tmp) = 0;
    while ((ch = *src++) != '\0') {
        const char* pch;

        if ((pch = strchr(digits, ch)) != NULL) {
            unsigned int new = *tp * 10 + (pch - digits);

            if (new > 255)
                return (0);
            if (! saw_digit) {
                if (++octets > 4)
                    return (0);
                saw_digit = 1;
            }
            *tp = (uint8_t)new;
        } else if (ch == '.' && saw_digit) {
            if (octets == 4)
                return (0);
            *++tp = 0;
            saw_digit = 0;
        } else
            return (0);
    }
    if (octets < 4)
        return (0);
    
    memcpy(dst, tmp, IPV4_ALEN);
    return (1);
}

/* int
 * ss_inet_pton6(src, dst)
 *      convert presentation level address to network order binary form.
 * return:
 *      1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *      (1) does not touch `dst' unless it's returning 1.
 *      (2) :: in a full address is silently ignored.
 * credit:
 *      inspired by Mark Andrews.
 * author:
 *      Paul Vixie, 1996.
 */
int ss_inet_pton6(const char* src, uint8_t* dst) {
    static const char xdigits_l[] = "0123456789abcdef";
    static const char xdigits_u[] = "0123456789ABCDEF";
    unsigned char tmp[IPV6_ALEN], *tp = 0, *endp = 0, *colonp = 0;
    const char* xdigits = 0;
    const char* curtok = 0;
    int ch = 0, saw_xdigit = 0, count_xdigit = 0;
    unsigned int val = 0;
    unsigned dbloct_count = 0;

    memset((tp = tmp), '\0', IPV6_ALEN);
    endp = tp + IPV6_ALEN;
    colonp = NULL;
    /* Leading :: requires some special handling. */
    if (*src == ':')
        if (*++src != ':')
            return (0);
    curtok = src;
    saw_xdigit = count_xdigit = 0;
    val = 0;

    while ((ch = *src++) != '\0') {
        const char* pch;

        if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
            pch = strchr((xdigits = xdigits_u), ch);
        if (pch != NULL) {
            if (count_xdigit >= 4)
                return (0);
            val <<= 4;
            val |= (pch - xdigits);
            if (val > 0xffff)
                return (0);
            saw_xdigit = 1;
            count_xdigit++;
            continue;
        }
        if (ch == ':') {
            curtok = src;
            if (!saw_xdigit) {
                if (colonp)
                    return (0);
                colonp = tp;
                continue;
            } else if (*src == '\0') {
                return (0);
            }
            if (tp + sizeof(int16_t) > endp)
                return (0);
            *tp++ = (unsigned char) ((val >> 8) & 0xff);
            *tp++ = (unsigned char) (val & 0xff);
            saw_xdigit = 0;
            count_xdigit = 0;
            val = 0;
            dbloct_count++;
            continue;
        }
        if (ch == '.' && ((tp + IPV4_ALEN) <= endp) &&
            ss_inet_pton4(curtok, tp) > 0) {
            tp += IPV4_ALEN;
            saw_xdigit = 0;
            dbloct_count += 2;
            break;  /* '\0' was seen by ss_inet_pton4(). */
        }
        return (0);
    }
    if (saw_xdigit) {
        if (tp + sizeof(int16_t) > endp)
            return (0);
        *tp++ = (unsigned char) ((val >> 8) & 0xff);
        *tp++ = (unsigned char) (val & 0xff);
        dbloct_count++;
    }
    if (colonp != NULL) {
        /* if we already have 8 double octets, having a colon means error */
        if (dbloct_count == 8)
            return 0;

        /*
         * Since some memmove()'s erroneously fail to handle
         * overlapping regions, we'll do the shift by hand.
         */
        const int n = tp - colonp;
        int i;

        for (i = 1; i <= n; i++) {
            endp[- i] = colonp[n - i];
            colonp[n - i] = 0;
        }
        tp = endp;
    }
    if (tp != endp) {
        return (0);
    }
    
    memcpy(dst, tmp, IPV6_ALEN);
    return (1);
}

/* char*
 * ss_inet_ntop(af, src, dst, size)
 *      convert a network format address to presentation format.
 * return:
 *      pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *      Paul Vixie, 1996.
 */
const char* ss_inet_ntop(const ip_addr_t* src, char* dst, unsigned int size) {
    switch (src->family) {
        case SS_AF_INET4: {
            return (ss_inet_ntop4((uint8_t*) &src->ip4_addr, dst, size));
        }
        case SS_AF_INET6: {
            return (ss_inet_ntop6((uint8_t*) &src->ip6_addr, dst, size));
        }
        default: {
            errno = EAFNOSUPPORT;
            return (NULL);
        }
    }
    /* NOTREACHED */
}

/* const char*
 * ss_inet_ntop4(src, dst, size)
 *      format an IPv4 address
 * return:
 *      `dst' (as a const)
 * notes:
 *      (1) uses no statics
 *      (2) takes a u_char* not an in_addr as input
 * author:
 *      Paul Vixie, 1996.
 */
const char* ss_inet_ntop4(const uint8_t* src, char* dst, unsigned int size) {
    static const char fmt[] = "%u.%u.%u.%u";
    char tmp[sizeof "255.255.255.255"];

    if (sprintf(tmp, fmt, src[0], src[1], src[2], src[3]) >= (int) size) {
        errno = ENOSPC;
        return (NULL);
    }
    
    return strcpy(dst, tmp);
}

/* const char*
 * inet_ntop6(src, dst, size)
 *      convert IPv6 binary address into presentation (printable) format
 * author:
 *      Paul Vixie, 1996.
 */
const char* ss_inet_ntop6(const uint8_t* src, char* dst, unsigned int size) {
    /*
     * Note that int32_t and int16_t need only be "at least" large enough
     * to contain a value of the specified size.
     */
    char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
    struct { int base, len; } best, cur;
    u_int words[IPV6_ALEN / SS_INT16_SIZE];
    int i;

    /*
     * Preprocess:
     *      Copy the input (bytewise) array into a wordwise array.
     *      Find the longest run of 0x00's in src[] for :: shorthanding.
     */
    memset(words, '\0', sizeof words);
    for (i = 0; i < IPV6_ALEN; i += 2) {
        words[i / 2] = (src[i] << 8) | src[i + 1];
    }
    best.base = -1;
    cur.base = -1;
    best.len = 0;
    cur.len = 0;
    for (i = 0; i < (IPV6_ALEN / SS_INT16_SIZE); i++) {
        if (words[i] == 0) {
            if (cur.base == -1) {
                cur.base = i, cur.len = 1;
            }
            else {
                cur.len++;
            }
        }
        else {
            if (cur.base != -1) {
                if (best.base == -1 || cur.len > best.len) {
                    best = cur;
                }
                cur.base = -1;
            }
        }
    }
    if (cur.base != -1) {
        if (best.base == -1 || cur.len > best.len) {
            best = cur;
        }
    }
    if (best.base != -1 && best.len < 2) {
        best.base = -1;
    }

    /*
     * Format the result.
     */
    tp = tmp;
    for (i = 0; i < (IPV6_ALEN / SS_INT16_SIZE); i++) {
        /* Are we inside the best run of 0x00's? */
        if (best.base != -1 && i >= best.base && i < (best.base + best.len)) {
            if (i == best.base) {
                *tp++ = ':';
            }
            continue;
        }
        /* Are we following an initial run of 0x00s or any real hex? */
        if (i != 0)
            *tp++ = ':';
        /* Is this address an encapsulated IPv4? */
        if (i == 6 && best.base == 0 &&
            (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
            if (!ss_inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp))) {
                return (NULL);
            }
            tp += strlen(tp);
            break;
        }
        tp += sprintf(tp, "%x", words[i]);
    }
    /* Was it a trailing run of 0x00's? */
    if (best.base != -1 && (best.base + best.len) == (IPV6_ALEN / SS_INT16_SIZE)) {
        *tp++ = ':';
    }
    *tp++ = '\0';

    /*
     * Check for overflow, copy, and we're done.
     */
    if ((unsigned int)(tp - tmp) > size) {
        errno = ENOSPC;
        return (NULL);
    }
    return strcpy(dst, tmp);
}
