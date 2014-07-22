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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

#include <rte_log.h>

#include "common.h"
#include "ip_utils.h"

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
int ss_inet_pton(int af, const char* src, void* dst) {
    switch (af) {
        case SS_AF_INET:
            return (ss_inet_pton4(src, dst));
        case SS_AF_INET6:
            return (ss_inet_pton6(src, dst));
        default:
            errno = EAFNOSUPPORT;
            return (-1);
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
int ss_inet_pton4(const char* src, unsigned char* dst) {
    static const char digits[] = "0123456789";
    int saw_digit, octets, ch;
    unsigned char tmp[SS_V4_ADDR_SIZE], *tp;

    saw_digit = 0;
    octets = 0;
    *(tp = tmp) = 0;
    while ((ch = *src++) != '\0') {
        const char *pch;

        if ((pch = strchr(digits, ch)) != NULL) {
            unsigned int new = *tp * 10 + (pch - digits);

            if (new > 255)
                return (0);
            if (! saw_digit) {
                if (++octets > 4)
                    return (0);
                saw_digit = 1;
            }
            *tp = (unsigned char)new;
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

    memcpy(dst, tmp, SS_V4_ADDR_SIZE);
    return (1);
}

/* int
 * inet_pton6(src, dst)
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
int ss_inet_pton6(const char* src, unsigned char* dst) {
    static const char xdigits_l[] = "0123456789abcdef";
    static const char xdigits_u[] = "0123456789ABCDEF";
    unsigned char tmp[SS_V6_ADDR_SIZE], *tp = 0, *endp = 0, *colonp = 0;
    const char *xdigits = 0, *curtok = 0;
    int ch = 0, saw_xdigit = 0, count_xdigit = 0;
    unsigned int val = 0;
    unsigned dbloct_count = 0;

    memset((tp = tmp), '\0', SS_V6_ADDR_SIZE);
    endp = tp + SS_V6_ADDR_SIZE;
    colonp = NULL;
    /* Leading :: requires some special handling. */
    if (*src == ':')
        if (*++src != ':')
            return (0);
    curtok = src;
    saw_xdigit = count_xdigit = 0;
    val = 0;

    while ((ch = *src++) != '\0') {
        const char *pch;

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
        if (ch == '.' && ((tp + SS_V4_ADDR_SIZE) <= endp) &&
            ss_inet_pton4(curtok, tp) > 0) {
            tp += SS_V4_ADDR_SIZE;
            saw_xdigit = 0;
            dbloct_count += 2;
            break;  /* '\0' was seen by inet_pton4(). */
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
    if (tp != endp)
        return (0);
    memcpy(dst, tmp, SS_V6_ADDR_SIZE);
    return (1);
}

int ss_parse_cidr(const char* input, ip_addr* ip_addr) {
    unsigned int input_len = 0;
    int rv = -1;
    char ip_str[SS_INET6_ADDRSTRLEN+4+1]; /* '+4' is for prefix (if any) */
    char *prefix_start, *prefix_end;
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
        ss_inet_pton(SS_AF_INET6, ip_str, &ip_addr->addr.ipv6) == 1 &&
        prefix <= SS_V6_PREFIX_MAX) {
        ip_addr->family = SS_AF_INET6;
        if (ip_addr->prefix == 0) {
            ip_addr->prefix = SS_V6_PREFIX_MAX;
        }
        rv = input_len;
    }
    else if (strchr(ip_str, '.') &&
             ss_inet_pton(SS_AF_INET, ip_str, &ip_addr->addr.ipv4) == 1 &&
             prefix <= SS_V4_PREFIX_MAX) {
        ip_addr->family = SS_AF_INET;
        if (ip_addr->prefix == 0) {
            ip_addr->prefix = SS_V4_PREFIX_MAX;
        }
        rv = input_len;
    }
    else {
        RTE_LOG(ERR, SS, "could not parse CIDR / IP: %s", ip_str);
        memset(&ip_addr->addr, 0, sizeof(ip_addr->addr));
    }
    
    return input_len;
}
