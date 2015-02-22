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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>

#include "netflow_common.h"
#include "netflow.h"
#include "netflow_log.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"

static int logstarted = 0;
static int logstderr = 0;
static int logdebug = 0;

/* (re-)initialise logging */
void loginit(const char* ident, int to_stderr, int debug_flag)
{
    logstarted = 1;
    logdebug = (debug_flag != 0);
    logstderr = 1;
}

/* Varargs vsyslog-like log interface */
void vlogit(int level, const char* fmt, va_list args)
{
    vfprintf(stderr, fmt, args);
    fputs("\n", stderr);
}

/* Standard syslog-like interface */
void logit(int level, const char* fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vlogit(level, fmt, args);
    va_end(args);
}

/* Standard log interface that appends ": strerror(errno)" for convenience */
void logitm(int level, const char* fmt, ...)
{
    va_list args;
    char buf[1024];

    va_start(args, fmt);
    snprintf(buf, sizeof(buf), "%s: %s", fmt, strerror(errno));
    vlogit(level, buf, args);
    va_end(args);
}

/* logitm and exit (like err(3)) */
void logerr(const char* fmt, ...) __attribute__((noreturn))
{
    va_list args;
    char buf[1024];

    va_start(args, fmt);
    snprintf(buf, sizeof(buf), "%s: %s", fmt, strerror(errno));
    vlogit(LOG_ERR, buf, args);
    va_end(args);

    exit(1);
}

/* logit() and exit() (like errx(3)) */
void logerrx(const char* fmt, ...) __attribute__((noreturn))
{
    va_list args;

    va_start(args, fmt);
    vlogit(LOG_ERR, fmt, args);
    va_end(args);

    exit(1);
}

#pragma clang diagnostic pop
