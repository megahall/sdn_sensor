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

#pragma once

#include <sys/cdefs.h>
#include <sys/time.h>

#include <sys/types.h>
#include <sys/poll.h>
#include <unistd.h>

#include <time.h>
#include <paths.h>
#include <strings.h>
#include <inttypes.h>
#include <stdint.h>
#include <endian.h>

#if defined(__GNUC__)
# ifndef __dead
#  define __dead		__attribute__((__noreturn__))
# endif
# ifndef __packed
#  define __packed		__attribute__((__packed__))
# endif
#endif

#include <bsd/sys/poll.h>
#include <paths.h>

/* BEGIN PROTOTYPES */



/* END PROTOTYPES */
