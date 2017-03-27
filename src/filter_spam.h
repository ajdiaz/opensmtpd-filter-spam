/*
 * Copyright (c) 2016 Andrés J. Díaz <ajdiaz@ajdiaz.me>
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

#ifndef FILTER_SPAM_H
#define FILTER_SPAM_H

#include "smtpd-defines.h"
#include "includes.h"
#include "smtpd-api.h"
#include "log.h"

typedef enum spamstate {
    SPAM_NEUTRAL = 0x0,
    SPAM_BAD = 0x1,
    SPAM_GOOD = 0x2,
} spamstate_t;

typedef struct {
  sa_family_t sa_family;
  char *addr;
  char *helo;
} spam_session_t;

char *
helper_ip2str(const struct sockaddr_storage *ss);

spam_session_t *
spam_get_session(uint64_t id);

#endif /* !FILTER_SPAM_H */
