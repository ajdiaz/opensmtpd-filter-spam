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

#ifndef _SPAMFILTER_SPF_H
#define _SPAMFILTER_SPF_H

#include "filter_spam.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>


typedef struct {
  sa_family_t sa_family;
  char *addr;
  char *helo;
} spam_spf_t;


#ifdef ENABLE_SESSION
spam_spf_t *
spf_session_alloc(uint64_t id);

void
spf_session_destructor(void *s);
#endif

spamstate_t
spam_step_spf_connect(uint64_t id, struct filter_connect *conn);

void
spam_step_spf_exit(uint64_t id);

spamstate_t
spam_step_spf_helo(uint64_t id, const char *helo);

spamstate_t
spam_step_spf_mail(uint64_t id, struct mailaddr *mail);

#endif
