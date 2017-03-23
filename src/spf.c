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

#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#include <spf2/spf.h>

#include "filter_spam.h"
#include "spf.h"

#ifdef ENABLE_SESSION
#define GETUDATA(i) filter_api_session(i)
spam_spf_t *
spf_session_alloc(uint64_t id)
{
  log_debug("filter-spam: spf: spf_allocator");
  return xcalloc(1, sizeof(spam_spf_t), "filter-spam: spf_alloc");
}

void
spf_session_destructor(void *s)
{
  log_debug("filter-spam: spf: spf_destructor");
  spf_clear((spam_spf_t *)s);
}
#else
#define GETUDATA(i) filter_api_get_udata(i)
#endif


static spam_spf_t *
spf_session_set_conn(uint64_t id, const struct sockaddr_storage *ss)
{
  spam_spf_t *ret;
  char *buf;

#ifdef ENABLE_SESSION
  ret = (spam_spf_t *) GETUDATA(id);
#else
  ret = xcalloc(1, sizeof(spam_spf_t), "filter-spam: spf_alloc");
#endif

  log_debug("filter-spam: spf: set_conn: %p", ret);
  ret->sa_family = ss->ss_family;

  if ((buf = helper_ip2str(ss)) == NULL)
    return NULL;

  /* now we have a string representation of the IP */
  ret->addr = buf;

#ifndef ENABLE_SESSION
  filter_api_set_udata(id, ret);
#endif

  return ret;
}


static void
spf_clear(spam_spf_t *d)
{
  if (d != NULL) { /* prevent double free */
    if (d->addr) free(d->addr);
    if (d->helo) free(d->helo);
    free(d);
  }
}

spamstate_t
spam_step_spf_connect(uint64_t id, struct filter_connect *conn)
{
  log_debug("filter-spam: spf: on connect %lu", id);
  if ((spf_session_set_conn(id, &conn->remote)) == NULL)
    log_warn("filter-spam: spf: unable to set conn in session");

  return SPAM_NEUTRAL;
}


spamstate_t
spam_step_spf_helo(uint64_t id, const char *helo)
{
  spam_spf_t *d;
  log_debug("filter-spam: spf: on helo %lu", id);

  if ((d = GETUDATA(id)) == NULL)
    /* in theory never happen */
    fatalx("filter-spam: spf: no spam_spf_t initialized on HELO");

  if(d->helo) free(d->helo);
  d->helo = strdup(helo);

  return SPAM_NEUTRAL;
}

spamstate_t
spam_step_spf_mail(uint64_t id, struct mailaddr *mail)
{
  spam_spf_t *d;
  char *err = NULL;
  spamstate_t ret = SPAM_NEUTRAL;
  SPF_server_t *spf_server = NULL;
  SPF_request_t *spf_request = NULL;
  SPF_response_t *spf_response = NULL;
  SPF_result_t spf_result = SPF_RESULT_NEUTRAL;

  log_debug("filter-spam: spf: on mail");

  if ((d = GETUDATA(id)) == NULL)
    /* in theory never happen */
    fatalx("filter-spam: spf: no spam_spf_t initialized on MAIL");

#define GOTO_CLEAN(_x) { err=_x; goto clean; }

  if ((spf_server = SPF_server_new(SPF_DNS_CACHE, 1)) == NULL)
    GOTO_CLEAN("filter-spam: spf: unable to initialize SPF_server");

  if ((spf_request = SPF_request_new(spf_server)) == NULL)
    GOTO_CLEAN("filter-spam: spf: unable to initialize SPF_request");

  if (d->sa_family == AF_INET6)
  {
    if (SPF_request_set_ipv6_str(spf_request, d->addr))
      GOTO_CLEAN("filter-spam: spf: invalid ipv6 address on mail");
  }
  else if (d->sa_family == AF_INET)
  {
    if (SPF_request_set_ipv4_str(spf_request, d->addr))
      GOTO_CLEAN("filter-spam: spf: invalid ipv4 address on mail");
  }
  else
    GOTO_CLEAN("filter-spam: spf: invalid family on mail");

  if (d->helo)
  {
    if (SPF_request_set_helo_dom(spf_request, d->helo))
      GOTO_CLEAN("filter-spam: spf: invalid HELO on mail");
  }

  if (SPF_request_set_env_from(spf_request, filter_api_mailaddr_to_text(mail)))
    GOTO_CLEAN("filter-spam: spf: invalid from on mail");

  log_debug("filter-spam: spf: check for helo=%s mail=%s addr=%s",
            d->helo, filter_api_mailaddr_to_text(mail), d->addr);

  if (SPF_request_query_mailfrom(spf_request, &spf_response))
    GOTO_CLEAN("filter-spam: spf: unable to query");


  spf_result = SPF_response_result(spf_response);

  switch (spf_result){
    case SPF_RESULT_PASS:
      ret = SPAM_GOOD;
      break;
    case SPF_RESULT_FAIL:
      log_warn("filter-spam: spf: failed SPF validation %s via %s",
               filter_api_mailaddr_to_text(mail),
               d->addr);
      ret = SPAM_BAD;
    default:
      log_warn("filter-spam: spf: neutral SPF validation %s via %s",
               filter_api_mailaddr_to_text(mail),
               d->addr);
      ret = SPAM_NEUTRAL;
  }

clean:
  if (err) log_warn("%s", err);
  if (spf_server) free(spf_server);
  if (spf_request) free(spf_request);
#ifndef ENABLE_SESSION
  spf_clear(d);
#endif
  return ret;
}
