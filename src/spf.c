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


spamstate_t
spam_step_spf_helo(uint64_t id, const char *helo)
{
  spam_session_t *d;
  log_debug("filter-spam: spf: on helo %lu", id);

  if ((d = spam_get_session(id)) == NULL)
    /* in theory never happen */
    fatalx("filter-spam: spf: no spam_session_t initialized on HELO");

  if(d->helo) free(d->helo);
  d->helo = strdup(helo);

  return SPAM_NEUTRAL;
}

spamstate_t
spam_step_spf_mail(uint64_t id, struct mailaddr *mail)
{
  spam_session_t *d;
  char *err = NULL;
  spamstate_t ret = SPAM_NEUTRAL;
  SPF_server_t *spf_server = NULL;
  SPF_request_t *spf_request = NULL;
  SPF_response_t *spf_response = NULL;
  SPF_result_t spf_result = SPF_RESULT_NEUTRAL;

  log_debug("filter-spam: spf: on mail");

  if ((d = spam_get_session(id)) == NULL)
    /* in theory never happen */
    fatalx("filter-spam: spf: no spam_session_t initialized on MAIL");

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
  return ret;
}
