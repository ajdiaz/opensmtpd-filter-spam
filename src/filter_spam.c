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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "filter_spam.h"
#include "pause.h"
#include "dnsbl.h"
#include "spf.h"
#include "grey.h"

#ifdef ENABLE_SESSION
#define GETUDATA(i) filter_api_session(i)
spam_session_t *
spam_session_alloc(uint64_t id)
{
  log_debug("filter-spam: session_allocator");
  return xcalloc(1, sizeof(spam_session_t), "filter-spam: session_alloc");
}

void
spam_session_destructor(void *s)
{
  log_debug("filter-spam: session_destructor");
  spam_clear((spam_session_t *)s);
}
#else
#define GETUDATA(i) filter_api_get_udata(i)
#endif


static spam_session_t *
spam_session_set_conn(uint64_t id, const struct sockaddr_storage *ss)
{
  spam_session_t *ret;
  char *buf;

#ifdef ENABLE_SESSION
  ret = (spam_session_t *) GETUDATA(id);
#else
  ret = xcalloc(1, sizeof(spam_session_t), "filter-spam: session_alloc");
#endif

  log_debug("filter-spam: set_conn: %p", ret);
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

spam_session_t *
spam_get_session(uint64_t id)
{
  spam_session_t *s = NULL;
  s = GETUDATA(id);
  return s;
}

static void
spam_clear(spam_session_t *d)
{
  if (d != NULL) { /* prevent double free */
    if (d->addr) free(d->addr);
    if (d->helo) free(d->helo);
    free(d);
  }
}

spamstate_t
spam_step_all_connect(uint64_t id, struct filter_connect *conn)
{
  log_debug("filter-spam: on connect %lu", id);
  if ((spam_session_set_conn(id, &conn->remote)) == NULL)
    log_warn("filter-spam: unable to set conn in session");

  return SPAM_NEUTRAL;
}

void
spam_step_all_disconnect(uint64_t id)
{
  spam_session_t *d = NULL;

  if ((d = GETUDATA(id)) == NULL)
    /* in theory never happen */
    fatalx("filter-spam: no spam_session_t initialized on disconnect");

  spam_clear(d);
}

char *
helper_ip2str(const struct sockaddr_storage *ss)
{

  char *buf;

  buf = xcalloc(1, INET6_ADDRSTRLEN, "filter-spam: helper_ip2str: ");
  memset(buf, 0, INET6_ADDRSTRLEN);

  if (ss->ss_family == AF_INET6)
  {
    struct sockaddr_in6 *ip6 = (struct sockaddr_in6 *)ss;

#define hinet6_str(i,b) \
    inet_ntop(AF_INET6, \
              (const void *)&((i)->sin6_addr.s6_addr), \
              (char *)b, \
              INET6_ADDRSTRLEN)

    if (hinet6_str(ip6, buf) == NULL)
    {
      log_warn("filter-spam: grey: can't convert ipv6 addr to str %i", errno);
      free(buf);
      return NULL;
    }
  }
  else if (ss->ss_family == AF_INET)
  {
    struct sockaddr_in *ip4 = (struct sockaddr_in *)ss;

#define hinet4_str(i,b) \
    inet_ntop(AF_INET, \
              (const void *)&((i)->sin_addr.s_addr), \
              (char *)b, \
              INET_ADDRSTRLEN)

    if (hinet4_str(ip4, buf) == NULL)
    {
      log_warn("filter-spam: grey: can't convert ipv4 addr to str %i", errno);
      free(buf);
      return NULL;
    }
  }
  else
  {
    log_warn("filter-spam: spf_session_set_conn: unknown protocol family %i",
             ss->ss_family);
    free(buf);
    return NULL;
  }

  return buf;
}


#ifdef ENABLE_SESSION
static void *
on_session_alloc(uint64_t id)
{
  return (void *)spam_session_alloc(id);
}

void
on_session_destructor(void *s)
{
  spam_session_destructor(s);
}
#endif

static int
on_helo(uint64_t id, const char *helo)
{
  log_debug("debug: on_helo");

  if (spam_step_spf_helo(id, helo) == SPAM_BAD)
    return filter_api_reject_code(id, FILTER_CLOSE, 550,
                                  "Blacklisted");

  return filter_api_accept(id);
}


static int
on_mail(uint64_t id, struct mailaddr *m)
{
  log_debug("debug: on_mail");

  spamstate_t ret = SPAM_NEUTRAL;

  ret = spam_step_spf_mail(id, m);

  switch(ret) {
    case SPAM_BAD:
      return filter_api_reject_code(id, FILTER_CLOSE, 550,
                                    "Blacklisted");
    case SPAM_GOOD:
      log_debug("Bypassing greylist because good SPF");
      return filter_api_accept(id);

    case SPAM_NEUTRAL:
      if (spam_step_grey_mail(id, m) == SPAM_NEUTRAL)
        return filter_api_reject_code(id, FILTER_CLOSE, 451,
                                      "Temporary error");
  }

  return filter_api_accept(id);
}

static int
on_connect(uint64_t id, struct filter_connect *conn)
{
  log_debug("debug: on_connect");

  (void) spam_step_all_connect(id, conn);
  (void) spam_step_pause(id, conn);

  if (spam_step_dnsbl(id, conn) == SPAM_BAD)
    return filter_api_reject_code(id, FILTER_CLOSE, 550,
                                  "Blacklisted");

  return filter_api_accept(id);
}

static void
on_disconnect(uint64_t id)
{
  log_debug("filter-spam: on_disconnect");
  (void) spam_step_all_disconnect(id);
}

int
main(int argc, char **argv)
{
  int ch, d = 0, v = 0;
  const char *errstr;

  log_init(1);

  while ((ch = getopt(argc, argv, "dvp:D:g:E:F:")) != -1) {
    switch (ch) {
      case 'd':
        d = 1;
        break;
      case 'v':
        v |= TRACE_DEBUG;
        break;
      case 'p':
        pause_setconf(strtonum(optarg, 1, 300, &errstr));
        if (errstr)
          fatalx("filter-spam: pause seconds option is %s: %s",
                 errstr, optarg);
        break;
      case 'D':
        dnsbl_setconf(optarg);
        break;
      case 'g':
        grey_setconf_db(optarg);
        break;
      case 'E':
        grey_setconf_expire(strtonum(optarg, 0, 72*3600, &errstr));
        if (errstr)
          fatalx("filter-spam: expire max option is %s: %s",
                 errstr, optarg);
      case 'F':
        grey_setconf_fastrecon(strtonum(optarg, 0, 12*3600, &errstr));
        if (errstr)
          fatalx("filter-spam: fast reconnect option is %s: %s",
                 errstr, optarg);
      default:
        log_warnx("warn: bad option");
        return 1;
        /* NOTREACHED */
    }
  }
  argc -= optind;
  argv += optind;

  log_init(d);
  log_verbose(v);

  log_debug("filter-spam: starting session...");

#ifdef ENABLE_SESSION
  filter_api_session_allocator(on_session_alloc);
  filter_api_session_destructor(on_session_destructor);
#endif

  log_debug("debug: starting handler...");
  filter_api_on_connect(on_connect);
  filter_api_on_helo(on_helo);
  filter_api_on_mail(on_mail);
  filter_api_on_disconnect(on_disconnect);
  filter_api_no_chroot();
  filter_api_loop();

  log_debug("debug: exiting");

  return 1;
}
