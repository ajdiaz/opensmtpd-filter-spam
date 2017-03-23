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
  return (void *)spf_session_alloc(id);
}

void
on_session_destructor(void *s)
{
  spf_session_destructor(s);
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
    case SPAM_NEUTRAL:
    case SPAM_GOOD:
      return filter_api_accept(id);
  }

  return 1;
}

static int
on_connect(uint64_t id, struct filter_connect *conn)
{
  log_debug("debug: on_connect");

  (void) spam_step_pause(id, conn);

  if ((spam_step_dnsbl(id, conn) == SPAM_BAD) ||
      (spam_step_spf_connect(id, conn) == SPAM_BAD))
    return filter_api_reject_code(id, FILTER_CLOSE, 550,
                                  "Blacklisted");

  if (spam_step_grey(id, conn) == SPAM_NEUTRAL)
    return filter_api_reject_code(id, FILTER_CLOSE, 451,
                                  "Temporary error");

  return filter_api_accept(id);
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
  filter_api_no_chroot();
  filter_api_loop();

  log_debug("debug: exiting");

  return 1;
}
