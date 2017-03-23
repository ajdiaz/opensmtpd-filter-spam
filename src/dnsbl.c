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

#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "dnsbl.h"

static char dnsbl_host[256] = "dnsbl.sorbs.net";

void
dnsbl_setconf(const char *h)
{
  strncpy(dnsbl_host, h, 255);
  dnsbl_host[255]='\0';
}

spamstate_t
spam_step_dnsbl(uint64_t id, struct filter_connect *conn)
{
  struct addrinfo hints = {
    .ai_family = PF_UNSPEC,
    .ai_socktype = SOCK_STREAM
  };
  struct addrinfo *ar = NULL;
  in_addr_t in_addr;
  char buf[512];
  int ret;

  log_debug("debug: filter-spam: starting DNSBL check");

  /* DNSBL has no real impact on others than IPv4 */
  if (conn->remote.ss_family != AF_INET)
    return SPAM_NEUTRAL;

  in_addr = ntohl(
    ((const struct sockaddr_in *)&conn->remote)->sin_addr.s_addr
  );

#define inaddr_buf(i, b) \
	snprintf(b, sizeof(b), "%d.%d.%d.%d.%s.", \
	         i & 0xff, (i >> 8) & 0xff, (i >> 16) & 0xff, (i >> 24) & 0xff, \
	         dnsbl_host)

	if (inaddr_buf(in_addr, buf) >= (int)sizeof(buf))
	{
		log_warnx("filter-spam: dnsbl: host name too long: %s", buf);
		return SPAM_BAD;
	}

	ret = getaddrinfo(buf, NULL, &hints, &ar);

  if (ar)
    freeaddrinfo(ar);

  if (ret != EAI_NONAME)
  {
    log_debug("filter-spam: dnsbl: trap spam: %s", buf);
    return SPAM_BAD;
  }

  return SPAM_NEUTRAL;
}
