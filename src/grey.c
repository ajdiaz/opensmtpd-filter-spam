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
#include <time.h>

#include <db.h>

#include "grey.h"

#define abort(l, m) do { log_warn(m); chain = SPAM_GOOD; goto l; } while(0)

static time_t fast_reconnect_min = 60;
static time_t expire_max = 24*3600;

char greylist_db[256] = "/var/lib/greylist.db";

void
grey_setconf_db(const char *g)
{
  strncpy(greylist_db, g, 255);
  greylist_db[255]='\0';
}

void
grey_setconf_expire(time_t e)
{
  expire_max = e;
}

void
grey_setconf_fastrecon(time_t f)
{
  fast_reconnect_min = f;
}

spamstate_t
spam_step_grey_mail(uint64_t id, struct mailaddr *addr)
{
  char *buf = NULL;
  int ret;
  DB *dbp;
  DBT key, data;
  time_t t;
  spamstate_t chain = SPAM_GOOD;
  spam_session_t *d;

  log_debug("filter-spam: grey: on_connect");

  if ((d = spam_get_session(id)) == NULL)
    /* in theory never happen */
    fatalx("filter-spam: grey: no spam_session_t initialized on MAIL");

  buf = d->addr;

  if ((ret = db_create(&dbp, NULL, 0)) != 0)
  {
    log_warn("filter-spam: grey: unable to create DB object");
    return chain;
  }

	if ((ret = dbp->open(dbp, NULL, greylist_db, NULL, DB_BTREE,
	                     DB_CREATE, 0664)) != 0)
	{
	  log_warn("filter-spam: grey: unable to open greylist DB: %s",
		      greylist_db);
		return chain;
  }

  t = time(&t);

  memset(&key, 0, sizeof(DBT));
  memset(&data, 0, sizeof(DBT));

  key.data = buf;
  key.size = strlen(buf) * sizeof(char);

	ret = dbp->get(dbp, NULL, &key, &data, 0);

	if (ret == 0) /* data found */
  {
    time_t d = *(time_t *)data.data;
    time_t diff = t - d;

    log_debug("filter-spam: grey: found previus entry in grey DB: %s %lu.",
              (char *)key.data, d);

    if (diff < fast_reconnect_min)
    {
      chain = SPAM_NEUTRAL;
      log_warn("filter-spam: grey: greylisting %s: too fast retry (%lus)",
               buf, diff);
    }
    else if (diff > expire_max)
    {
      chain = SPAM_NEUTRAL;
      log_warn("filter-spam: grey: greylisting %s: visit long time ago (%lus)",
               buf, diff);
    }
    else
      chain = SPAM_GOOD;

  }
  else if (ret == DB_NOTFOUND) /* if data not found */
    chain = SPAM_NEUTRAL;

  /* update ts in db */
  data.data = &t;
  data.size = sizeof(time_t);

  if (dbp->put(dbp, NULL, &key, &data, 0) != 0)
    log_warn("filter-spam: grey: unable to save time into greylist DB");

  (void) dbp->close(dbp, 0);
  return chain;
}
