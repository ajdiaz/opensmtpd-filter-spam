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

#include "pause.h"

static unsigned int pause_seconds = 5;


void pause_setconf(unsigned int t)
{
  pause_seconds = t;
}

spamstate_t
spam_step_pause(uint64_t id, struct filter_connect *conn)
{
  unsigned int r;

  /* Pausing connection */
  log_debug("debug: filter-spam: sleeping %u", pause_seconds);

  if ((r = sleep(pause_seconds)) != 0)
  {
    log_warnx("filter-pause: wakeup %u seconds too early", r);
    return SPAM_BAD;
  }

  return SPAM_NEUTRAL;
}
