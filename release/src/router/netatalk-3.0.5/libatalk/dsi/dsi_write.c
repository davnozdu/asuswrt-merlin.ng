/*
 *
 * Copyright (c) 1997 Adrian Sun (asun@zoology.washington.edu)
 * All rights reserved. See COPYRIGHT.
 *
 * 7 Oct 1997 added checks for 0 data.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

/* this streams writes */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <string.h>

#include <atalk/dsi.h>
#include <atalk/util.h>
#include <atalk/logger.h>

/* initialize relevant things for dsi_write. this returns the amount
 * of data in the data buffer. the interface has been reworked to allow
 * for arbitrary buffers. */
size_t dsi_writeinit(DSI *dsi, void *buf, const size_t buflen)
{
  size_t header = ntohl(dsi->header.dsi_data.dsi_doff);
  size_t total = ntohl(dsi->header.dsi_len);

  dsi->datasize = 0;
  dsi->writebuf_offset = dsi->writebuf_len = 0;

  /* Reaper R01 / CVE-2022-43634: validate before subtraction or pointer
   * arithmetic. 3.0.5 pre-reads cmdlen bytes into commands, unlike the newer
   * upstream implementation. An invalid offset must not wrap a length or
   * turn a partial command into a read outside that received data. As in
   * dsi_opensession(), reject only the malformed client's session. */
  if (dsi->cmdlen > dsi->server_quantum || dsi->cmdlen > total ||
      header > total || header > dsi->cmdlen) {
      LOG(log_error, logtype_dsi, "dsi_writeinit: invalid write lengths");
      exit(EXITERR_CLNT);
  }

  /* Preserve the existing no-data convention for a zero data offset. */
  if (!header)
      return 0;

  dsi->datasize = total - header;
  dsi->writebuf_offset = header;
  dsi->writebuf_len = dsi->cmdlen - header;

  /* Deliver at most buflen; leave remaining buffered bytes for dsi_write().
   * Merely clipping memmove while consuming the old length would silently
   * lose data and put subsequent streamed reads at the wrong position. */
  return dsi_write(dsi, buf, buflen);
}

/* fill up buf and then return. this should be called repeatedly
 * until all the data has been read. i block alarm processing 
 * during the transfer to avoid sending unnecessary tickles. */
size_t dsi_write(DSI *dsi, void *buf, const size_t buflen)
{
  size_t length;

  LOG(log_maxdebug, logtype_dsi, "dsi_write: remaining DSI datasize: %jd", (intmax_t)dsi->datasize);

  if ((length = MIN(buflen, dsi->datasize)) > 0) {
      if (dsi->writebuf_len > 0) {
          length = MIN(length, dsi->writebuf_len);
          /* The file-write caller uses commands itself as its destination;
           * memmove preserves that existing overlapping-buffer contract. */
          memmove(buf, dsi->commands + dsi->writebuf_offset, length);
          dsi->writebuf_offset += length;
          dsi->writebuf_len -= length;
          dsi->datasize -= length;
          return length;
      }
      if ((length = dsi_stream_read(dsi, buf, length)) > 0) {
          LOG(log_maxdebug, logtype_dsi, "dsi_write: received: %ju", (intmax_t)length);
          dsi->datasize -= length;
          return length;
      }
  }
  return 0;
}

/* flush any unread buffers. */
void dsi_writeflush(DSI *dsi)
{
  size_t length;

  /* These bytes have already left the socket. Discard them locally before
   * draining the rest, otherwise flushing would consume the next request. */
  dsi->datasize -= dsi->writebuf_len;
  dsi->writebuf_offset = dsi->writebuf_len = 0;

  while (dsi->datasize > 0) { 
    length = dsi_stream_read(dsi, dsi->data,
			     MIN(sizeof(dsi->data), dsi->datasize));
    if (length > 0)
      dsi->datasize -= length;
    else
      break;
  }
}
