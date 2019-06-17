#ifndef _LIBNETLINK_SLANK_H_
#define _LIBNETLINK_SLANK_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

typedef struct {
  uint16_t magic;
  uint16_t lladdr;
  uint16_t dum1[2];
  uint16_t dum2[2];
  uint16_t dum3;
  uint16_t family;
} nl_cooked_hdr_t;

typedef struct {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
} pcap_pkt_hdr_t;

typedef struct {
  uint32_t magic_number;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t  thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
} pcap_file_hdr_t;

static void write_rtnl_pcap(struct nlmsghdr *n, const char *filename)
{
  FILE *fp = fopen(filename, "w");
  if (!fp)
    abort();

  pcap_file_hdr_t hdr;
  memset(&hdr, 0x0, sizeof(hdr));
  hdr.magic_number = 0xa1b2c3d4;
  hdr.version_major = 0x0002;
  hdr.version_minor = 0x0004;
  hdr.thiszone = 0x0;
  hdr.sigfigs = 0x0;
  hdr.snaplen = 0x00040000;
  hdr.network = 0xfd;
  fwrite(&hdr, sizeof(hdr), 1, fp);

  pcap_pkt_hdr_t pp;
  memset(&pp, 0x0, sizeof(pp));
  pp.ts_sec = 0;
  pp.ts_usec = 0;
  pp.incl_len = sizeof(nl_cooked_hdr_t) + n->nlmsg_len;
  pp.orig_len = sizeof(nl_cooked_hdr_t) + n->nlmsg_len;
  fwrite(&pp, sizeof(pp), 1, fp);

  nl_cooked_hdr_t ph;
  memset(&ph, 0x0, sizeof(ph));
  ph.magic = 0x0400;
  ph.lladdr = 0x3803;
  ph.family = 0x0000;
  fwrite(&ph, sizeof(ph), 1, fp);

  fwrite(n, n->nlmsg_len, 1, fp);

  fclose(fp);
}

#endif /* _LIBNETLINK_SLANK_H_ */
