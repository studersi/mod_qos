/*
 * $Header$
 *
 * send gratuitous arp
 */

#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void atoip(const char *s, struct in_addr *i) {
  struct hostent *h;
  i->s_addr = inet_addr(s);
  if (i->s_addr == -1) {
    if ((h = gethostbyname(s))) {
      memcpy(i, h->h_addr, sizeof(i));
    } else {
      error(1, 0, "unknown host '%s'", s);
    }
  }
}

void atohw(const char *s, u_int8_t *h) {
  char a, b, i;

  for (a = b = i = 0; i < ETH_ALEN; i++, h++) {
    if (!(a = tolower(*s++)) || !(b = tolower(*s++)))
      error(1, 0, "invalid hardware address length");

    if (isdigit(a))
      *h = (a - '0') << 4;
    else if (a >= 'a' && a <= 'f')
      *h = (a - 'a' + 10) << 4;
    else
      error(1, 0, "invalid digit in hardware address");

    if (isdigit(b))
      *h |= b - '0';
    else if (b >= 'a' && b <= 'f')
      *h |= b - 'a' + 10;
    else
      error(1, 0, "invalid digit in hardware address");

    if (*s == ':')
      s++;
  }
}

void usage(char *progname) {
  fprintf(stderr, "Usage: %s <interface> <src ip> <src mac>\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "Example:\n");
  fprintf(stderr, " %s eth1 192.168.23.12 0b:ef:e6:47:ae:a7\n", progname);
  fprintf(stderr, "\n");
  exit(1);
}

int main(int argc, char **argv) {
  int i = 0, opt, s;
  struct ifreq ifr;
  struct sockaddr_ll sa;
  char *progname = argv[0];
  struct {
    struct ether_header eh;
    struct arphdr ah;
    u_int8_t ar_sha[ETH_ALEN];
    struct in_addr ar_sip;
    u_int8_t ar_tha[ETH_ALEN];
    struct in_addr ar_tip;
    u_int8_t padding[18];
  } arp;

  if(argc < 4) {
    usage(progname);
  }

  atoip(argv[2], &arp.ar_sip);
  atohw(argv[3], arp.eh.ether_shost);
  atohw(argv[3], arp.ar_sha);

  atoip(argv[2], &arp.ar_tip);
  atohw("ff:ff:ff:ff:ff:ff", arp.eh.ether_dhost);
  atohw("ff:ff:ff:ff:ff:ff", arp.ar_tha);

  arp.eh.ether_type = htons(ETHERTYPE_ARP);
  arp.ah.ar_hrd = htons(ARPHRD_ETHER);
  arp.ah.ar_pro = htons(ETHERTYPE_IP);
  arp.ah.ar_hln = ETH_ALEN;
  arp.ah.ar_pln = sizeof(struct in_addr);
  arp.ah.ar_op = htons(ARPOP_REPLY);
  memset(&arp.padding, 0, sizeof(arp.padding));

  s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_RARP));
  if (s < 0)
    error(1, errno, "socket");

  strncpy (ifr.ifr_name, argv[1], IFNAMSIZ);
  if(ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
    error(1, errno, "ioctl SIOCGIFINDEX");
  }

  sa.sll_family = AF_PACKET;
  sa.sll_ifindex = ifr.ifr_ifindex;
  sa.sll_halen = ETH_ALEN;

  if(sendto(s, &arp, sizeof(arp), 0, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
    error(1, errno, "sendto");
  }

  return 0;
}
