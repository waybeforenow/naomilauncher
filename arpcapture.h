#ifndef ARPCAPTURE_H_
#define ARPCAPTURE_H_

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

// The maximum length in bytes of an ARP packet, and not-coincidentally the
// maximum number of bytes we care about in any given packet.
#define ARP_LENGTH 56

// Ethernet addresses are 6 bytes
#define ETHER_ADDR_LEN 6

// ethernet headers are always exactly 14 bytes
#define SIZE_ETHERNET 14

// Ethernet header
typedef struct {
  u_char ether_dhost[ETHER_ADDR_LEN];  // destination host address
  u_char ether_shost[ETHER_ADDR_LEN];  // source host address
  u_short ether_type;                  // IP? ARP? RARP? etc
} sniff_ethernet;

typedef struct {
  u_short htype;
  u_short ptype;
  u_char hlen;
  u_char plen;
  u_short operation;
  u_char sha[ETHER_ADDR_LEN];
  uint32_t spa;
  u_char dha[ETHER_ADDR_LEN];
  uint32_t dpa;
} sniff_arp;

void packet_handler(u_char *user, const struct pcap_pkthdr *header,
                    const u_char *packet) {
  static int count = 1;  // packet counter

  void (*cb)(uint8_t) = (void (*)(uint8_t))user;

  // declare pointers to packet headers
  const sniff_ethernet *ethernet;  // The ethernet header [1]
  const sniff_arp *arp;            // The ARP payload

  // cast packet data to ethernet header
  ethernet = (sniff_ethernet *)(packet);

  // cast packet payload to arp structure
  arp = (sniff_arp *)(packet + SIZE_ETHERNET);

  puts("Calling the callback");
  cb(0);

  printf(
      "Source HW address: %u\n"
      "Source IP address: %d\n"
      "Destination HW address: %u\n"
      "Destination IP address: %d\n",
      (unsigned int)arp->sha, arp->spa, (unsigned int)arp->dha, arp->dpa);
}

void sniff(const char *dev, void (*cb)(uint8_t)) {
  pcap_t *sniffer;

  char errbuf[1024];
  struct bpf_program fp;  // compiled filter program (expression)
  bpf_u_int32 mask;       // subnet mask
  bpf_u_int32 net;        // ip

  // open capture device
  sniffer = pcap_open_live(dev, ARP_LENGTH, 1, 1000, errbuf);
  if (sniffer == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
  }

  // make sure we're capturing on an Ethernet device [2]
  if (pcap_datalink(sniffer) != DLT_EN10MB) {
    fprintf(stderr, "%s is not an Ethernet\n", dev);
    exit(EXIT_FAILURE);
  }

  char filter_exp[] = "arp";
  // compile the filter expression
  if (pcap_compile(sniffer, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp,
            pcap_geterr(sniffer));
    exit(EXIT_FAILURE);
  }

  // apply the compiled filter
  if (pcap_setfilter(sniffer, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp,
            pcap_geterr(sniffer));
    exit(EXIT_FAILURE);
  }

  pcap_loop(sniffer, 0, packet_handler, (u_char *)cb);
}

#endif  // ARPCAPTURE_H_
