#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "arpcapture.h"
#include "triforcetools.h"

#define TIME_QUANTUM 300

const char default_dev[] = "eth0";
const char ip[] = "10.7.0.3";
const uint16_t port = 10703;
uint64_t curtime = 0;

/* Since multiple ARP requests may come in in succession, only respond to one
 * request every TIME_QUANTUM seconds. */
void dedupe_arp() {
  if (time(NULL) - curtime < TIME_QUANTUM) {
    return;
  }

  sleep(15);
  curtime = time(NULL);
}

void upload_rom(uint8_t selection) {
  dedupe_arp();

  NAOMI_Connect(ip, port);
  HOST_SetMode(0, 1);
  SECURITY_SetKeycode(0);
  DIMM_UploadFile("/boot/naomiboot.bin");
  HOST_Restart();
  TIME_SetLimit(10 * 60 * 1000);
  NAOMI_Disconnect();
}

int main(int argc, char** argv) {
  const char* dev = default_dev;
  if (argc > 1) {
    dev = argv[1];
  }

  sniff(dev, &upload_rom);
  return 0;
}
