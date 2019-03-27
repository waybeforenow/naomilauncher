#ifndef TRIFORCETOOLS_H_
#define TRIFORCETOOLS_H_

/*

                                 /\
                                /  \
                               /    \
                              /      \
                             /        \
                            /__________\
                            \__/\______/   /\
                              /  \        /  \
                             /    \      /    \
                            /      \    /      \
                           /        \  /        \
                          /__________\/__________\
                          \__________/\__________/

 _____    _  __                      _   _      _      _ _
|_   _|  (_)/ _|                    | \ | |    | |    | (_)
  | |_ __ _| |_ ___  _ __ ___ ___   |  \| | ___| |_ __| |_ _ __ ___  _ __ ___
  | | '__| |  _/ _ \| '__/ __/ _ \  | . ` |/ _ \ __/ _` | | '_ ` _ \| '_ ` _ \
  | | |  | | || (_) | | | (_|  __/  | |\  |  __/ || (_| | | | | | | | | | | | |
  \_/_|  |_|_| \___/|_|  \___\___|  \_| \_/\___|\__\__,_|_|_| |_| |_|_| |_| |_|
                     _____           _ _
                    |_   _|         | | |
                      | | ___   ___ | | |__   _____  __
                      | |/ _ \ / _ \| | '_ \ / _ \ \/ /
                      | | (_) | (_) | | |_) | (_) >  <
                      \_/\___/ \___/|_|_.__/ \___/_/\_\


                    ~ originally authored by debugmode ~
                     ~ ported from python to C by wbn ~

*/

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define CARP fprintf(stderr, "erroring at %s:%d\n", __FILE__, __LINE__)

int triforcetools_sock_fd_;

// Connect to the NAOMI system. If it fails, let's just not worry about it.
void NAOMI_Connect(const char* ip, uint16_t port) {
  sleep(15);

  struct sockaddr_in dest;
  dest.sin_family = AF_INET;
  dest.sin_port = htons(port);
  dest.sin_addr.s_addr = inet_addr(ip);

  triforcetools_sock_fd_ = socket(AF_INET, SOCK_STREAM, 0);

  int res;
  long arg;
  fd_set myset;
  struct timeval tv;
  int valopt;
  socklen_t lon;
  // set the socket to non-blocking mode, so we can timeout
  if ((arg = fcntl(triforcetools_sock_fd_, F_GETFL, NULL)) < 0) {
    return;
  }
  arg |= O_NONBLOCK;
  if (fcntl(triforcetools_sock_fd_, F_SETFL, arg) < 0) {
    return;
  }
  // Trying to connect with timeout
  res = connect(triforcetools_sock_fd_, (struct sockaddr*)&dest, sizeof(dest));
  if (res < 0) {
    if (errno == EINPROGRESS) {
      do {
        tv.tv_sec = 15;
        tv.tv_usec = 0;
        FD_ZERO(&myset);
        FD_SET(triforcetools_sock_fd_, &myset);
        res = select(triforcetools_sock_fd_ + 1, NULL, &myset, NULL, &tv);
        if (res < 0 && errno != EINTR) {
          CARP;
          return;
        } else if (res > 0) {
          // Socket selected for write
          lon = sizeof(int);
          if (getsockopt(triforcetools_sock_fd_, SOL_SOCKET, SO_ERROR,
                         (void*)(&valopt), &lon) < 0) {
            CARP;
            return;
          }
          // Check the value returned...
          if (valopt) {
            CARP;
            return;
          }
          break;
        } else {
          CARP;
          return;
        }
      } while (1);
    } else {
      CARP;
      return;
    }
  }
  // Set to blocking mode again...
  if ((arg = fcntl(triforcetools_sock_fd_, F_GETFL, NULL)) < 0) {
    CARP;
    return;
  }
  arg &= (~O_NONBLOCK);
  fcntl(triforcetools_sock_fd_, F_SETFL, arg);
}

void NAOMI_Disconnect() { close(triforcetools_sock_fd_); }

void HOST_SetMode(uint16_t v_and, uint16_t v_or) {
  uint16_t payload = (v_and << 8) | v_or;

  char outbox[8] = {0x04,
                    0x00,
                    0x00,
                    0x07,
                    (char)(payload & 0x000000ff),
                    (char)((payload & 0x0000ff00) >> 8),
                    (char)((payload & 0x00ff0000) >> 16),
                    (char)((payload & 0xff000000) >> 24)};

  ssize_t bytes = send(triforcetools_sock_fd_, outbox, 8, 0);
  if (bytes < 0) {
    CARP;
    exit(errno);
  }
}

void SECURITY_SetKeycode(uint64_t payload) {
  char outbox[12] = {0x08, 0x00, 0x00, 0x7f};
  memcpy(outbox + 4, &payload, 8);

  ssize_t bytes = send(triforcetools_sock_fd_, outbox, 12, 0);
  if (bytes < 0) {
    CARP;
    exit(errno);
  }
}

void DIMM_Upload(uint16_t addr, void* payload, size_t size, uint32_t mark) {
  uint32_t first_piece = 0x04800000 | (size + 0xA) | (mark << 16);
  char outbox[14] = {(char)(first_piece & 0x000000ff),
                     (char)((first_piece & 0x0000ff00) >> 8),
                     (char)((first_piece & 0x00ff0000) >> 16),
                     (char)((first_piece & 0xff000000) >> 24),

                     0,
                     0,
                     0,
                     0,

                     (char)(addr & 0x000000ff),
                     (char)((addr & 0x0000ff00) >> 8),
                     (char)((addr & 0x00ff0000) >> 16),
                     (char)((addr & 0xff000000) >> 24),

                     0,
                     0};

  ssize_t bytes = send(triforcetools_sock_fd_, outbox, sizeof(outbox), 0);
  if (bytes < 0) {
    CARP;
    exit(errno);
  }
  bytes = send(triforcetools_sock_fd_, payload, size, 0);
  if (bytes < 0) {
    CARP;
  }
}

void DIMM_UploadFile(char* name) {
  int file = open(name, O_RDONLY);
  char buf[0x8000];
  size_t addr = 0, bytes_read;

  while ((bytes_read = read(file, buf, 0x8000)) > 0) {
    DIMM_Upload(addr, buf, bytes_read, 0);
    addr += bytes_read;
  }

  DIMM_Upload(addr, "12345678", 8, 1);

  close(file);
}

void HOST_Restart() {
  char outbox[4] = {0x00, 0x00, 0x00, 0x0a};

  ssize_t bytes = send(triforcetools_sock_fd_, outbox, 4, 0);
  if (bytes < 0) {
    CARP;
    exit(errno);
  }
}

void TIME_SetLimit(uint32_t data) {
  char outbox[8] = {0x04,
                    0x00,
                    0x00,
                    0x17,
                    (char)(data & 0x000000ff),
                    (char)((data & 0x0000ff00) >> 8),
                    (char)((data & 0x00ff0000) >> 16),
                    (char)((data & 0xff000000) >> 24)};

  ssize_t bytes = send(triforcetools_sock_fd_, outbox, 4, 0);
  if (bytes < 0) {
    CARP;
    exit(errno);
  }
}

#endif  // TRIFORCETOOLS_H_
/*
import struct, sys
import socket
import time
from Adafruit_CharLCDPlate import Adafruit_CharLCDPlate

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def connect(ip, port):
        global s
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))


#a function to receive a number of bytes with hard blocking
def readsocket(n):
        res = ""
        while len(res) < n:
                res += s.recv(n - len(res))
        return res

#Peeks 16 bytes from Host(gamecube) memory
def HOST_Read16(addr):
        s.send(struct.pack("<II", 0xf0000004, addr))
        data = readsocket(0x20)
        res = ""
        for d in xrange(0x10):
                res += data[4 + (d ^ 3)]
        return res

#same, but 4 bytes.
def HOST_Read4(addr, type = 0):
        s.send(struct.pack("<III", 0x10000008, addr, type))
        return s.recv(0xc)[8:]

def HOST_Poke4(addr, data):
        s.send(struct.pack("<IIII", 0x1100000C, addr, 0, data))

def HOST_Restart():
        s.send(struct.pack("<I", 0x0A000000))

#Read a number of bytes(up to 32k) from DIMM memory(i.e.where the game is) \
    .Probably doesn't work for NAND-based games.
def DIMM_Read(addr, size):
        s.send(struct.pack("<III", 0x05000008, addr, size))
        return readsocket(size + 0xE)[0xE:]

def DIMM_GetInformation():
        s.send(struct.pack("<I", 0x18000000))
        return readsocket(0x10)

def DIMM_SetInformation(crc, length):
        s.send(struct.pack("<IIII", 0x1900000C, crc & 0xFFFFFFFF, length, 0))

def DIMM_Upload(addr, data, mark):
        s.send(struct.pack("<IIIH", 0x04800000 | (len(data) + 0xA) | (mark <<
16), 0, addr, 0) + data)

def NETFIRM_GetInformation():
        s.send(struct.pack("<I", 0x1e000000))
        return s.recv(0x404)

def CONTROL_Read(addr):
        s.send(struct.pack("<II", 0xf2000004, addr))
        return s.recv(0xC)


def DIMM_SetMode(v_and, v_or):
        s.send(struct.pack("<II", 0x08000004, (v_and << 8) | v_or))
        return readsocket(0x8)

def DIMM22(data):
        assert len(data) >= 8
        s.send(struct.pack("<I", 0x22000000 | len(data)) + data)

def MEDIA_SetInformation(data):
        assert len(data) >= 8
        s.send(struct.pack("<I",	0x25000000 | len(data)) + data)

def MEDIA_Format(data):
        s.send(struct.pack("<II", 0x21000004, data))


def DIMM_DumpToFile(file):
        for x in xrange(0, 0x20000, 1):
                file.write(DIMM_Read(x * 0x8000, 0x8000))
                sys.stderr.write("%08x\r" % x)

def HOST_DumpToFile(file, addr, len):
        for x in range(addr, addr + len, 0x10):
#if not(x & 0xFFF) :
                sys.stderr.write("%08x\r" % x)
                file.write(HOST_Read16(x))

#upload a file into DIMM memory, and optionally encrypt for the given key.
#note that the re - encryption is obsoleted by just setting a zero - key, which
#is a magic to disable the decryption.
def DIMM_UploadFile(name, key = None):
        import zlib
        crc = 0
        a = open(name, "rb")
        addr = 0
        if key:
                d = DES.new(key[::-1], DES.MODE_ECB)
        while True:
                sys.stderr.write("%08x\r" % addr)
                data = a.read(0x8000)
                if not len(data):
                        break
                if key:
                        data = d.encrypt(data[::-1])[::-1]
                DIMM_Upload(addr, data, 0)
                crc = zlib.crc32(data, crc)
                addr += len(data)
        crc = ~crc
        DIMM_Upload(addr, "12345678", 1)
        DIMM_SetInformation(crc, addr)

#obsolete
def PATCH_MakeProgressCode(x):
#addr = 0x80066ed8 #2.03
#addr = 0x8005a9c0 #1.07
#addr = 0x80068304 #2.15
        addr = 0x80068e0c # 3.01
        HOST_Poke4(addr + 0, 0x4e800020)
        HOST_Poke4(addr + 4, 0x38a00000 | x)
        HOST_Poke4(addr + 8, 0x90a30000)
        HOST_Poke4(addr + 12, 0x38a00000)
        HOST_Poke4(addr + 16, 0x60000000)
        HOST_Poke4(addr + 20, 0x4e800020)
        HOST_Poke4(addr + 0, 0x60000000)

#obsolete
def PATCH_MakeContentError(x):
#addr = 0x80066b30 #2.03
#addr = 0x8005a72c #1.07
#addr = 0x80067f5c #2.15
        addr = 0x8005a72c # 3.01
        HOST_Poke4(addr + 0, 0x4e800020)
        HOST_Poke4(addr + 4, 0x38a00000 | x)
        HOST_Poke4(addr + 8, 0x90a30000)
        HOST_Poke4(addr + 12, 0x38a00000)
        HOST_Poke4(addr + 16, 0x60000000)
        HOST_Poke4(addr + 20, 0x4e800020)
        HOST_Poke4(addr + 0, 0x60000000)

#this essentially removes a region check, and is triforce - specific; It's also
segaboot-version specific.
#- look for string : "CLogo::CheckBootId: skipped."
#- binary - search for lower 16bit of address
def PATCH_CheckBootID():

# 3.01
        addr = 0x8000dc5c
        HOST_Poke4(addr + 0, 0x4800001C)
        return

        addr = 0x8000CC6C # 2.03, 2.15
#addr = 0x8000d8a0 #1.07
        HOST_Poke4(addr + 0, 0x4e800020)
        HOST_Poke4(addr + 4, 0x38600000)
        HOST_Poke4(addr + 8, 0x4e800020)
        HOST_Poke4(addr + 0, 0x60000000)
*/

