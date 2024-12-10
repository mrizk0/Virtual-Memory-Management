/*
 * This file is part of the Nautilus AeroKernel developed
 * by the Hobbes and V3VEE Projects with funding from the
 * United States National  Science Foundation and the Department of Energy.
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  The Hobbes Project is a collaboration
 * led by Sandia National Laboratories that includes several national
 * laboratories and universities. You can find out more at:
 * http://www.v3vee.org  and
 * http://xstack.sandia.gov/hobbes
 *
 * Copyright (c) 2023, Nick Wanninger <ncw@u.northwestern.edu>
 * Copyright (c) 2015, The V3VEE Project  <http://www.v3vee.org>
 *                     The Hobbes Project <http://xstack.sandia.gov/hobbes>
 * All rights reserved.
 *
 * Author: Nick Wanninger <ncw@u.northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "LICENSE.txt".
 */

// The main purpose of this program is to show how you must be careful when
// accessing pointers in the kernel that the user gave to you. It also tests
// that memory allocated by the kernel is zeroed. If it isn't we could be
// leaking data from other programs! In a real kernel environment, that data
// might be passwords or encryption keys!

#include <ulib.h>

// this is a simple hexdump implementation
void hexdump(void *vbuf, long len) {
  unsigned char *buf = vbuf;
  int w = 16;
  for (int i = 0; i < len; i += w) {
    unsigned char *line = buf + i;
    // printf("%p: ", (void *)(long)i);
    for (int c = 0; c < w; c++) {
      if (i + c >= len) {
        printf("   ");
      } else {
        printf("%x%x ", (line[c] & 0xF0) >> 4, line[c] & 0x0F);
      }
    }
    printf(" |");
    for (int c = 0; c < w; c++) {
      if (i + c >= len) {
      } else {
        printf("%c", (line[c] < 0x20) || (line[c] > 0x7e) ? '.' : line[c]);
      }
    }
    printf("|\n");
  }
}

// The kernel lives at 1MB
void *kernel_memory = (void*)0x100000UL;

void my_signal_handler(void) {
  printf("Hit signal handler due to permission denial\n");
  exit();
  // This function cannot return!
}

int main() {
  // configure a signal handler (the only signal is segfault, so there isn't a distinction)
  signal((void*)my_signal_handler);

  printf("I'm going to allocate some memory and print it out\n");
  printf("It better be all zeroes! Otherwise the paging impl has leaked info!\n");
  // allocate a page
  void *x = valloc(1);
  hexdump(x, 64); // hexdump some bytes
  printf("Now, I'm gonna try and wipe the kernel memory!\n");

  // zero 1 MB of memory in the kernel!
  memset(kernel_memory, 0, 0x100000);

  printf("Wow, that actually worked! (it shouldn't have...)\n");
  return 0;
}
