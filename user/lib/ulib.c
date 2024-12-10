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

#include "./liballoc.h"
#include <ulib.h>

extern void main(const char *cmd, const char *arg);

// This function is the entrypoint to the userspace binary
__attribute__((section(".init"), noinline)) void start(const char *cmd,
                                                       const char *arg) {
  main(cmd, arg);
  exit();
  while (1) {
    // no return
  }
}

// The syscalls
void exit(void) { syscall0(SYSCALL_EXIT); }
int getc() { return syscall1(SYSCALL_GETC, 1); }

// read a line into dst, with a maximum size of `len`
long readline(char *dst, long len) {
  long i;
  bool echo;
  bool save;

  for (i = 0; i < len - 1; i++) {
    int c = getc();
    echo = true;
    save = false;
    if (c == '\n') {
      break;
    } else if (c == 0x08) {
      if (i != 0) {
        echo = true;
        save = false;
        dst[--i] = '\0'; // delete the previous char
      } else {
        echo = false;
        save = false;
      }
      i--; // make sure the i++ in the for loop doesn't do anything
    } else {
      echo = true;
      save = true;
    }

    if (save)
      dst[i] = c;
    if (echo)
      putc(c);
  }

  // null terminate the output
  dst[i] = '\0';
  // make go to the next line (we don't echo \n input)
  putc('\n');

  return i;
}

// ----------------------------------------------------
int strcmp(const char *l, const char *r) {
  for (; *l == *r && *l; l++, r++)
    ;
  return *(unsigned char *)l - *(unsigned char *)r;
}

long strlen(const char *s) {
  long len = 0;
  for (len = 0; s[len]; len++) {
    // ...
  }
  return len;
}

void *memset(void *x, unsigned char value, unsigned long length) {
  unsigned char *xs = x;
  for (unsigned long i = 0; i < length; i++) {
    xs[i] = value;
  }
  return x;
}

typedef __builtin_va_list va_list;
#define va_start(ap, param) __builtin_va_start(ap, param)
#define va_end(ap) __builtin_va_end(ap)
#define va_arg(ap, type) __builtin_va_arg(ap, type)

static void printint(long xx, int base, int sgn) {
  static char digits[] = "0123456789abcdef";
  char buf[16];
  int i, neg;
  uint64_t x;

  neg = 0;
  if (sgn && xx < 0) {
    neg = 1;
    x = -xx;
  } else {
    x = xx;
  }

  i = 0;
  do {
    buf[i++] = digits[x % base];
  } while ((x /= base) != 0);
  if (neg)
    buf[i++] = '-';

  while (--i >= 0)
    putc(buf[i]);
}

// A simple printf. Only understands %d, %x, %p, %s.
void printf(char *fmt, ...) {
  va_list ap;
  char *s;
  uint64_t c, i, state;
  va_start(ap, fmt);

  state = 0;
  for (i = 0; fmt[i]; i++) {
    c = fmt[i] & 0xff;
    if (state == 0) {
      if (c == '%') {
        state = '%';
      } else {
        putc(c);
      }
    } else if (state == '%') {
      if (c == 'd') {
        printint(va_arg(ap, uint64_t), 10, 1);
      } else if (c == 'x' || c == 'p') {
        printint(va_arg(ap, uint64_t), 16, 0);
      } else if (c == 's') {
        s = va_arg(ap, char *);
        if (s == 0)
          s = "(null)";
        while (*s != 0) {
          putc(*s);
          s++;
        }
      } else if (c == 'c') {
        putc(va_arg(ap, uint64_t));
      } else if (c == '%') {
        putc(c);
      } else {
        // Unknown % sequence.  Print it to draw attention.
        putc('%');
        putc(c);
      }
      state = 0;
    }
  }
}

// Simply write a single byte to the console
void putc(char c) { syscall1(SYSCALL_PUTC, c); }
void conwrite(void *buf, long len) {
  for (int i = 0; i < len; i++)
    putc(((char *)buf)[i]);
}

void puts(const char *s) { conwrite((void *)s, strlen(s)); }

pid_t spawn(const char *program, const char *argument) {
  return (pid_t)syscall2(SYSCALL_SPAWN, program, argument);
}

int wait(pid_t pid) { return (int)syscall1(SYSCALL_WAIT, pid); }

void *valloc(unsigned npages) {
  return (void *)syscall1(SYSCALL_VALLOC, npages);
}

// Utility functions for the allocator.
int liballoc_lock() {
  // TODO
  return 0;
}

int liballoc_unlock() {
  // TODO
  return 0;
}

/** This is the hook into the local system which allocates pages. It
 * accepts an integer parameter which is the number of pages
 * required.  The page size was set up in the liballoc_init function.
 *
 * \return NULL if the pages were not allocated.
 * \return A pointer to the allocated memory.
 */
void *liballoc_alloc(size_t npages) { return valloc(npages); }

/** This frees previously allocated memory. The void* parameter passed
 * to the function is the exact same value returned from a previous
 * liballoc_alloc call.
 *
 * The integer value is the number of pages to free.
 *
 * \return 0 if the memory was successfully freed.
 */
int liballoc_free(void *ptr, size_t pages) {
  // TODO:
  return 0;
}

int open(const char *filename, int flags) {
  return syscall2(SYSCALL_OPEN, filename, flags);
}
void close(int fd) { syscall1(SYSCALL_CLOSE, fd); }
long read(int fd, void *buf, long size) {
  return syscall3(SYSCALL_READ, fd, buf, size);
}
long write(int fd, void *buf, long size) {
  return syscall3(SYSCALL_WRITE, fd, buf, size);
}

// If pending_signal -> iretq takes us to signal_handler
void signal(void *signal_handler) { syscall1(SYSCALL_SIGNAL, signal_handler); }