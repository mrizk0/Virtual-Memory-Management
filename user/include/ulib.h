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

#pragma once

#ifndef __NAUTILUS_ULIB__
#define __NAUTILUS_ULIB__

#include "../../include/nautilus/uapi.h"

// This header file contains the full system interface for the Nautilus
// userspace interface. Note: it is not meant to mirror how POSIX works, as that
// would be difficult :). At most, you can print to the console, spawn a new
// program, and exit the current program.

// first, some typedefs
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;
typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned long uintptr_t;

typedef int int32_t;
typedef long int64_t;
typedef long pid_t;
typedef unsigned char bool;


#define true ((bool)1)
#define false ((bool)0)
#define NULL ((void*)0)
// Exit the program
extern void exit(void);

extern int strcmp(const char *l, const char *r);
extern long strlen(const char *s);
extern void printf(char *fmt, ...);
extern void puts(const char *s);
extern void putc(char c);
extern int getc(void); // get a character from the console.
extern void conwrite(void *buf, long len); // write to the console
extern long readline(char *dst, long len);
extern void *memset(void *x, unsigned char value, unsigned long length);

// allocate `page_count` pages of virtual memory to the process.
extern void *valloc(unsigned page_count);

#define O_RDONLY 1
#define O_WRONLY 2
#define O_RDWR   3 // OR of RD and WR ONLY
#define O_APPEND 4
#define O_CREAT  8
#define O_TRUNC  16 // guess
// File abstractions
extern int open(const char *filename, int flags);
extern void close(int fd);
extern long read(int fd, void *buf, long size);
extern long write(int fd, void *buf, long size);

// Spawning a userspace program in Nautilus requires the user pass in the path
// to the binary (absolute path) and the argument. Note there is not an array of
// argv. Every program takes one and only string as argument to simplify the
// interface
extern pid_t spawn(const char *program, const char *argument);
extern int wait(pid_t pid /* TODO: return value? */);


extern void *malloc(size_t);
extern void *realloc(void *, size_t);
extern void *calloc(size_t, size_t);
extern void free(void *);

// These macros declare interfaces to make systemcalls to the kernel. There are
// 4 of them to allow you to invoke a systemcall `nr` up to three arguments,
// `a,b,c`.
#define syscall0(nr)                                                           \
  ({                                                                           \
    unsigned long ret;                                                         \
    asm volatile("int $0x80" : "=a"(ret) : "0"(nr) : "memory");                \
    ret;                                                                       \
  });

#define syscall1(nr, a)                                                        \
  ({                                                                           \
    unsigned long ret;                                                         \
    asm volatile("int $0x80" : "=a"(ret) : "0"(nr), "D"(a) : "memory");        \
    ret;                                                                       \
  });

#define syscall2(nr, a, b)                                                     \
  ({                                                                           \
    unsigned long ret;                                                         \
    asm volatile("int $0x80"                                                   \
                 : "=a"(ret)                                                   \
                 : "0"(nr), "D"(a), "S"(b)                                     \
                 : "memory");                                                  \
    ret;                                                                       \
  });

#define syscall3(nr, a, b, c)                                                  \
  ({                                                                           \
    unsigned long ret;                                                         \
    asm volatile("int $0x80"                                                   \
                 : "=a"(ret)                                                   \
                 : "0"(nr), "D"(a), "S"(b), "d"(c)                             \
                 : "memory");                                                  \
    ret;                                                                       \
  });

#endif

// Userspace processes can register signal handlers w/ this
// Right now, no way to specify diff types of signals.
void signal(void * signal_handler);