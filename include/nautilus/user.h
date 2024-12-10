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
#ifndef __NK_USER_H__
#define __NK_USER_H__

#include "./uapi.h"
#include <nautilus/thread.h>



// An internal representation for a userspace trap frame.
// This is used when handling system calls, and lives on the kernel interrupt stack.
struct user_frame {
  uint64_t r15;
  uint64_t r14;
  uint64_t r13;
  uint64_t r12;
  uint64_t r11;
  uint64_t r10;
  uint64_t r9;
  uint64_t r8;
  uint64_t rbp;
  uint64_t rdi;
  uint64_t rsi;
  uint64_t rdx;
  uint64_t rcx;
  uint64_t rbx;
  uint64_t rax;

  uint64_t trapno;
  uint64_t err;

  uint64_t rip;
  uint64_t cs;
  uint64_t rflags;
  uint64_t rsp;
  uint64_t ss;
} __packed;

/**
 * This file is the main implementation of the nautilus kernel simple userspace
 * system.
 */

#define SEG_KCODE 1 // kernel code
#define SEG_KDATA 2 // kernel data+stack
#define SEG_KCPU 3  // kernel per-cpu data
#define SEG_UCODE 4 // user code
#define SEG_UDATA 5 // user data+stack
#define SEG_TSS 6   // this process's task state

#define PROCESS_FD_TABLE_SIZE 64
// A nautilus user process
typedef struct nk_process {

	// processes in nautilus get a unique pid, which
	// is entirely unrelated to the threads that are run under it
	int pid;
  
  // A lock for the fields of this structure
  spinlock_t process_lock;

	// Address space of the process
	// The API for this is implemented in src/user/process.c
	// In nautilus, this is the 
	nk_aspace_t *aspace;

	// The main thread of the process.
	// TODO: allow multiple threads to be in a process at once
  nk_thread_id_t main_thread;

	// The name of the program being run
	// (the name of the binary loaded from the disk)
	char program[255];

	// The argument passed to exit(exit_code)
	int exit_code;

	// for system-wide process list
	struct list_head ptable_list_node;

  // the next location to palloc to.
  off_t next_palloc;

  // Simply a bunch of open files. All initialized to FS_BAD_FD
  nk_fs_fd_t open_files[PROCESS_FD_TABLE_SIZE];

  // Super basic: just indicate whether there is a signal or not
  // No different types of signals yet
  bool_t pending_signal;

  // Signal Handler for the process
  void * signal_handler;

	// TODO: More state :)
} nk_process_t;


// Where user programs are loaded. In nautilus, we expect the kernel
// be 1:1 mapped virtually and physically. As a result, we must map
// the userspace program to the high half, and the kernel to the low
// half. This is the inverse of a regular kernel, but it doesn't
// really matter which order we use :)
#define USER_ASPACE_START ((void *) 0xffff800000000000UL)

extern nk_process_t *get_cur_process(void);

// this creates a new process, and starts running it immediately.
extern nk_process_t *nk_process_spawn(const char *program, const char *argument);
// wait for a process's main thread to exit, and return the exit code
extern int nk_process_wait(nk_process_t *process);
// given a pid, get the process structure
extern nk_process_t *nk_process_get(int pid);
extern nk_process_t *nk_get_current_process(void);
unsigned long process_dispatch_syscall(nk_process_t *proc, int nr, uint64_t a, uint64_t b, uint64_t c);
extern void nk_user_init(void);
// handle signals
extern void nk_ret_to_user(struct user_frame *frame_ptr);
// Set the `signal pending` bit in the current process. If that wasn't successful,
// this function will return -1 to indicate failure.
extern int set_pending_signal(void);

static inline int nk_thread_is_user_thread(nk_thread_t *thread) {
  // A thread is a userspace thread if the process field is non-null
  return thread->process != NULL;
}

#endif
