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

#ifndef __NAUTILUS_KERNEL_UAPI__
#define __NAUTILUS_KERNEL_UAPI__

#define SYSCALL_EXIT 0
#define SYSCALL_PUTC 1
#define SYSCALL_GETC 2
#define SYSCALL_SPAWN 3
#define SYSCALL_WAIT 4
#define SYSCALL_VALLOC 5 // Allocate some pages
#define SYSCALL_VFREE 6  // free some pages
#define SYSCALL_YIELD 7  // yield the thread
#define SYSCALL_OPEN 8   // open a file
#define SYSCALL_CLOSE 9  // close a file
#define SYSCALL_READ 10
#define SYSCALL_WRITE 11
#define SYSCALL_SIGNAL 12 // register signal handler
#define SYSCALL_LS 13     // list files in a directory

#endif
