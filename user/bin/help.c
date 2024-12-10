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

#include <ulib.h>

// This is a simple program which prints help messages

int main() {
  printf("Welcome to the Nautilus userspace! Here are some commands:\n");
  printf(" - exit: exit the shell.\n");
  printf(" - hello: print 'hello world'\n");
  printf(" - ls: list files in the local directory\n");
  printf(" - hack: tests some security features of the aspace implementation\n");
  printf("   This userspace is *NOT* secure, and has many vulnerabilities.\n");
  return 0;
}
