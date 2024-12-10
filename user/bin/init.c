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

int main(char *argument) {
  printf("Hello from userspace!\n");

  // If this were a more complex userspace, we'd read some kind of runtime
  // configuration file which would startup all the daemons required for a
  // user to hapilly use the system (networking, user interface, sound, etc)
  // But since this is a minimal environment, we'll just start a shell
  printf("[init] starting shell (/sh). Run the `help` program for help\n");
  pid_t pid = spawn("/sh", "");
  wait(pid);
  return 0;
}