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

// This is an implementation of a *very* simple shell.

#include <ulib.h>

int main() {
  // Allocate a big buffer for the command to be read into.
  char *buf = malloc(4096);
  while (1) {
    // Display the prompt
    printf("user# ");

    // Ask the user for input.
    long len = readline(buf, 4096);

    // If the user didn't type anything, don't try to do anything
    if (len == 0)
      continue;

    // Handle the command, `exit` by breaking from the loop.
    if (strcmp(buf, "exit") == 0) {
      break;
    }

    // Spawn the program (NOT through forking) 
    pid_t pid = spawn(buf, "argument");
    if (pid == -1) {
      // If the spawn command failed, notify the user and continue
      printf("Unknown command: %s\n", buf);
      continue;
    }

    // Wait for the process to exit before we show the prompt again
    wait(pid);
  }

  // Make sure to free the region!
  free(buf);
  return 0;
}
