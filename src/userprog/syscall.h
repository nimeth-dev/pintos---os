#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

/* Global lock for synchronizing all file system operations across threads. */
extern struct lock filesys_lock;

void syscall_init (void);
void sys_exit (int status);

#endif 
