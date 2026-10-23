#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);
static void check_user_ptr (const void *vaddr);
static void check_user_buffer (const void *buffer, unsigned size);
static void check_user_string (const char *str);
static struct file_descriptor *get_open_file (int fd);
void sys_exit (int status);

void
syscall_init (void) 
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Validates that a user virtual address is safe to access. */
static void
check_user_ptr (const void *vaddr)
{
  if (vaddr == NULL || !is_user_vaddr (vaddr) ||
      pagedir_get_page (thread_current ()->pagedir, vaddr) == NULL)
    {
      sys_exit (-1);
    }
}

/* Validates that a contiguous buffer in user memory is safe to access. */
static void
check_user_buffer (const void *buffer, unsigned size)
{
  const char *buf = (const char *) buffer;
  for (unsigned i = 0; i < size; i++)
    {
      check_user_ptr (buf + i);
    }
}

/* Validates a string pointer in user memory byte-by-byte up to the null terminator.
   Kills the process with -1 if any byte points to unmapped or kernel memory. */
static void
check_user_string (const char *str)
{
  check_user_ptr (str);
  for (const char *p = str; ; p++)
    {
      check_user_ptr (p);
      if (*p == '\0')
        break;
    }
}

/* Looks up an open file descriptor in the current process by its number.
   Returns NULL if the fd is invalid or doesn't belong to this process. */
static struct file_descriptor *
get_open_file (int fd)
{
  if (fd < 2)
    return NULL;

  struct thread *cur = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&cur->fd_list); e != list_end (&cur->fd_list); e = list_next (e))
    {
      struct file_descriptor *desc = list_entry (e, struct file_descriptor, elem);
      if (desc->fd == fd)
        return desc;
    }
  return NULL;
}

/* Terminates the current process, prints the required exit message,
   and exits the thread. */
void
sys_exit (int status)
{
  struct thread *cur = thread_current ();
  if (cur->my_child_info != NULL)
    cur->my_child_info->exit_status = status;
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit ();
}

static void
syscall_handler (struct intr_frame *f) 
{
  /* Validate pointer to system call number on user stack */
  check_user_buffer (f->esp, sizeof (int));

  int syscall_num = *(int *) f->esp;

  switch (syscall_num)
    {
    case SYS_HALT:
      shutdown_power_off ();
      break;

    case SYS_EXIT:
      {
        check_user_buffer (f->esp + 4, sizeof (int));
        int status = *(int *) (f->esp + 4);
        sys_exit (status);
        break;
      }

    case SYS_EXEC:
      {
        check_user_buffer (f->esp + 4, sizeof (char *));
        const char *cmd_line = *(const char **) (f->esp + 4);
        check_user_string (cmd_line);
        f->eax = process_execute (cmd_line);
        break;
      }

    case SYS_WAIT:
      {
        check_user_buffer (f->esp + 4, sizeof (tid_t));
        tid_t child_tid = *(tid_t *) (f->esp + 4);
        f->eax = process_wait (child_tid);
        break;
      }

    case SYS_CREATE:
      {
        /* Arguments: const char *file, unsigned initial_size */
        check_user_buffer (f->esp + 4, sizeof (char *));
        check_user_buffer (f->esp + 8, sizeof (unsigned));

        const char *file_name = *(const char **) (f->esp + 4);
        unsigned initial_size = *(unsigned *) (f->esp + 8);
        check_user_string (file_name);

        lock_acquire (&filesys_lock);
        f->eax = filesys_create (file_name, initial_size);
        lock_release (&filesys_lock);
        break;
      }

    case SYS_REMOVE:
      {
        /* Argument: const char *file */
        check_user_buffer (f->esp + 4, sizeof (char *));

        const char *file_name = *(const char **) (f->esp + 4);
        check_user_string (file_name);

        lock_acquire (&filesys_lock);
        f->eax = filesys_remove (file_name);
        lock_release (&filesys_lock);
        break;
      }

    case SYS_OPEN:
      {
        /* Argument: const char *file */
        check_user_buffer (f->esp + 4, sizeof (char *));

        const char *file_name = *(const char **) (f->esp + 4);
        check_user_string (file_name);

        lock_acquire (&filesys_lock);
        struct file *opened_file = filesys_open (file_name);
        lock_release (&filesys_lock);

        if (opened_file == NULL)
          {
            f->eax = -1;
          }
        else
          {
            struct file_descriptor *desc = malloc (sizeof (struct file_descriptor));
            if (desc == NULL)
              {
                lock_acquire (&filesys_lock);
                file_close (opened_file);
                lock_release (&filesys_lock);
                f->eax = -1;
              }
            else
              {
                struct thread *cur = thread_current ();
                desc->fd = cur->next_fd++;
                desc->file = opened_file;
                list_push_back (&cur->fd_list, &desc->elem);
                f->eax = desc->fd;
              }
          }
        break;
      }

    case SYS_FILESIZE:
      {
        /* Argument: int fd */
        check_user_buffer (f->esp + 4, sizeof (int));

        int fd = *(int *) (f->esp + 4);
        struct file_descriptor *desc = get_open_file (fd);

        if (desc == NULL)
          {
            f->eax = -1;
          }
        else
          {
            lock_acquire (&filesys_lock);
            f->eax = file_length (desc->file);
            lock_release (&filesys_lock);
          }
        break;
      }

    case SYS_READ:
      {
        /* Arguments: int fd, void *buffer, unsigned size */
        check_user_buffer (f->esp + 4, sizeof (int));
        check_user_buffer (f->esp + 8, sizeof (void *));
        check_user_buffer (f->esp + 12, sizeof (unsigned));

        int fd = *(int *) (f->esp + 4);
        void *buffer = *(void **) (f->esp + 8);
        unsigned size = *(unsigned *) (f->esp + 12);

        check_user_buffer (buffer, size);

        if (fd == 0) // Keyboard input (STDIN)
          {
            uint8_t *byte_buf = (uint8_t *) buffer;
            for (unsigned i = 0; i < size; i++)
              {
                byte_buf[i] = input_getc ();
              }
            f->eax = size;
          }
        else if (fd == 1) // Cannot read from STDOUT
          {
            f->eax = -1;
          }
        else
          {
            struct file_descriptor *desc = get_open_file (fd);
            if (desc == NULL)
              {
                f->eax = -1;
              }
            else
              {
                lock_acquire (&filesys_lock);
                f->eax = file_read (desc->file, buffer, size);
                lock_release (&filesys_lock);
              }
          }
        break;
      }

    case SYS_WRITE:
      {
        /* Arguments: int fd, const void *buffer, unsigned size */
        check_user_buffer (f->esp + 4, sizeof (int));
        check_user_buffer (f->esp + 8, sizeof (void *));
        check_user_buffer (f->esp + 12, sizeof (unsigned));

        int fd = *(int *) (f->esp + 4);
        const void *buffer = *(const void **) (f->esp + 8);
        unsigned size = *(unsigned *) (f->esp + 12);

        check_user_buffer (buffer, size);

        if (fd == 1) // Console display (STDOUT)
          {
            putbuf (buffer, size);
            f->eax = size;
          }
        else if (fd == 0) // Cannot write to STDIN
          {
            f->eax = -1;
          }
        else
          {
            struct file_descriptor *desc = get_open_file (fd);
            if (desc == NULL)
              {
                f->eax = -1;
              }
            else
              {
                lock_acquire (&filesys_lock);
                f->eax = file_write (desc->file, buffer, size);
                lock_release (&filesys_lock);
              }
          }
        break;
      }

    case SYS_SEEK:
      {
        /* Arguments: int fd, unsigned position */
        check_user_buffer (f->esp + 4, sizeof (int));
        check_user_buffer (f->esp + 8, sizeof (unsigned));

        int fd = *(int *) (f->esp + 4);
        unsigned position = *(unsigned *) (f->esp + 8);

        struct file_descriptor *desc = get_open_file (fd);
        if (desc != NULL)
          {
            lock_acquire (&filesys_lock);
            file_seek (desc->file, position);
            lock_release (&filesys_lock);
          }
        break;
      }

    case SYS_TELL:
      {
        /* Argument: int fd */
        check_user_buffer (f->esp + 4, sizeof (int));

        int fd = *(int *) (f->esp + 4);
        struct file_descriptor *desc = get_open_file (fd);

        if (desc == NULL)
          {
            f->eax = -1;
          }
        else
          {
            lock_acquire (&filesys_lock);
            f->eax = file_tell (desc->file);
            lock_release (&filesys_lock);
          }
        break;
      }

    case SYS_CLOSE:
      {
        /* Argument: int fd */
        check_user_buffer (f->esp + 4, sizeof (int));

        int fd = *(int *) (f->esp + 4);
        struct file_descriptor *desc = get_open_file (fd);

        if (desc != NULL)
          {
            lock_acquire (&filesys_lock);
            file_close (desc->file);
            lock_release (&filesys_lock);

            list_remove (&desc->elem);
            free (desc);
          }
        break;
      }

    default:
      sys_exit (-1);
      break;
    }
}
