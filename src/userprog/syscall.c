#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/synch.h"

static void syscall_handler(struct intr_frame*);

static struct lock global_filesys_lock;

bool create (const char *, unsigned);
bool remove (const char *);
int open (const char *);
int filesize (int);
int read (int, void *, unsigned);
int write (int, const void *, unsigned);
void seek (int, unsigned);
unsigned tell(int);
void close (int);

void syscall_init(void) { 
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&global_filesys_lock); 
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit((int) args[1]);
  } else if (args[0] == SYS_PRACTICE) {
    f->eax = args[1]+1;
  } else if (args[0] == SYS_HALT) {
    halt();
  } else if (args[0] == SYS_EXEC) {
    f->eax = process_execute((char*) args[1]);
  } else if (args[0] == SYS_WAIT) {
    f->eax = process_wait((pid_t) args[1]);   
  } else if (args[0] == SYS_CREATE) {
    f->eax = create((const char*) args[1], (unsigned) args[2]);
  } else if (args[0] == SYS_REMOVE) {
    f->eax = remove((const char*) args[1]);
  } else if (args[0] == SYS_OPEN) {
    f->eax = open((const char*) args[1]);
  } else if (args[0] == SYS_FILESIZE) {
    f->eax = filesize((int) args[1]);
  } else if (args[0] == SYS_READ) {
    f->eax = read((int) args[1], (void *) args[2], (unsigned) args[3]);
  } else if (args[0] == SYS_WRITE) {
    f->eax = write((int) args[1], (void *) args[2], (unsigned) args[3]);
  } else if (args[0] == SYS_SEEK) {
    f->eax = seek((int) args[1], (unsigned) args[2]);
  } else if (args[0] == SYS_TELL) {
    f->eax = tell((int) args[1]);
  } else if (args[0] == SYS_CLOSE) {
    f->eax = close((int) args[1]);
  }
} 

bool create (const char *file, unsigned initial_size) {
  lock_acquire(&global_filesys_lock);
  bool create_file = filesys_create(file, initial_size);
  lock_release(&global_filesys_lock);
  return create_file;
}

bool remove (const char *file) {
  lock_acquire(&global_filesys_lock);
  bool remove_file = filesys_remove(file);
  lock_release(&global_filesys_lock);
  return remove_file;
}

//Reminder to initiate variables: MAX_POSSIBLE_OPENED, all_open_files, count_open_files, global lock, call file_deny_write
//Reminder to put locks

int open (const char *file) {
  lock_acquire(&global_filesys_lock);

  if (count_open_files > MAX_POSSIBLE_OPENED) {
    lock_release(&global_filesys_lock);
    return -1;
  }

  /* Find smallest available file descriptor for the newly opening file. */
  for (int new_fd = 2; new_fd < MAX_POSSIBLE_OPENED; ++new_fd) {
    if (all_open_files[new_fd] == NULL) {
      break;
    }
  }

  all_open_files[new_fd] = malloc(sizeof(FILE));
  all_open_files[new_fd] = filesys_open(file);

  /* Free memory if the file name was invalid. */
  if (all_open_files[new_fd] == NULL) {
    free(all_open_files[new_fd]);
    lock_release(&global_filesys_lock);
    return -1;
  }

  /* Increment number of open files if successful. */
  count_open_files++;

  lock_release(&global_filesys_lock);
}

int filesize (int fd) {
  lock_acquire(&global_filesys_lock);

  if (fd >= MAX_POSSIBLE_OPENED || fd == 0 || fd == 1 || all_open_files[fd] == NULL) {
    lock_release(&global_filesys_lock);
    return -1;
  }

  off_t size_file = file_length(all_open_files[fd]);

  lock_release(&global_filesys_lock);

  return (int) size_file;
}

int read (int fd, void *buffer, unsigned size) {
  lock_acquire(&global_filesys_lock);

  if (fd >= MAX_POSSIBLE_OPENED || fd == 1 || all_open_files[fd] == NULL) {
    lock_release(&global_filesys_lock);
    return -1;
  }

  /* Reading from the keyboard when fd refers to the STDIN. */
  if (fd == 0) {
    for (int s = 0; s < size; ++s) {
      buffer[s] = input_getc();
    }
    lock_release(&global_filesys_lock);
    return size;
  }

  off_t read_file = file_read(all_open_files[fd]);

  lock_release(&global_filesys_lock);
  return (int) read_file;
}

int write (int fd, const void *buffer, unsigned size) {
  lock_acquire(&global_filesys_lock);

  if (fd >= MAX_POSSIBLE_OPENED || fd == 0 || all_open_files[fd] == NULL) {
    lock_release(&global_filesys_lock);
    return -1;
  }

  /* Writing to the console when fd refers to STDOUT. */
  if (fd == 1) {
    putbuf(buffer, size);
    lock_release(&global_filesys_lock);
    return size;
  }

  off_t write_file = file_write(all_open_files[fd], buffer, size);
  lock_release(&global_filesys_lock);
  return (int) write_file;
}

void seek (int fd, unsigned position) {
  lock_acquire(&global_filesys_lock);

  if (fd >= MAX_POSSIBLE_OPENED || fd == 0 || fd == 1 || all_open_files[fd] == NULL) {
    lock_release(&global_filesys_lock);
    return;
  }

  file_seek(all_open_files[fd], (off_t) position);
  lock_release(&global_filesys_lock);
}

unsigned tell(int fd) {
  lock_acquire(&global_filesys_lock);

  if (fd >= MAX_POSSIBLE_OPENED || fd == 0 || fd == 1 || all_open_files[fd] == NULL) {
    lock_release(&global_filesys_lock);
    return -1;
  }

  off_t tell_file = file_tell(all_open_files[fd]);
  lock_release(&global_filesys_lock);
  return (unsigned) tell_file;
}

void close (int fd) {
  lock_acquire(&global_filesys_lock);

  if (fd >= MAX_POSSIBLE_OPENED || fd == 0 || fd == 1 || all_open_files[fd] == NULL) {
    lock_release(&global_filesys_lock);
    return;
  }

  file_close(all_open_files[fd]);
  /* Decrement number of open files. */
  count_open_files--;
  all_open_files[fd] = NULL;
  /* Free memory for the closed file */
  free(all_open_files[fd]);
}