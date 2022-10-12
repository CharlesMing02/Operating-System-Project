#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

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

void validate(uint32_t* address) {
  bool valid = true;
  for (int i = 0; i < 4; i++) {
    valid = is_user_vaddr(address+i);
    if (!valid) {
      process_exit(-1);
    }
    if (pagedir_get_page(active_pd(), address+i) == NULL) {
      process_exit(-1);
    }
  }
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

  validate((uint32_t*) args);
  switch (args[0]) {
    case SYS_EXIT:
      validate((uint32_t*) &args[1]);
      f->eax = args[1];
      process_exit((int) args[1]);
      break;
    case SYS_PRACTICE:
      validate((uint32_t*) &args[1]);
      f->eax = args[1]+1;
      break;
    case SYS_HALT:
      halt();
      break;
    case SYS_EXEC:
      validate((uint32_t*) &args[1]);
      validate((uint32_t*) args[1]);
      lock_acquire(&global_filesys_lock);
      f->eax = process_execute((char*) args[1]);
      lock_release(&global_filesys_lock);
      break;
    case SYS_WAIT:
      validate((uint32_t*) &args[1]);
      f->eax = process_wait((pid_t) args[1]);   
      break;
    case SYS_COMPUTE_E:
      validate((uint32_t*) &args[1]);
      f->eax = sys_sum_to_e(args[1]);
      break;
    case SYS_WRITE:
      validate((uint32_t*) &args[1]);
      validate((uint32_t*) &args[2]);
      validate((uint32_t*) args[2]);
      validate((uint32_t*) &args[3]);
      f->eax = write((int) args[1], (void *) args[2], (unsigned) args[3]);
      break;
    case SYS_CREATE:
      validate((uint32_t*) &args[1]);
      validate((uint32_t*) args[1]);
      validate((uint32_t*) &args[2]);
      f->eax = create((char*) args[1], (unsigned) args[2]);
      break;
    case SYS_REMOVE:
      validate((uint32_t*) &args[1]);
      validate((uint32_t*) args[1]);
      f->eax = remove((char*) args[1]);
      break;
    case SYS_OPEN:
      validate((uint32_t*) &args[1]);
      validate((uint32_t*) args[1]);
      f->eax = open((char*) args[1]);
      break;
    case SYS_FILESIZE:
      validate((uint32_t*) &args[1]);
      f->eax = filesize((int) args[1]);
      break;
    case SYS_READ:
      validate((uint32_t*) &args[1]);
      validate((uint32_t*) &args[2]);
      validate((uint32_t*) args[2]);
      validate((uint32_t*) &args[3]);
      f->eax = read((int) args[1], (void*) args[2], (unsigned) args[3]);
      break;
    case SYS_SEEK:
      validate((uint32_t*) &args[1]);
      validate((uint32_t*) &args[2]);
      //f->eax =
      seek((int) args[1], (unsigned)args[2]);
      break;
    case SYS_TELL:
      validate((uint32_t*) &args[1]);
      f->eax = tell((int) args[1]);
      break;
    case SYS_CLOSE:
      validate((uint32_t*) &args[1]);
      //f->eax = 
      //NOTE: return -1 if fd does not correspond
      close((int) args[1]);
      break;
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

  if (thread_current()->count_open_files > MAX_POSSIBLE_OPENED) {
    lock_release(&global_filesys_lock);
    return -1;
  }

  /* Find smallest available file descriptor for the newly opening file. */
  int new_fd = 2;
  while (thread_current()->all_open_files[new_fd] != NULL) {
    new_fd++;
  }

  //file_deny_write(file);
  thread_current()->all_open_files[new_fd] = filesys_open(file);

  if (thread_current()->all_open_files[new_fd] == NULL) {
    lock_release(&global_filesys_lock);
    return -1;
  }

  /* Increment number of open files if successful. */
  thread_current()->count_open_files++;
  //file_deny_write(thread_current()->all_open_files[new_fd]);

  lock_release(&global_filesys_lock);
  return new_fd;
}

int filesize (int fd) {
  lock_acquire(&global_filesys_lock);

  if (fd >= MAX_POSSIBLE_OPENED || fd == 0 || fd == 1 || thread_current()->all_open_files[fd] == NULL) {
    lock_release(&global_filesys_lock);
    return -1;
  }

  int size_file = (int) file_length(thread_current()->all_open_files[fd]);

  lock_release(&global_filesys_lock);

  return size_file;
}

int read (int fd, void *buffer, unsigned size) {
  lock_acquire(&global_filesys_lock);

  if (fd >= MAX_POSSIBLE_OPENED || fd == 1 || thread_current()->all_open_files[fd] == NULL) {
    lock_release(&global_filesys_lock);
    process_exit(-1);
    //return -1;
  }

  /* Reading from the keyboard when fd refers to the STDIN. */
  if (fd == 0) {
    for (unsigned s = 0; s < size; ++s) {
      * (uint8_t *)(buffer + s) = input_getc();
    }
    lock_release(&global_filesys_lock);
    return size;
  }

  /*if (thread_current()->all_open_files[fd] == NULL) {
    return -1;
  }*/
  int read_file = (int) file_read(thread_current()->all_open_files[fd], buffer, size); //WHAT SHOULD THE OTHER ARGS BE?

  lock_release(&global_filesys_lock);
  return read_file;
}

int write (int fd, const void *buffer, unsigned size) {
  lock_acquire(&global_filesys_lock);

  /* Writing to the console when fd refers to STDOUT. */
  if (fd == 1) {
    putbuf(buffer, size);
    lock_release(&global_filesys_lock);
    return size;
  }

  if (fd >= MAX_POSSIBLE_OPENED || fd == 0 || thread_current()->all_open_files[fd] == NULL) {
    lock_release(&global_filesys_lock);
    process_exit(-1);
    //return -1;
  }

  int write_file = (int) file_write(thread_current()->all_open_files[fd], buffer, size);
  lock_release(&global_filesys_lock);
  return write_file;
}

void seek (int fd, unsigned position) {
  lock_acquire(&global_filesys_lock);

  if (fd >= MAX_POSSIBLE_OPENED || fd == 0 || fd == 1 || thread_current()->all_open_files[fd] == NULL) {
    lock_release(&global_filesys_lock);
    return;
  }

  file_seek(thread_current()->all_open_files[fd], position);
  lock_release(&global_filesys_lock);
}

unsigned tell(int fd) {
  lock_acquire(&global_filesys_lock);

  if (fd >= MAX_POSSIBLE_OPENED || fd == 0 || fd == 1 || thread_current()->all_open_files[fd] == NULL) {
    lock_release(&global_filesys_lock);
    return -1;
  }

  unsigned tell_file = (unsigned) file_tell(thread_current()->all_open_files[fd]);
  lock_release(&global_filesys_lock);
  return tell_file;
}

void close (int fd) {
  lock_acquire(&global_filesys_lock);

  if (fd >= MAX_POSSIBLE_OPENED || fd == 0 || fd == 1 || thread_current()->all_open_files[fd] == NULL) {
    lock_release(&global_filesys_lock);
    return;
  }

  file_close(thread_current()->all_open_files[fd]);
  //file_allow_write(thread_current()->all_open_files[fd]);
  /* Decrement number of open files. */
  thread_current()->count_open_files--;
  thread_current()->all_open_files[fd] = NULL;
  lock_release(&global_filesys_lock);

}
