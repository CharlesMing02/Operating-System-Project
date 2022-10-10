#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler(struct intr_frame*);

static struct lock global_filesys_lock;

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
  }
  if (pagedir_get_page(active_pd(), address) == NULL) {
    process_exit(-1);
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
      //printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
      process_exit((int) args[1]);
      break;
    case SYS_WRITE:
      validate((uint32_t*) &args[1]);
      validate((uint32_t*) &args[2]);
      validate((uint32_t*) args[2]);
      validate((uint32_t*) &args[3]);
      lock_acquire(&global_filesys_lock);
      if (args[1] == 1) {
        putbuf(args[2], args[3]);
        f->eax = args[3];
      }
      lock_release(&global_filesys_lock);
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
      f->eax = process_execute((char*) args[1]);
      break;
    case SYS_WAIT:
      validate((uint32_t*) &args[1]);
      f->eax = process_wait((pid_t) args[1]);   
      break;
  }
}
