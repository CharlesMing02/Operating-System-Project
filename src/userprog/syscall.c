#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/synch.h"

static void syscall_handler(struct intr_frame*);

static struct lock global_filesys_lock;

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
  } else if (args[0] == SYS_WRITE) {
    lock_acquire(&global_filesys_lock);
    if (args[1] == 1) {
      putbuf(args[2], args[3]);
      f->eax = args[3];
    }
    lock_release(&global_filesys_lock);
  } else if (args[0] == SYS_PRACTICE) {
    f->eax = args[1]+1;
  } else if (args[0] == SYS_HALT) {
    halt();
  } else if (args[0] == SYS_EXEC) {
    f->eax = process_execute((char*) args[1]);
  } else if (args[0] == SYS_WAIT) {
    f->eax = process_wait((pid_t) args[1]);   
  }
}
