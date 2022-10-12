/* Tries to return the position of the next byte in an open file using tell. */

#include <syscall.h>
#include "tests/userprog/sample.inc"
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int handle, next_byte;

  CHECK(create("test.txt", sizeof sample - 1), "create \"test.txt\"");
  CHECK((handle = open("test.txt")) > 1, "open \"test.txt\"");

  write(handle, sample, sizeof sample - 2);
  next_byte = tell(handle);
  if (next_byte != sizeof sample - 2) {
    fail("tell() returned %d instead of %d", next_byte, sizeof sample - 2);
  }
}
