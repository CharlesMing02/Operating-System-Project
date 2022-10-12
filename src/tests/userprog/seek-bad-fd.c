/* Tries to pass in an invalid file descriptor to the seek syscall. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
    seek(0x20101234, 0);
}