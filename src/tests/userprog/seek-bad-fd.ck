# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF', <<'EOF']);
(seek-bad-fd) begin
(seek-bad-fd) end
seek-bad-fd: exit(0)
EOF
(seek-bad-fd) begin
seek-bad-fd: exit(-1)
EOF
pass;
