# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF']);
(join-twice) begin
(join-twice) Main starting
(join-twice) Finished joining
(join-twice) Thread finished
(join-twice) Finished joining
(join-twice) Main regained control
(join-twice) Main finishing
(join-twice) end
join-twice: exit(0)
EOF
pass;
