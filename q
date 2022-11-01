[33mcommit 29ad34acb3ebf7d4c004a347552d92ee82707941[m[33m ([m[1;36mHEAD -> [m[1;32mmaster[m[33m, [m[1;31mgroup/master[m[33m)[m
Author: Edison <zx.chen@berkeley.edu>
Date:   Mon Oct 10 05:09:40 2022 +0000

    fix FPU errors

[33mcommit bbd54026a41f85f1491eec075252feb4a813eb31[m
Author: Edison <zx.chen@berkeley.edu>
Date:   Mon Oct 10 03:57:15 2022 +0000

    fix bug with startup

[33mcommit 960285d643b17a25247738f75223fb1f853eaa5e[m
Author: Darren Wu <dwu3@berkeley.edu>
Date:   Sun Oct 9 18:38:23 2022 -0700

    fixed free page error

[33mcommit c4fd9daea71c597e6f73aee4a30977fe856899d0[m
Merge: a8a0e97 02c8f81
Author: Darren Wu <dwu3@berkeley.edu>
Date:   Sun Oct 9 00:14:04 2022 -0700

    commit

[33mcommit a8a0e97884a264d261483f6ccb222c1bbd261aa5[m
Author: Darren Wu <dwu3@berkeley.edu>
Date:   Sun Oct 9 00:08:40 2022 -0700

    cant run anything

[33mcommit 02c8f811571e10f2d1e7ad0bc21c7264c0d152b7[m
Author: Edison <zx.chen@berkeley.edu>
Date:   Sun Oct 9 06:05:38 2022 +0000

    FPU part done, should work when prereqs work

[33mcommit 375d280a3d833d1ec32d4c1eba993528d4964546[m
Merge: ec9650c 845c439
Author: Darren Wu <dwu3@berkeley.edu>
Date:   Sat Oct 8 22:45:04 2022 -0700

    fixed some syntax errors

[33mcommit ec9650c86282875d9de51ec2790874f419e2798f[m
Author: Darren Wu <dwu3@berkeley.edu>
Date:   Sat Oct 8 22:41:32 2022 -0700

    release lock in write syscall

[33mcommit 845c439fbec9747fd8d340da82d5babdc6c2c8b7[m
Author: Andy Chen <andyc789@berkeley.edu>
Date:   Sun Oct 9 05:40:04 2022 +0000

    fixed syntax for process syscalls

[33mcommit fd9b22c408b41f585d131a571e6b008b263f4c7b[m
Author: Andy Chen <andyc789@berkeley.edu>
Date:   Sun Oct 9 05:15:10 2022 +0000

    syntax error on 146 of process.c

[33mcommit 29aae2eac067649f3f5d1f49497a8b3e480de5ef[m
Merge: 43a5105 b8f2798
Author: Darren Wu <dwu3@berkeley.edu>
Date:   Sat Oct 8 01:03:57 2022 -0700

    try to implement write syscall for STDOUT

[33mcommit 43a5105b4380e3eb8cc214428f45c4e1bb749d01[m
Author: Darren Wu <dwu3@berkeley.edu>
Date:   Sat Oct 8 00:50:01 2022 -0700

    implemented write syscall for STDOUT

[33mcommit b8f2798c7dc97fc0c79a9d9bf8a64c3ffac7051d[m
Author: Andy Chen <andyc789@berkeley.edu>
Date:   Sat Oct 8 07:00:36 2022 +0000

    added syscall.c stuff for process control syscalls

[33mcommit c36d28dbaf4a212b9e6d69d9561bbc01d115405f[m
Merge: 85c1643 7038e37
Author: Andy Chen <andyc789@berkeley.edu>
Date:   Sat Oct 8 06:45:40 2022 +0000

    Merge branch 'master' of github.com:Berkeley-CS162/group82

[33mcommit 85c1643230b847f2bf6879df641560d7c4f0bf4a[m
Author: Andy Chen <andyc789@berkeley.edu>
Date:   Sat Oct 8 06:45:24 2022 +0000

    first draft of process control syscall functions in process.c

[33mcommit 7038e37f3f8c572f0b77acf5291d2ab434ba1e10[m
Author: Darren Wu <dwu3@berkeley.edu>
Date:   Fri Oct 7 23:17:24 2022 -0700

    use memcpy to push args

[33mcommit 2957b5458b041aa7005deef781bcabceef3d016e[m
Merge: a743db8 2e8895f
Author: Andy Chen <andyc789@berkeley.edu>
Date:   Sat Oct 8 05:49:46 2022 +0000

    Merge branch 'master' of github.com:Berkeley-CS162/group82

[33mcommit a743db88f9b0438afb1a9c2ffb25e0d238a14ec0[m
Author: Andy Chen <andyc789@berkeley.edu>
Date:   Sat Oct 8 05:47:56 2022 +0000

    added semicolon after startprocess_data

[33mcommit 2e8895f3f58fe01db8b7a5c9d9c56d81069c56a0[m
Author: Darren Wu <dwu3@berkeley.edu>
Date:   Fri Oct 7 22:47:05 2022 -0700

    added check for successful load

[33mcommit 9dc3f026e422ca27b5b6868ef7fa90bacab66a0a[m
Author: Darren Wu <dwu3@berkeley.edu>
Date:   Fri Oct 7 22:41:15 2022 -0700

    casted esp to char*

[33mcommit e9df09732294ce6e98a29c728d3a4e2f62f1ae41[m
Merge: 77eb03d 7e54201
Author: Andy Chen <andyc789@berkeley.edu>
Date:   Sat Oct 8 04:58:17 2022 +0000

    Merge branch 'master' of github.com:Berkeley-CS162/group82

[33mcommit 77eb03dc2e22880155f68eecdfb273068f6783ba[m
Author: Andy Chen <andyc789@berkeley.edu>
Date:   Sat Oct 8 04:57:53 2022 +0000

    first draft exit, started working on exec

[33mcommit 7e542019ca5c48f863ecb1b5b4c591f8fe875bd6[m
Author: Darren Wu <dwu3@berkeley.edu>
Date:   Thu Oct 6 07:01:27 2022 -0700

    implemented argument passing (not tested, probably wrong)

[33mcommit 6c80e044fde3d73ba364364aef9966a06358e093[m[33m ([m[1;31mstaff/master[m[33m, [m[1;31mstaff/HEAD[m[33m)[m
Author: Daniel Zhu <daniel.e.zhu+github@gmail.com>
Date:   Sat Sep 10 16:51:41 2022 -0700

    Publish Pintos starter code

[33mcommit fc5d6ee4caf1363c9969698d7993e789a290ebdb[m
Author: PotatoParser <wilsonqnguyen@gmail.com>
Date:   Mon Aug 22 00:44:34 2022 -0700

    Initial Commit
