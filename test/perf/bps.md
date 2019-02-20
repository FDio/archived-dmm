# 1.  Description
**Test description:**
Measure the bps required to run kernel stack with DMM and lwip stack with DMM using bps tool.

**Date:**Monday, 21. January 2019 10:53PM 

**Test Environment:**
Virtual Machines: 172.28.128.3  and 172.28.128.5
Operating System: Ubuntu 16.04 LTS

**Test App:**
bps

# 2. Topology Diagram
![test_topology.png](resources/test_topology.png
"test_topology.png")

**Physical Machines:**
Server-------------------------Client
connected via 82540EM Gigabit Ethernet Controller

# 3. Test Commands
**Server Command with kernel+DMM:**
```
$sudo LD_LIBRARY_PATH=./ LD_PRELOAD=libnStackAPI.so ./bps 172.28.128.3
```

**Client Command with kernel+DMM:**
```
$ sudo LD_LIBRARY_PATH=./ LD_PRELOAD=libnStackAPI.so ./bps -c 172.28.128.3 -l 64
```

**Server Command with lwip+DMM:**
```
$sudo LD_LIBRARY_PATH=../release/lib64/ LD_PRELOAD=../release/lib64/libnStackAPI.so ./bps 172.28.128.3
```

**Client Command with lwip+DMM:**
```
$sudo LD_LIBRARY_PATH=../release/lib64/ LD_PRELOAD=../release/lib64/libnStackAPI.so ./bps -c 172.28.128.3 -l 64
```

#4. Commit version
```
commit 840dc98676773c027e699bd6efc3793118a5f1ef
Author: charan makkina <charan795m@gmail.com>
Date:   Tue Jan 22 14:18:33 2019 +0530

    Test: Testcases for bps, cps, ip6, lp and te.
    
    Change-Id: I17ad8a915c4a9332c11797e7f02c82abbfadfbbc
    Signed-off-by: charan makkina <charan795m@gmail.com>

```
```
Download source code: git clone https://gerrit.fd.io/r/dmm
```
#5. Result

**Virtual Machines:**
**Kernel Stack**

**Client:**

 | T:mbps | kpps | S:mbps | kpps | R:mbps | kpps | info |
| ---------- | ------ | ---------- | -------| ---------- | ------- | -----|
   | 206 |     03 |     79   | 156 |    126 |  247 | 00:01|
   | 726 |1,419 |    314  | 614 |    412 |  804 | 00:02|
   | 786 |1,535 |    346  | 677 |    439 |  857 | 00:03|
   | 814 |1,591 |    365  | 713 |    449 |  877 | 00:04|
   | 828 |1,618 |    391  | 765 |    436 |  853 | 00:05|
   | 856 |1,672 |    438  | 856 |    417 |  816 | 00:06|
   | 820 |1,602 |    392  | 767 |    427 |  834 | 00:07|
   | 775 |1,513 |    339  | 662 |    435 |  850 | 00:08|
   | 791 |1,545 |    347  | 678 |    443 |  866 | 00:09|
   | 842 |1,646 |    424  | 829 |    418 |  817 | 00:10|
   | 723 |1,413 |    306  | 598 |    417 |  815 | 00:11|
   | 837 |1,635 |    426  | 832 |    411 |  803 | 00:12|
   | 770 |1,505 |    334  | 654 |    435 |  851 | 00:13|
   | 767 |1,499 |    349  | 682 |    417 |  816 | 00:14|
   | 835 |1,631 |    387  | 757 |    447 |  874 | 00:15|
   | 820 |1,601 |    358  | 699 |    461 |  902 | 00:16|
   | 817 |1,597 |    370  | 723 |    447 |  874 | 00:17|
   | 844 |1,648 |    391  | 763 |    452 |  884 | 00:18|
   | 814 |1,590 |    364  | 711 |    450 |  879 | 00:19|
   | 726 |1,418 |    269  | 526 |    456 |  892 | 00:20|
   | 747 |1,459 |    345  | 674 |    402 |  785 | 00:21|
   | 811 |1,584 |    389  | 760 |    422 |  824 | 00:22|
   | 806 |1,575 |    356  | 696 |    450 |  879 | 00:23|
   | 798 |1,559 |    351  | 685 |    447 |  873 | 00:24|
   | 712 |1,390 |    270  | 528 |    441 |  862 | 00:25|
   | 790 |1,544 |    318  | 622 |    471 |  921 | 00:26|
   | 837 |1,636 |    379  | 741 |    457 |  894 | 00:27|
   | 753 |1,472 |    342  | 669 |    410 |  802 | 00:28|
   | 788 |1,540 |    350  | 685 |    437 |  855 | 00:29|
   | 794 |1,551 |    350  | 685 |    443 |  865 | 00:30|

**LWIP stack:**


**Client:**

 | T:mbps | kpps | S:mbps | kpps | R:mbps | kpps | info |
| ---------- | ------ | ---------- | -------| ---------- | ------- | -----|
    |109  | 214 |     53 |  104 |     56  | 109 | 00:01 |
    |123  | 241 |     55 |  108 |     68  | 133 | 00:02 |
    |142  | 277 |     72 |  140 |     70  | 136 | 00:03 |
    |118  | 230 |     51 |  101 |     66  | 129 | 00:04 |
    |135  | 263 |     55 |  107 |     79  | 155 | 00:05 |
    |137  | 269 |     55 |  107 |     82  | 161 | 00:06 |
    |138  | 270 |     53 |  105 |     84  | 165 | 00:07 |
    |122  | 239 |     58 |  113 |     64  | 126 | 00:08 |
    |125  | 244 |     51 |  100 |     73  | 143 | 00:09 |
    |111  | 217 |     53 |  105 |     57  | 112 | 00:10 |
    |125  | 244 |     58 |  115 |     66  | 129 | 00:11 |
    |225  | 440 |    105|   205 |    120|   234 | 00:12|
    |192  | 376 |     91 |  177 |    101 |  198 | 00:13|
    |201  | 393 |     95 |  186 |    106 |  207 | 00:14|
    |210  | 410 |     98 |  192 |    111 |  218 | 00:15|
    |210  | 410 |     93 |  183 |    116 |  226 | 00:16|
    |149  | 292 |     78 |  152 |     71  | 139 | 00:17 |
    |132  | 257 |     59 |  116 |     72  | 140 | 00:18 |
    |138  | 271 |     58 |  114 |     80  | 156 | 00:19 |
    |133  | 260 |     58 |  114 |     74  | 146 | 00:20 |
    |127  | 248 |     58 |  114 |     68  | 133 | 00:21 |
    |114  | 224 |     55 |  107 |     59  | 116 | 00:22 |
    |126  | 247 |     60 |  117 |     66  | 129 | 00:23 |
    |141  | 275 |     71 |  140 |     69  | 135 | 00:24 |
    |158  | 308 |     73 |  144 |     84  | 164 | 00:25 |
    |181  | 354 |     78 |  153 |    102 |  200 | 00:26|
    |156  | 306 |     70 |  138 |     85  | 167 | 00:27 |
    |158  | 310 |     74 |  145 |     84  | 164 | 00:28 |
    |167  | 327 |     79 |  155 |     88  | 172 | 00:29 |
    |161  | 315 |     85 |  166 |     76  | 149 | 00:30 |

#7. Conclusion
**Virtual Machines:**
The sender and receiver has values in the range of 357 and 436 mbps for kernel stack.
The sender and receiver has values in the range of  68 and 80 mbps for lwip stack.

These are the benchmark values for further tests.
