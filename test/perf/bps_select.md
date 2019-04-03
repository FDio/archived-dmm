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
    |459 |  897  |    182  | 356 |    277 |  541 | 00:01|
    |838 |1,637 |    374  | 731 |    463 |  906 | 00:02|
    |747 |1,459 |    310  | 605 |    437 |  854 | 00:03|
    |749 |1,464 |    302  | 590 |    447 |  874 | 00:04|
    |793 |1,549 |    357  | 697 |    436 |  851 | 00:05|
    |766 |1,497 |    309  | 604 |    457 |  893 | 00:06|
    |821 |1,603 |    361  | 705 |    459 |  898 | 00:07|
    |791 |1,544 |    333  | 650 |    457 |  894 | 00:08|
    |815 |1,592 |    370  | 722 |    445 |  869 | 00:09|
    |800 |1,564 |    326  | 637 |    474 |  927 | 00:10|
    |759 |1,482 |    296  | 579 |    462 |  903 | 00:11|
    |794 |1,551 |    329  | 642 |    465 |  908 | 00:12|
    |804 |1,571 |    343  | 670 |    461 |  900 | 00:13|
    |827 |1,615 |    367  | 717 |    460 |  898 | 00:14|
    |755 |1,475 |    320  | 625 |    435 |  850 | 00:15|
    |840 |1,641 |    363  | 710 |    476 |  930 | 00:16|
    |747 |1,459 |    318  | 621 |    429 |  838 | 00:17|
    |787 |1,537 |    305  | 595 |    482 |  941 | 00:18|
    |798 |1,560 |    320  | 626 |    478 |  933 | 00:19|
    |741 |1,447 |    304  | 594 |    436 |  853 | 00:20|
    |807 |1,577 |    362  | 708 |    444 |  868 | 00:21|
    |826 |1,614 |    381  | 745 |    445 |  869 | 00:22|
    |792 |1,548 |    325  | 636 |    466 |  911 | 00:23|
    |852 |1,665 |    384  | 750 |    468 |  914 | 00:24|
    |787 |1,538 |    332  | 650 |    455 |  888 | 00:25|
    |812 |1,585 |    374  | 731 |    437 |  854 | 00:26|
    |789 |1,541 |    340  | 665 |    448 |  876 | 00:27|
    |799 |1,561 |    341  | 666 |    458 |  894 | 00:28|
    |766 |1,497 |    319  | 624 |    447 |  873 | 00:29|
    |775 |1,514 |    296  | 578 |    479 |  936 | 00:30|

**LWIP stack:**


**Client:**

 | T:mbps | kpps | S:mbps | kpps | R:mbps | kpps | info |
| ---------- | ------ | ---------- | -------| ---------- | ------- | -----|
   |  89  |174 |     53   |103 |     36   | 71 | 00:01    |
   | 115 |  225 |     53 |  105 |     61 |  120 | 00:02 |
   |  95  | 185 |     45  |  88 |     49   | 96 | 00:03    |
   | 142 |  279 |     69 |  136 |     73 |  142 | 00:04 |
   | 107 |  209 |     54 |  106 |     52 |  103 | 00:05 |
   | 121 |  237 |     52 |  101 |     69 |  135 | 00:06 |
   |  92  | 180 |     42  |  83 |     49   | 97 | 00:07    |
   | 163 |  318 |     75 |  147 |     87 |  170 | 00:08 |
   | 125 |  245 |     70 |  137 |     54 |  107 | 00:09 |
   | 134 |  262 |     69 |  136 |     64 |  125 | 00:10 |
   | 135 |  264 |     74 |  145 |     61 |  119 | 00:11 |
   | 132 |  259 |     68 |  133 |     64 |  125 | 00:12 |
   | 100 |  197 |     51 |   99 |     49  |  97 | 00:13   |
   | 108 |  212 |     55 |  107 |     53 |  105 | 00:14 |
   | 109 |  213 |     57 |  113 |     51 |  100 | 00:15 |
   | 129 |  253 |     56 |  109 |     73 |  143 | 00:16 |
   | 213 |  417 |     85 |  166 |    128|   250 | 00:17|
   | 180 |  352 |     86 |  168 |     94 |  184 | 00:18 |
   | 177 |  347 |     86 |  168 |     91 |  179 | 00:19 |
   | 192 |  376 |     86 |  169 |    106|   207 | 00:20|
   | 202 |  395 |     89 |  175 |    112|   219 | 00:21|
   | 198 |  388 |     91 |  178 |    107|   209 | 00:22|
   | 181 |  355 |     82 |  161 |     99 |  193 | 00:23 |
   | 192 |  375 |     85 |  167 |    106|   208 | 00:24|
   | 176 |  345 |     86 |  169 |     89 |  175 | 00:25 |
   | 174 |  341 |     82 |  160 |     92 |  180 | 00:26 |
   | 186 |  364 |     81 |  158 |    105|   205 | 00:27|
   | 199 |  389 |     82 |  160 |    117|   228 | 00:28|
   | 173 |  338 |     81 |  160 |     91 |  178 | 00:29 |
   | 191 |  373 |     88 |  172 |    103|   201 | 00:30|

#7. Conclusion
**Virtual Machines:**
The sender and receiver has values in the range of 357 and 455 mbps for kernel stack.
The sender and receiver has values in the range of  71 and 80 mbps for lwip stack.

These are the benchmark values for further tests.
