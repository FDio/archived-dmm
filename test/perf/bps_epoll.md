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
    |369 |   722 |    177 |  347 |    191  | 374 | 00:01|
    |786 |1,535 |    378 |  738 |    407  | 796 | 00:02|
    |829 |1,619 |    416 |  812 |    413  | 806 | 00:03|
    |866 |1,692 |    425 |  831 |    441  | 861 | 00:04|
    |839 |1,639 |    399 |  779 |    440  | 859 | 00:05|
    |774 |1,512 |    377 |  737 |    396  | 774 | 00:06|
    |796 |1,554 |    365 |  713 |    430  | 841 | 00:07|
    |839 |1,640 |    432 |  845 |    406  | 794 | 00:08|
    |820 |1,601 |    383 |  749 |    436  | 851 | 00:09|
    |801 |1,565 |    362 |  708 |    438  | 856 | 00:10|
    |812 |1,586 |    391 |  764 |    421  | 822 | 00:11|
    |860 |1,679 |    414 |  809 |    445  | 869 | 00:12|
    |790 |1,544 |    359 |  702 |    431  | 841 | 00:13|
    |826 |1,614 |    391 |  765 |    435  | 849 | 00:14|
    |868 |1,695 |    430 |  841 |    437  | 853 | 00:15|
    |858 |1,676 |    430 |  841 |    427  | 835 | 00:16|
    |819 |1,599 |    409 |  798 |    410  | 800 | 00:17|
    |817 |1,596 |    416 |  812 |    401  | 783 | 00:18|
    |835 |1,631 |    428 |  837 |    406  | 794 | 00:19|
    |848 |1,657 |    409 |  799 |    439  | 858 | 00:20|
    |835 |1,631 |    413 |  807 |    422  | 824 | 00:21|
    |909 |1,775 |    464 |  908 |    444  | 867 | 00:22|
    |840 |1,641 |    420 |  820 |    420  | 821 | 00:23|
    |794 |1,551 |    347 |  678 |    446  | 872 | 00:24|
    |815 |1,593 |    377 |  737 |    438  | 856 | 00:25|
    |895 |1,748 |    462 |  903 |    432  | 845 | 00:26|
    |848 |1,657 |    401 |  783 |    447  | 874 | 00:27|
    |826 |1,614 |    391 |  765 |    434  | 849 | 00:28|
    |781 |1,527 |    362 |  707 |    419  | 819 | 00:29|
    |853 |1,666 |    436 |  852 |    416  | 813 | 00:30|

**LWIP stack:**


**Client:**

 | T:mbps | kpps | S:mbps | kpps | R:mbps | kpps | info |
| ---------- | ------ | ---------- | -------| ---------- | ------- | -----|
  |  126 |  247 |     30  |  58 |     96 |  188 | 00:01|
  |  138 |  271 |     31  |  62 |    106|   208 | 00:02|
  |  125 |  244 |     47  |  93 |     77 |  151 | 00:03|
  |  138 |  270 |     40  |  79 |     97 |  190 | 00:04|
  |  131 |  257 |     39  |  78 |     91 |  179 | 00:05|
  |  115 |  225 |     46  |  91 |     68 |  134 | 00:06|
  |  132 |  257 |     49  |  95 |     82 |  162 | 00:07|
  |  121 |  237 |     49  |  96 |     72 |  141 | 00:08|
  |  116 |  227 |     58  | 114 |     57|   112 | 00:09|
  |  103 |  202 |     51  | 101 |     51|   101 | 00:10|
  |  110 |  216 |     45  |  88 |     65 |  128 | 00:11|
  |  137 |  268 |     52  | 101 |     85|   167 | 00:12|
  |  116 |  227 |     30  |  60 |     85 |  166 | 00:13|
  |  116 |  227 |     47  |  92 |     69 |  135 | 00:14|
  |  124 |  242 |     40  |  79 |     83 |  163 | 00:15|
  |  106 |  207 |     43  |  84 |     62 |  122 | 00:16|
  |  120 |  234 |     51  | 100 |     68|   134 | 00:17|
  |  118 |  232 |     35  |  68 |     83 |  163 | 00:18|
  |  131 |  256 |     30  |  59 |    100|   196 | 00:19|
  |  105 |  205 |     32  |  64 |     72 |  141 | 00:20|
  |  96   |188 |     29    |57 |     67   |131 | 00:21  |
  |  119 |  233 |     33  |  66 |     85 |  167 | 00:22|
  |  110 |  215 |     31  |  61 |     78 |  154 | 00:23|
  |  80   |158 |     28    |55 |     52   |103 | 00:24  |
  |  73   |144 |     26    |51 |     47   | 92 | 00:25   |
  |104   |204 |     34    |67 |     69   |136 | 00:26  |
  | 100  | 196 |     31   | 62 |     68  | 133 | 00:27 |
  |  71   |138 |     27    |54 |     43   | 84 | 00:28   |
  |  88   |171 |     31    |62 |     56   |109 | 00:29  |
  |  82   |161 |     34    |67 |     48   | 93 | 00:30   |

#7. Conclusion
**Virtual Machines:**
The sender and receiver has values in the range of 403 and 427 mbps for kernel stack.
The sender and receiver has values in the range of 38 and 73 mbps for lwip stack.

These are the benchmark values for further tests.
