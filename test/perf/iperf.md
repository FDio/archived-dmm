# 1.  Description
**Test description:**
Measure the bandwith required to run kernel stack with DMM and without DMM using IPERF tool.

**Date:** Thursday, 17. January 2019 03:57PM 

**Test Environment:**
Physical Machines: 172.16.101.1 and 172.16.103.1
Operating System: Ubuntu 16.04 LTS

Virtual Machines:172.28.128.4 and 172.28.128.6
Operating System: Ubuntu 16.04 LTS

**Test App:**
Iperf : iPerf3 is a tool for active measurements of the maximum achievable bandwidth on IP networks. It supports tuning of various parameters related to timing, buffers and protocols (TCP, UDP, SCTP with IPv4 and IPv6). For each test it reports the bandwidth, loss, and other parameters.

# 2. Topology Diagram
![test_topology.png](resources/test_topology.png
"test_topology.png")

**Physical Machines:**
Server-------------------------Client
connected via 82599ES 10-Gigabit SFI/SFP+ Network Connection

**Virtual Machines:**
Server-------------------------Client
connected via 82540EM Gigabit Ethernet Controller
# 3. Test Commands
**Server Command with DMM:**
```
$sudo LD_LIBRARY_PATH=/home/root1/dmm/thirdparty/apps/iperf-3.1.3/src/.libs/ LD_PRELOAD=/home/root1/dmm/thirdparty/apps/iperf-3.1.3/src/.libs/libnStackAPI.so ./iperf3 -s -B 172.28.128.3 -4
```

**Client Command with DMM:**
```
$sudo LD_LIBRARY_PATH=/home/root1/dmm/thirdparty/apps/iperf-3.1.3/src/.libs/ LD_PRELOAD=/home/root1/dmm/thirdparty/apps/iperf-3.1.3/src/.libs/libnStackAPI.so ./iperf3 -c 172.18.128.3 -B 172.28.128.5 -4
```

**Server Command without DMM:**
```
$sudo ./iperf3 -s -B 172.28.128.3 -4
```

**Client Command without DMM:**
```
$sudo ./iperf3 -c 172.18.128.3 -B 172.28.128.5 -4
```

#4. Commit version
```
commit fa0dce9d94e9bfbdd9ec877036a101d2fd69f42c
Merge: b5f1d4b f35c043
Author: yalei wang <wylandrea@gmail.com>
Date:   Mon Dec 3 12:46:58 2018 +0000

    Merge "Fix: removing unwanted json elements"
```
```
Download source code: git clone https://gerrit.fd.io/r/dmm
```
#5. Result

**Physical Machines:**
**DMM+Kernel:**

**Server:**

| ID | Interval | Transfer  |  Bandwidth | sender/receiver |
| -- | -------- | --------- | ------------ | ----------------- |
| 18 | 0.00-10.04  sec | 0.00 Bytes | 0.00 bits/sec | sender |
| 18 | 0.00-10.04  sec | 11.0 GBytes | 9.38 Gbits/sec | receiver |

**Client:**

| ID | Interval | Transfer  |  Bandwidth | Retr | sender/receiver |
| -- | -------- | --------- | ------------ | ------| ---------------- |
| 17 |  0.00-10.00  sec | 11.0 GBytes | 9.41 Gbits/sec  | 14 | sender |
| 17 |   0.00-10.00  sec | 11.0 GBytes | 9.41 Gbits/sec |  | receiver |

**Kernel:**

**Server:**

| ID | Interval | Transfer  |  Bandwidth | sender/receiver |
| -- | -------- | --------- | ------------ | ----------------- |
| 5 |  0.00-10.04  sec  | 0.00 Bytes | 0.00 bits/sec | sender |
| 5 |  0.00-10.04  sec | 11.0 GBytes | 9.38 Gbits/sec | receiver |

**Client:**

| ID | Interval | Transfer  |  Bandwidth | Retr | sender/receiver |
| -- | -------- | --------- | ------------ | ------| ---------------- |
|  4 |   0.00-10.00  sec | 11.0 GBytes | 9.42 Gbits/sec |  15  |  sender |
|  4 |   0.00-10.00  sec | 11.0 GBytes | 9.41 Gbits/sec       |         | receiver |

**Virtual Machines:**
**DMM+Kernel:**

**Server:**

| ID | Interval | Transfer  |  Bandwidth | sender/receiver |
| -- | -------- | --------- | ------------ | ----------------- |
| 18 | 0.00-10.04  sec | 0.00 Bytes | 0.00 bits/sec | sender |
| 18 | 0.00-10.04  sec | 2.94 GBytes | 2.51 Gbits/sec | receiver |

**Client:**

| ID | Interval | Transfer  |  Bandwidth | Retr | sender/receiver |
| -- | -------- | --------- | ------------ | ------| ---------------- |
| 17 |  0.00-10.00  sec | 2.94 GBytes | 2.52 Gbits/sec  | 22634 | sender |
| 17 |   0.00-10.00  sec | 2.94 GBytes | 2.52 Gbits/sec |  | receiver |

**Kernel:**

**Server:**

| ID | Interval | Transfer  |  Bandwidth | sender/receiver |
| -- | -------- | --------- | ------------ | ----------------- |
| 5 |  0.00-10.04  sec  | 0.00 Bytes | 0.00 bits/sec | sender |
| 5 |  0.00-10.04  sec | 2.87 GBytes | 2.46 Gbits/sec | receiver |

**Client:**

| ID | Interval | Transfer  |  Bandwidth | Retr | sender/receiver |
| -- | -------- | --------- | ------------ | ------| ---------------- |
|  4 |   0.00-10.00  sec | 2.87 GBytes | 2.47 Gbits/sec |  21104  |  sender |
|  4 |   0.00-10.00  sec | 2.87 GBytes | 2.47 Gbits/sec       |         | receiver |

#7. Conclusion
**Physical Machines:**
The bandwidth while running iperf with kernel and DMM is 9.41 Gbits/sec at both sender and receiver and while running iperf with kernel alone is 9.42 Gbits/sec at sender and 9.41 Gbits/sec at receiver. 

**Virtual Machines:**
The bandwidth while running iperf with kernel and DMM is 2.52 Gbits/sec at both sender and receiver and while running iperf with kernel alone is 2.47 Gbits/sec at both sender and receiver.

These are the benchmark values for further tests.