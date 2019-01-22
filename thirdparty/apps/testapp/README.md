# 1.  BPS
**NAME**
bps

**SYNOPSIS**
bps [OPTIONS] [SERVER-ADDRESS] 

**DESCRIPTION**
bps is used to test throughput.
```
  -h, --help				help
  -v, --verbose				show more statistics
  -e, --exact				show exact value
  -i, --interval=SECONDS	report time(default:1s)
  -l, --length=LENGTH 		message length(default:458 max:1024)
  -B, --buffer=BUFFER 		recv buffer size(default:LENGTH max:1024)
  -C, --core=COREMASK		bound core mask HEX(default:0(no bind core))
  -S, --send-only			only send
  -R, --recv-only 			only receive
  -c, --client 			client mode
 Client mode options:
  -t, --time=SECOND 		test time(default:30s)
  -b, --bind=ADDRESS 		bind address
  -p, --parallel=#			parallel number(default:1 max:128)
  -D, --debug				show debug information
  ADDRESS: X.X.X.X:PORT default port:58177
```
**EXAMPLE**
Server: 
```
$./bps 192.168.1.1:6666 -l 1000
```

Client:
```
$./bps -c 192.168.1.1:6666 -l 1000
```

#2. CPS
**NAME**
cps

**SYNOPSIS**
cps [OPTIONS] [SERVER-ADDRESS] 

**DESCRIPTION**
cps is used to test the connection rate.
```
  -i, --interval=#			report time(default: 10s max:3600s)
  -c, --client 				server address list for one thread
  -e, --evnum 				epoll event number(default:256 max:1024)
  -T, --time=# 			 C 	test time(default: 300s max:604800s)
  -d, --data=#[:#] 		 C  request and response data length(default:1:1 max:4096)
  -r, --rate=#[k|m|w] 	 C  global connect rate per each thread(CPS, default: 10000 max:100000000)
  -t, --thread=CONFIG 			  set one net and thread(max: 128)
	  server=X.X.X.X:P 			  server address set(max: 32)
 	  core=# 					  bind to core
 	  client=X.X.X.X 		 C 	  client ip address set(max: 32 max ip: 256)
	  rate=# 				 C 	  set connect rate for this thread(default: use global set)
	  cf 					 C 	  client loop first(default: both)
	  sf 					 C 	  server loop first(default: both)
  -D, --debug 					show debug information
  -m, --more 					show more statistics
  -v, --verbose 				show thread statistics
  -h, --help					help
 IMPORTANT:
  socket()			EMFILE(24) error: ulimit -n 1048576
  bind()		EADDRINUSE(98) error: echo 1 > /proc/sys/net/ipv4/tcp_tw_recycle
  connect() EADDRNOTAVAIL(99) error: echo 1 > /proc/sys/net/ipv4/tcp_tw_reuse
 									 echo "3000 65534" > /proc/sys/net/ipv4/ip_local_port_range
```

**EXAMPLE**
Server: 
```
$./cps -t "server=192.168.1.1:8888"
```
Client:
```
$./cps -c -t "server=192.168.1.1:8888,rate=10"
```

# 3. LP
**NAME**
lp

**SYNOPSIS**
lp [OPTIONS] TEST-SET...

**DESCRIPTION**
lp test multiple connections, connect rate and close rate.
```
  -s, --server LIST 		set one server address list
			X.Y.Z.M-N:P1-P2,...
  -c,  --client LIST 		set one client address list
			CLIENT*SERVER: R.S.T.K-J:Pa-Pb,...*X.Y.Z.M-N:P1-P2,...
			A,B,C,D*1,2		random link
			A,B,C,D=1,2		A1B2C1D2
			A,B,C,D}1,2		A1B1C1D1 A2B2C2D2
			A,B,C,D{1,2		A1A2 B1B2 C1C2 D1D2
  -b, --block 				  set block mode for connecting(client only)
  -n, --nodelay 			  set nodelay
  -i, --interval # 		  report time(default:1s max:60s)
  -m, --core #HEX			  set bind cpu core mask(hex mode)
  -D, --debug 				  show debug information
  -w, --watch 				  show watch time statistic
  -e, --no-error #-#		  skip error
  -E, --error-msg			  show error message
  -C, --no-color			  no color
  -v, --verbose			  show worker statistics
  -h, --help 				  help
 TEST-SET for client
	TARGET@TIME+UP-DOWN=QUERY:REPLY*TIMES-/PERIOD%WAIT 		(client only)
		TARGET 		max connection(default: INFINITE)
 		@TIME 		max time(0 or default:INFINITE)
 		+UP 		connect rate(default: 0 no connnect; *: INFINITE)
 		-DOWN 		close rate(default: 0 no close; *: INFINITE)
		=...		IO set(default: no IO)
 		 QUERY 		send query data len(8-65536)
 		:REPLY 		receive response data len(0-10485760; default: same with QUERY)
 		*TIMES- 	IO times(0 or default: INFINITE; suffix-: IO then close)
 		/PERIOD 	IO period time(0-3600s; default: one by one)
 		%WAIT 		first IO wait time(0-3600s; default: 0 no wait)
 UNITS:
	k=1000 m=1000k g=1000m  w=10000  K=1024 M=1024K G=1024M
 	s=Seconds m=Minutes h=Hours
 	
 =QUERY:REPLY*TIMES-/PERIOD%WAIT
This section set the send/recv action

```
**EXAMPLE**
Server:
```
$./lp -s 192.168.1.1:1000-1999 -s 182.168.1.1:2000-2999
	#each -s start 1 thread, open 1000 fd to listen
```

Client:
```
$./lp -c 192.168.1.100:10000-19999*192.168.1.1:1000-1999 TEST-SET
	#each -c start 1 thread
	#192.168.1.100:10000-19999 is client addresses
	#192.168.1.1:1000-1999 are server addresses
	#TEST-SET is client only, you can set some test case, see options
```

**TEST-SET EXAMPLES**

```
1. $./lp -c 192.168.1.100:10000-19999*192.168.1.1:1000-1999 1m+10k @10s 0-1k
```

Step1: target 1000000 connection, connect rate is 10k/s
Step2: no target, sleep 10 seconds
Step3: target 0 connection, close rate is 1k/s

```
2. $./lp -c 192.168.1.100:10000-19999*192.168.1.1:1000-1999 100000+10k-5k @10s 0-1k
```
Step1: target 100000 connection, both connect and close are execute, connect rate 10k/s, close rate 5k/s

# 4.  TE
**NAME**
te

**SYNOPSIS**
te [OPTIONS] 

**DESCRIPTION**
te is used to test the test the basic functions of IPv6
```
l : v6_tcp_server_listen ( X::X PORT )
L : v6_tcp_server_listen ( X::X PORT )

c : v6_tcp_client_s ( X::X PORT )
s : v6_tcp_server_shutdown_rd ( X::X PORT )
d : v6_tcp_server_shutdown_wr ( X::X PORT )
f : v6_tcp_server_shutdown_rdwr ( X::X PORT )

1 : v4_tcp_client_s ( X.X.X.X PORT )
2 : v4_tcp_server_shutdown_rd ( X.X.X.X PORT )
3 : v4_tcp_server_shutdown_wr ( X.X.X.X PORT )

U : test_v6_udp ( X::X )
u : test_v4_udp ( X.X.X.X )
t : test_v4_tcp ( X.X.X.X )

b : v6_udp_close_select ( X::X PORT )
```

# 5.  IP6
**NAME**
ip6

**SYNOPSIS**
ip6 [OPTIONS] SERVER-ADDRESS 

**DESCRIPTION**
ip6 is used to test the test the basic functions of IPv6
```
  -b, --bind IP.PORT 		  bind address
  -c, --client 		      client mode
  -u, --udp 		          udp mode
  -n, --number # 		   C  packet number(default:LOOP)
  -d, --delay #		   C  seconds wait send next packet(default:1, 0: no delay)
  -l, --length #          C  data length(default:100)
  -o, --output #		      show received data(default:16)
  -D, --debug 	      		  show debug information
  -v, --verbose	 		  show thread statistics
  -h, --help 		 		  help
```
