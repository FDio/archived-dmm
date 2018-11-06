# Introduction 
DMM (Dual Mode, Multi-protocol, Multi-instance) is to implement a transport agnostic framework for network
applications that can
1. Work with both user space and kernel space network stacks
2. Use different network protocol stacks based on their functional and performance requirements (QOS)
3. Work with multiple instances of a transport protocol stack.

Following demo directory demonstrates some of these features of DMM.
Procedures and details of how to run this demo is inside each demo directory.

##demo-1

This demo use NGINX as a reverse proxy server. The server uses lwip as client facing stack and kernel tcp/ip
stack as upstream server facing stack.

##demo-2 

This demo NGINX as a reverse proxy server. The server uses lwip as client facing stack and kernel tcp/ip stack 
as upstream server facing stack for UDP, vpp-hoststack for another updtream server facing stack for TCP.