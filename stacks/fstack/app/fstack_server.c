#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "dmm_pub_api.h"
#define PORT 8080

int server_fd;
struct sockaddr_in address;
int
loop (void *arg)
{
  int new_socket, valread;
  int addrlen = sizeof (address);
  char buffer[1024] = { 0 };
  char hello[1024] = { 0 };
  sprintf (hello, "Hello from server\t PROC_ID : %d", getpid ());
  printf ("before accept\n");
  if ((new_socket = accept (server_fd, (struct sockaddr *) &address,
                            (socklen_t *) & addrlen)) < 0)
    {
      printf ("accept failed");
      return -1;
    }

  printf ("accept success\n");
  valread = read (new_socket, buffer, 1024);
  printf ("%s\n", buffer);
  send (new_socket, hello, strlen (hello), 0);
  printf ("Hello message sent\n");
  return 0;
}

int
main (int argc, char *argv[])
{

  int opt = 1;
  int addrlen = sizeof (address);
#if 0
  if (-1 == nstack_conf (argc, argv))
    {
      printf ("nstack_conf failed\n");
      return -1;
    }
#endif
  if ((server_fd = socket (AF_INET, SOCK_STREAM, 0)) == 0)
    {
      printf ("socket failed\n");
      exit (EXIT_FAILURE);
    }
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = inet_addr ("172.28.128.13");
  address.sin_port = htons (PORT);

  // Forcefully attaching socket to the port 8080
  if (bind (server_fd, (struct sockaddr *) &address, sizeof (address)) < 0)
    {
      printf ("bind failed");
      exit (EXIT_FAILURE);
    }
  printf ("bind success\n");
  if (listen (server_fd, 3) < 0)
    {
      printf ("listen");
      exit (EXIT_FAILURE);
    }
  printf ("listen success\n");
  nstack_run ((void *) loop);
  return 0;
}
