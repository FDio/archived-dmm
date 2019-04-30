#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <ctype.h>
char *END_FLAG = "=================END";
#define HEXCONVERT_COLS 8
#define HEX_CONVERT 1
//#define DEBUG 1
#define out(fmt, arg...) (void)printf(fmt, ##arg)

#ifdef DEBUG
#define DBG(fmt, arg...) do { \
                out("[Debug] " fmt, ##arg); \
 } while (0)
#else
#define DBG(fmt, arg...) ((void)0)
#endif

void error(const char *msg)
{
    perror(msg);
    out("./client_tcp [server_ip_address] [port number] [filename] [client_ip_address]\n");
    exit(1);
}

#if defined(HEX_CONVERT) && defined(DEBUG)
void hexconvert(void *mem, unsigned int len)
{
    unsigned int i;

    for (i = 0;
         i <
         len +
         ((len % HEXCONVERT_COLS) ? (HEXCONVERT_COLS -
                                     len % HEXCONVERT_COLS) : 0); i++)
    {
        /* print offset */
        if (i % HEXCONVERT_COLS == 0)
        {
            DBG("\n0x%06x: ", i);
        }

        /*print hex data */
        if (i < len)
        {
            DBG("%02x ", 0xFF & ((char *) mem)[i]);
        }
        else                    /* end of block, just aligning for ASCII dump */
        {
            DBG("\n");
        }
    }
}
#endif

void tcp(char **pArgv)
{

    int sockfd, portno;
    char buff[1024];

    struct sockaddr_in serv_addr, cli_addr;
    struct hostent *server;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        error("error in socket creation\n");
    }
    out("socket create successful\n");

    portno = atoi(pArgv[2]);
    server = gethostbyname(pArgv[1]);

    if (server == NULL)
    {
        fprintf(stderr, "error no such host\n");
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *) server->h_addr, (char *) &serv_addr.sin_addr,
          server->h_length);
    serv_addr.sin_port = htons(portno);
    bzero((char *) &cli_addr, sizeof(serv_addr));

    cli_addr.sin_family = AF_INET;
    cli_addr.sin_addr.s_addr = inet_addr(pArgv[4]);
    cli_addr.sin_port = htons(portno);
    if (bind(sockfd, (struct sockaddr *) &cli_addr, sizeof(cli_addr)) < 0)
    {
        error("bind fail");
    }
    out("Bind successful\n");

    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) <
        0)
    {
        error("connection fail");
    }
    out("connection done\n");

    FILE *file;
    int filebyte = 0;
    int lsize, totalsize = 0;

    file = fopen(pArgv[3], "r");
    fseek(file, 0, SEEK_END);
    lsize = ftell(file);
    rewind(file);
    out("Name of file: %s, Size of file : %d\n", pArgv[3], lsize);
    if (write(sockfd, &lsize, sizeof(int)) == -1)
    {
        out("error executing write\n");
    }
    if (write(sockfd, pArgv[3], 255) == -1)
    {
        out("error executing write\n");
    }
    while (lsize > totalsize)
    {
        bzero(buff, 1024);
        fseek(file, totalsize, SEEK_SET);
        filebyte = fread(buff, 1, sizeof(buff), file);
        if (filebyte == 0)
        {
            printf("file End of file\n");
            break;
        }

        if (filebyte < 0)
            error("error in reading file. \n");
#if defined(HEX_CONVERT) && defined(DEBUG)
        DBG("=========================================\n");
        hexconvert(buff, filebyte);
        DBG("=========================================\n");
#endif

        void *p = buff;
        totalsize += filebyte;

        while (filebyte > 0)
        {
#ifdef DEBUG
            DBG("=========================================\n");
            puts((const char *) p);
            DBG("=========================================\n");
#endif
            int bytes_written = write(sockfd, p, filebyte);
            if (bytes_written <= 0)
            {
                error("error in Socket write.\n");
            }

            filebyte -= bytes_written;
            p += bytes_written;
//#if DEBUG
            DBG("Total size of file = %d, Total Bytes sent to socket = %d, bytes_written in each step = %d\n", lsize, totalsize, bytes_written);
//#endif
        }
    }
    out("file has been sent successfully\n");
    out("Final Total size of file = %d, Total Bytes sent to socket = %d\n",
        lsize, totalsize);

    fclose(file);
    sleep(60);
    close(sockfd);
    return;
}

void udp(char **pArgv)
{
    int sockfd, n, fd, sz, portno, MAXLINE;
    FILE *fp;
    struct sockaddr_in servaddr, cliaddr;
    char *buf;
    char *target, *path;
    portno = atoi(pArgv[2]);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(portno);
    servaddr.sin_addr.s_addr = inet_addr(pArgv[1]);
    bzero(&cliaddr, sizeof(servaddr));
    cliaddr.sin_family = AF_INET;
    cliaddr.sin_port = htons(portno);
    cliaddr.sin_addr.s_addr = inet_addr(pArgv[3]);
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        out("error in socket creation\n");
    }
    out("socket create successful\n");

    if (bind(sockfd, (struct sockaddr *) &cliaddr, sizeof(cliaddr)) < 0)
    {
        out("bind fail");
    }
    out("Bind successful\n");

    path = pArgv[4];
    target = pArgv[5];
    MAXLINE = atoi(pArgv[6]);
    buf = malloc(MAXLINE * sizeof(int));
    fp = fopen(path, "r");
    fseek(fp, 0L, SEEK_END);
    sz = ftell(fp);
    out("The size of the path file is %d", sz);
    sendto(sockfd, target, strlen(target), 0,
           (struct sockaddr *) &servaddr, sizeof(servaddr));
    n = recvfrom(sockfd, buf, MAXLINE, 0, NULL, NULL);
    if (!strncmp(buf, "ok", 2))
    {
        out("Filename sent.\n");
    }

    fd = open(path, O_RDONLY);
    while ((n = read(fd, buf, MAXLINE)) > 0)
    {
        sendto(sockfd, buf, n, 0, (struct sockaddr *) &servaddr,
               sizeof(servaddr));
    }
    sendto(sockfd, END_FLAG, strlen(END_FLAG), 0,
           (struct sockaddr *) &servaddr, sizeof(servaddr));
    fclose(fp);
    sleep(60);
    close(sockfd);
    return;
}

int main(int argc, char *argv[])
{
    int i;
    char **pArgv, str[10];
    pArgv = (char **) malloc(sizeof(char *) * 10);
    for (i = 0; i < 10; i++)
    {
        pArgv[i] = (char *) malloc(sizeof(char) * 20);
    }
    printf("%s", argv[1]);

    if (strcmp("tcp", argv[1]) == 0)
    {
        strcpy(pArgv[0], "tcp");
        printf("pArgv[0]=%s", pArgv[0]);
        /* The arguments of tcp are [server_ip_address] [port number] [filename] [client_ip_address] */
        for (i = 1; i < 5; i++)
        {
            strcpy(pArgv[i], argv[i + 1]);
        }
        tcp(pArgv);
    }

    else
    {
        strcpy(str, argv[1]);
        if (strcmp("udp", str) == 0)
        {
            strcpy(pArgv[0], "udp");
            printf("pArgv[0]=%s", pArgv[0]);
            /* The arguments of udp are [server_ip_address] [port number] [client_ip_address] [filename] [target_filename] [MAX_BUFFER_LENGTH] */
            for (i = 1; i < 7; i++)
            {
                strcpy(pArgv[i], argv[i + 1]);
            }
            udp(pArgv);
        }
    }
    return 0;
}
