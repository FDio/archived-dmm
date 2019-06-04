#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <fcntl.h>
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
    out("./server_tcp [server_ip_address] [port number]\n");
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
int compareFiles(FILE * fp1, FILE * fp2)
{

    char ch1 = getc(fp1);
    char ch2 = getc(fp2);
    int error = 0, pos = 0, line = 1;

    while (ch1 != EOF && ch2 != EOF)
    {
        pos++;
        if (ch1 == '\n' && ch2 == '\n')
        {
            line++;
            pos = 0;
        }

        if (ch1 != ch2)
        {
            error++;
            DBG("Line Number : %d \tError" " Position :%d \n", line, pos);
        }

        ch1 = getc(fp1);
        ch2 = getc(fp2);
    }

    //printf("Total Errors : %d\t", error);
    return error;
}

void tcp(char **pArgv)
{

    int sockfd, newsockfd, portno;
    char buff[1024], filename[255];

    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        error("error in socket creation");
    }
    out("socket create successful\n");

    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = atoi(pArgv[2]);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(pArgv[1]);
    serv_addr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
        error("bind fail");
    }
    out("Bind successful\n");
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    if (newsockfd < 0)
    {
        error("error in accept");
    }
    out("socket accept succesful\n");
    bzero(buff, 1024);

    FILE *fp;
    int lSize = 0, totallSize = 0;

    bzero(filename, 255);

    fclose(fopen("receive_file.txt", "w"));
    if (system("chmod +x *") == -1)
    {
        out(" incorrect use of system\n");
    }
    fp = fopen("receive_file.txt", "a");

    if (read(newsockfd, &lSize, sizeof(int)) == -1)
    {
        out("error executing read\n");
    }
    if (read(newsockfd, filename, sizeof(filename)) == -1)
    {
        out("error executing read\n");
    }

    while (lSize > totallSize)
    {
        int bytes_read = 0;
        bzero(buff, 1024);

        bytes_read = read(newsockfd, buff, 1024);

        if (bytes_read == 0)
        {
            break;
        }

        if (bytes_read < 0)
        {
            error("error in Socket read.\n");
        }

#if defined(HEX_CONVERT) && defined(DEBUG)
        DBG("=========================================\n");
        hexconvert(buff, bytes_read);
        DBG("=========================================\n");
#endif
#ifdef DEBUG
        DBG("=========================================\n");
        puts((const char *) buff);
        DBG("=========================================\n");
#endif
        totallSize += bytes_read;

        if (fwrite(buff, 1, bytes_read, fp) == -1)
        {
            error("error in file write\n");
        }
//#if DEBUG
        DBG("Total size of file = %d, Total Bytes sent to socket = %d, bytes_read in each step = %d\n", lSize, totallSize, bytes_read);
//#endif
    }
    out("file name = %s\n", filename);
    out("Final total size of file = %d, total read from socket = %d\n", lSize,
        totallSize);
    out("copy complete\n");
    fclose(fp);

    FILE *fp1 = fopen("receive_file.txt", "r");
    FILE *fp2 = fopen(filename, "r");

    fseek(fp2, 0L, SEEK_END);
    int lfile_size = ftell(fp2);
    rewind(fp2);
    if (lfile_size != lSize)
    {
        out("Size unmatch...\n");
    }
    else
    {
        out("Size match...\n");
    }

    if (compareFiles(fp1, fp2) > 0)
    {
        out("file unmatch...\n");
    }
    else
    {
        out("file match...\n");
    }

    close(newsockfd);
    close(sockfd);
    return;
}

void
run(int sockfd, struct sockaddr *cliaddr, socklen_t clilen, char *res_buf,
    int MAXLINE)
{
    int n, fd;
    socklen_t len;
    char *buf, *buf2;
    FILE *fp1, *fp2;
    buf = malloc(MAXLINE + 1);
    len = clilen;
    n = recvfrom(sockfd, buf, MAXLINE, 0, cliaddr, &len);
    buf[n] = 0;
    out("Received from client:[%s] \n", buf);
    buf2 = malloc(MAXLINE);
    strcpy(buf2, buf);
    sendto(sockfd, "ok", strlen("ok"), 0, cliaddr, len);
    fd = open(buf, O_RDWR | O_CREAT, 0666);
    while ((n = recvfrom(sockfd, buf, MAXLINE, 0, cliaddr, &len)))
    {
        buf[n] = 0;
        //out("%s", buf);
        if (!(strcmp(buf, END_FLAG)))
        {
            break;
        }
        if (write(fd, buf, n) == -1)
        {
            out("error in executing write\n");
        }
    }
    fp1 = fopen(buf2, "r");
    fp2 = fopen(res_buf, "r");

    if (compareFiles(fp1, fp2) == 0)
    {
        out("\nPass:The contents of the files are same");
    }
    else
    {
        out("\nFail:The contents of the files are different");
    }
    close(fd);
}

void udp(char **pArgv)
{
    int sockfd, portno, MAXLINE;
    struct sockaddr_in servaddr, cliaddr;
    char *res_buf;
    res_buf = pArgv[3];

    portno = atoi(pArgv[2]);
    MAXLINE = atoi(pArgv[4]);
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        out("error in socket creation\n");
    }
    out("socket create successful\n");

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(pArgv[1]);
    servaddr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0)
    {
        out("bind fail");
    }
    out("Binded successfully\n");
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);
    int fdmax = sockfd;
    if (FD_ISSET(sockfd, &read_fds))
    {
        run(fdmax, (struct sockaddr *) &cliaddr, sizeof(cliaddr), res_buf,
            MAXLINE);
    }
    return;
}

int main(int argc, char *argv[])
{
    int i, j;
    char **pArgv;
    pArgv = (char **) malloc(sizeof(char *) * 10);
    for (i = 0; i < 10; i++)
    {
        pArgv[i] = (char *) malloc(sizeof(char) * 20);
    }
    if (strcmp("tcp", argv[1]) == 0)
    {
        strcpy(pArgv[0], "tcp");
        /* The arguments of tcp are [server_ip_address] [port number] */
        for (i = 1; i < 3; i++)
        {
            strcpy(pArgv[i], argv[i + 1]);
        }
        tcp(pArgv);
    }
    else if (strcmp("udp", argv[1]) == 0)
    {
        strcpy(pArgv[0], "udp");
        /* The arguments of udp are [server_ip_address] [port number] [filename] [MAX_BUFFER_LENGTH] */
        for (i = 1; i < 5; i++)
        {
            strcpy(pArgv[i], argv[i + 1]);
        }
        udp(pArgv);
    }

    return 0;
}
