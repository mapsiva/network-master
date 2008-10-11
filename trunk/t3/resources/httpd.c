#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
/* */
#define SERVER_PORT	5000
#define QLEN		5
/* */
int perror_exit(char *msg)
{
    perror(msg);
    exit(1);
    return 0;
}
/* */
int passiveTCPsocket(int port, int qlen)
{
    struct sockaddr_in sin;
    int sockd;
    
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons((u_short)port);

    if ((sockd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
	perror_exit("socket: ");
    
    if (bind(sockd, (struct sockaddr *)&sin, sizeof(sin)) < 0) 
		perror_exit("bind: ");
    
    if (listen(sockd, qlen) < 0) 
	perror_exit("listen: ");
    return sockd;
}
/* */
void httpd(int port)
{
    int msock;			/* master socket descriptor	*/
    int ssock;			/* slave socket descriptor	*/
    unsigned int alen;		/* from-address length		*/
    struct sockaddr_in fsin;	/* address of a client		*/
    pid_t ppid;
    
    msock = passiveTCPsocket(port, QLEN);
    while(1) {
		alen = sizeof(struct sockaddr_in);
		ssock = accept(msock, (struct sockaddr *)&fsin, &alen);
		if (ssock  < 0) 
		    perror_exit("accept: ");	
		ppid = fork();
		if (ppid == 0) {
		    /* It's in the child process */
		    printf("It'is in the child process\n");
		    close(msock);
		    getchar();
		    if (execv("/bin/date", NULL) < 0) 
				perror_exit("execv");
		}
		else {
		    /* It's in the parent process */
		    printf("It'is in the parent process\n");
		    ppid = fork();
		    if (ppid == 0) {
				char bc;
				close(msock);
				while (read(ssock, &bc, sizeof(bc)))
				    printf("%c", bc);
				close(ssock);
				exit(1);
		    }
		    else		
			close(ssock);	    
		}
    }
}
/* */
int main(int argc, char *argv[])
{
    int port;
    
    switch(argc) {
    case 1: 
	port = SERVER_PORT;
	break;
    case 2:
	port = atoi(argv[1]);
	break;
    default:
	printf("\nUsage: httpd [port]\n");
	exit(1);
    }
    httpd(port);
    
    return 0;
}
