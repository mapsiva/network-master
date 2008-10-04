#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "Httpd.h"
#include "Util.h"

Httpd::Httpd(int modo, int qtd_t, int port) 
{
	_modo = modo;
	_qtd_threads = qtd_t;
	_port = port;
}

int Httpd::PassiveTCPSocket()
{
    struct sockaddr_in sin;
    int sockd, reusage = 1;
    
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons((u_short)_port);

    if ((sockd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		perror_exit("Socket error");
	
	setsockopt(sockd, SOL_SOCKET, SO_REUSEADDR, &reusage, sizeof(reusage));
    
    if (bind(sockd, (struct sockaddr *)&sin, sizeof(sin)) < 0) 
		perror_exit("Bind error");
    
    if (listen(sockd, _QLEN) < 0) 
		perror_exit("Listen error");
	
    return sockd;
}

void Httpd::Run()
{
	int msock;					/* master socket descriptor	*/
    int ssock;					/* slave socket descriptor	*/
    unsigned int alen;			/* from-address length		*/
    struct sockaddr_in fsin;	/* address of a client		*/
    pid_t ppid;					/* id of process			*/
    
    msock = PassiveTCPSocket();
    	printf("sockect criado \n");
    while(1) {
		alen = sizeof(struct sockaddr_in);
		printf("escutando porta \n");   
		ssock = accept(msock, (struct sockaddr *)&fsin,(socklen_t *) &alen);
		printf("client conected \n");   
		if (ssock  < 0) 
		    perror_exit("accept: ");
		
		//Verificando o tipo de funcionamento do Servidor HTTP 
		if (_modo == _HTTP_PROCESS)
		{
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
		//else //_modo == _HTTP_THREAD
		//{}
    }
}
