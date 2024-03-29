#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include "Httpd.h"
#include "Util.h"
#include "FileManager.h"
#include "Mime.h"
#include "Thread.h"
#include "Config.h"

Httpd::Httpd(int modo, int qtd_t, int port)
{
	_modo = modo;
	_qtd_threads = qtd_t;
	_port = port;
	Config::Config();
}

void *
Httpd::Kill_Defuncts()
{
	int status;
	while (wait3(&status, WNOHANG, (struct rusage *) 0) > 0)
	{	//printf("matando defuntos\n");
	}
	return 0;
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

void Httpd::Start()
{
	Run();
}

void Httpd::Run()
{
	int msock;					/* master socket descriptor	*/
    int ssock;					/* slave socket descriptor	*/
    unsigned int alen;			/* from-address length		*/
    struct sockaddr_in fsin;	/* address of a client		*/
    pid_t ppid;					/* id of process			*/
    
    msock = PassiveTCPSocket();
    
    printf("Server Running.\n");
   
    Thread ** Pool = new Thread*[_qtd_threads];
   	int I= 0;

    while(1) 
    {
		alen = sizeof(struct sockaddr_in);
		ssock = accept(msock, (struct sockaddr *)&fsin,(socklen_t *) &alen);
		if (ssock  < 0)
		    perror_exit("Error Accept: ");
		char *queryString;
		char bc[1024];	
	    read(ssock, bc, sizeof(bc));
	    queryString =  strtok (bc, " ");
    	queryString =  strtok (NULL, " ");
    	
		FileManager *f = new FileManager(queryString, &ssock);    
		
		//Verificando o tipo de funcionamento do Servidor HTTP 
		if (_modo == _HTTP_PROCESS)
		{			
			ppid = fork();
			if (ppid == -1)
				perror_exit("Error Process:");
			else if (ppid == 0) 
			{
				//interpreta o sinal SIGCHLD
				//Tem que ver pq não está funfando
				signal(SIGCHLD,(sighandler_t)Httpd::Kill_Defuncts);
		
			    close(msock);
				f->Write();
				delete f;
			    close(ssock);
			    exit(1);
			}
			else		    
				close(ssock);	    
		}
		else
		{
			if(Thread::_Instances >= _qtd_threads)
				printf("Pool Overflow \n");
			else
			{
				Pool[(I%_qtd_threads)+1] = new Thread(f, &ssock);
				Pool[(I%_qtd_threads)+1]->Start(NULL);				
				I++;
			}
		} //_modo == _HTTP_THREAD
		
    }
}
