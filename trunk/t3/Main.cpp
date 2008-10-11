#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "Httpd.h"
#include "Util.h"

int main(int argc , char *argv[])
{
	int port = _SERVER_PORT;
	int qtd_threads = 0;
	int modo;
	Httpd *server;
		
	if (argc >= 2 && argc <= 4)
	{
		if(!strncasecmp(argv[1], "-T", 2))
		{
			modo = _HTTP_THREAD;
			if (argc > 2)
			{
				qtd_threads = atoi(argv[2]);	//capturando a qtd de threads do pool de threads
				if (argc > 3)
					port = atoi(argv[3]);	//capturando o número da porta de escuta (a porta padrão é a SERVER_PORT)		
			}
			else
			{
				printf("\nUsage: httpd -t [N] ([port])\n");
				exit(1);
			}
		}
		else if(!strncasecmp(argv[1], "-F", 2))
		{
			modo = _HTTP_PROCESS;
			if (argc == 3)
				port = atoi(argv[2]);	//capturando o número da porta de escuta (a porta padrão é a SERVER_PORT)					
		}
		server = new Httpd(modo, qtd_threads, port);
		server->Start();
	}
	else
	{
		printf("\nUsage: httpd [-f|-t] [N] ([port])\n");
		exit(1);
	}   
	return 0;
}
