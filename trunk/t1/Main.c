#include <stdlib.h>
#include <netinet/in.h>
#include "PackageHeader.h"
#include "Ethernet.h"
#include "Tcp.h"
#include "Ip.h"
#include "Udp.h"
#include "Icmp.h"
#include "Arp.h"
#include "Analyzer.h"
#include "Stack.h"
#include "Types.h"
#include "Filter.h"

#include <strings.h>

#define BUF_SIZE	2000
char byte_order; /* 0=little, 1=big endian*/

FILE_HEADER file_header;
FRAME_HEADER frame_header;

char pkt_buf[BUF_SIZE];

int check_parameters(int argc, char *argv[], int *translation, int *modo, unsigned long *npkgs, int *position)
{
	int i, aux;
	
	if (argc < 2) 
		error_exit("Correct sintaxe is \"xnoop <filename> [<options>] [<filter>]\"\n");
	
	i = 2;
	while(i<argc)
	{
		if (!strcasecmp(argv[i], "-c"))
		{
			if ((i+1) < argc)
			{
				aux = atoi(argv[i+1]);
				if (aux)
					(*npkgs) = aux;
				else
					error_exit("Correct sintaxe for option -c is \"-c <number_packages>\"\n");
				if (i >= *position)
					(*position) = i+2;
			}
			else
				error_exit("Correct sintaxe for option -c is \"-c <number_packages>\"\n");
		}
		else if (!strcasecmp(argv[i], "-n"))
		{
			if (i >= *position)
				(*position) = i+1;
			(*translation) = 0;
		}
		else if (!strcmp(argv[i], "-v"))
		{
			if (i >= *position)
				(*position) = i+1;
			(*modo) = VERB;
		}
		else if (!strcmp(argv[i], "-V"))
		{
			if (i >= *position)			
				(*position) = i+1;
			(*modo) = VERB_EXT;			
		}
		i++;
	}	
	
	return 0;
}

int main(int argc, char *argv[])
{
	FILE *inf;
	ETHERNET_HEADER * pkg_ethernet;
    IP_HEADER * pkg_ip;      
	TCP_HEADER * pkg_tcp;
	
	int qtd_pkt 		= 0;	
	int count_pkt_arp 	= 0;
	int count_pkt_ip 	= 0;
	int count_pkt_icmp 	= 0;
	int count_pkt_udp 	= 0;
	int count_pkt_tcp 	= 0;
	int count_pkt_broad = 0;
	int count_pkt_me	= 0;

	
	int is_broadcast;
	int modo = 1;							/*indica o modo de funcionamento (BASIC)*/
	int translation = 1;					/*indica que será utilizado a traducao de nomes*/
	int position = 2;						/*indica a posicao da lista de parâmetros que começam os filtros */
	
	unsigned long npkgs_max = 100000;		/*indica a quantidade máxima de pacotes a serem analisados*/	
	unsigned long npkgs = 1;
	is_broadcast = 0;	
	
	check_parameters(argc, argv, &translation, &modo, &npkgs_max, &position);
    
    /*######################################################*/
	inf = fopen(argv[1], "rb");
	
	
<<<<<<< .mine

=======
	for (i = position; i < argc; i++)
	{   
	      
	    Token *token = Advance ((CHAR_T *)argv[i]);
	   
	    push (stack, token); 
	   
	}

	//return 0;
	if (!inf) 
		error_exit("Could not open file: %s\n", argv[1]);	

	/* read file header */
	fread(&file_header, sizeof(FILE_HEADER), 1, inf);
	
	if (file_header.magic_number != 0xa1b2c3d4) 
		invert_file_header(&file_header);
	
	while (fread(&frame_header, sizeof(FRAME_HEADER), 1, inf) && npkgs <= npkgs_max) 
	{
		
		
		
		
		if (file_header.magic_number != 0xa1b2c3d4) 
			invert_pkt_header(&frame_header);
		
		/*Le o conteudo do pacote*/
		fread(pkt_buf, frame_header.capt_data, 1, inf);
		qtd_pkt ++;
		
		/*Capturando um pacote ethernet*/
		pkg_ethernet = (ETHERNET_HEADER *)pkt_buf;

		
		if(!filter (pkg_ethernet, argc, argv, position))
		    exit(0);
		
		npkgs++;

		trace_ethernet (pkg_ethernet, qtd_pkt,  &frame_header, modo, &count_pkt_broad, &is_broadcast);

		
		/*Verifica o tipo do pacote ethernet*/
		switch (ntohs (pkg_ethernet->type))
		{
		    case IP:
				count_pkt_ip++;
		        /*Determina o inicio do cabecalho IP
		        * Deslocando sizeof (pkg_ethernet) +1, da posicao atual de pkg_ethernet
		        */
		        
		        pkg_ip = (IP_HEADER *)( pkg_ethernet + 1 ); 
		        
		        trace_ip (pkg_ip, translation, modo, &count_pkt_me, is_broadcast);
		        
		        switch (pkg_ip->protocol)
		        {
		            case TCP:
		                pkg_tcp = (TCP_HEADER *)(pkg_ip + 1);
		                trace_tcp (pkg_tcp,modo);
						count_pkt_tcp++;
		                break;
		            case UDP:
		                trace_udp ((UDP_HEADER *)(pkg_ip + 1), modo);
						count_pkt_udp++;
		                break;
		            case ICMP:
		                trace_icmp ((ICMP_HEADER *)(pkg_ip + 1), translation , modo);
						count_pkt_icmp++;
		                break;
		        }
		        break;
		    case ARP:
		        trace_arp ((ARP_HEADER *)(pkg_ethernet + 1), translation, modo, is_broadcast);
		       	count_pkt_arp++;
		        break;
		}	
	}
	
	/*Impressão das informações no caso do funcionamento básico (Só deve imprimir estas informações se o modo for igual a BASIC)*/	

	if (modo == BASIC)
	{
		printf("ethernet frames: %d\n", qtd_pkt);
		printf("ethernet broadcast: %d\n", count_pkt_broad);
		printf("ARP: %d\n",count_pkt_arp);
		printf("IP: %d\n",count_pkt_ip);
		printf("ICMP: %d\n",count_pkt_icmp);
		printf("UDP: %d\n",count_pkt_udp);
		printf("TCP: %d\n",count_pkt_tcp);
		printf("To this host: %d\n",count_pkt_me);
	}
   	
   	return 0;
}
