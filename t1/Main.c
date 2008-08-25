#include <stdlib.h>
#include <netinet/in.h>
#include "PackageHeader.h"
#include "Ethernet.h"
#include "Tcp.h"
#include "Ip.h"
#include "Udp.h"
#include "Icmp.h"

#define BUF_SIZE	2000
char byte_order; /* 0=little, 1=big endian*/

FILE_HEADER file_header;
FRAME_HEADER frame_header;

char pkt_buf[BUF_SIZE];

int main(int argc, char *argv[])
{
	FILE *inf;
	ETHERNET_HEADER * pkg_ethernet;
    IP_HEADER * pkg_ip;      
	TCP_HEADER * pkg_tcp;
	 
	int qtd_pkt 		= 0;
	int count_pkt_ether = 0;
	int count_pkt_arp 	= 0;
	int count_pkt_ip 	= 0;
	int count_pkt_icmp 	= 0;
	int count_pkt_udp 	= 0;
	int count_pkt_tcp 	= 0;

	int modo = 1;	/*inicializa o modo com 1 indicando o modo de funcionamento BASICO*/
    
    /*A execucao do programa está passando parâmetros [opcoes] ou [filtros]*/
    if (argc > 2)
    {
    	if (argv[2][0] == '-')
    	{
    		switch (argv[2][1])
    		{
    			case 'f':
    				break;
    			case 'v':
    				modo = VERB;
    				break;
    			case 'V':
    				modo = VERB_EXT;
    				break;
    			case 'c':
    				break;
    		}
    	}
    }

	inf = fopen(argv[1], "rb");
	
	if (!inf) 
		error_exit("Could not open file: %s\n", argv[1]);	

	/* read file header */
	fread(&file_header, sizeof(FILE_HEADER), 1, inf);
	
	if (file_header.magic_number != 0xa1b2c3d4) 
		invert_file_header(&file_header);
	
	while (fread(&frame_header, sizeof(FRAME_HEADER), 1, inf)) 
	{
		if (file_header.magic_number != 0xa1b2c3d4) 
			invert_pkt_header(&frame_header);
		
		/*Le o conteudo do pacote*/
		fread(pkt_buf, frame_header.capt_data, 1, inf);
		qtd_pkt ++;
		/*Capturando um pacote ethernet*/
		pkg_ethernet = (ETHERNET_HEADER *)pkt_buf;
		/*trace_ethernet (pkg_ethernet, qtd_pkt,  &frame_header);*/
		/*Verifica o tipo do pacote ethernet*/
		switch (ntohs(pkg_ethernet->type))
		{
		    case IP:
				count_pkt_ip++;
		        /*Determina o inicio do cabecalho IP
		        * Deslocando sizeof (pkg_ethernet) +1, da posicao atual de pkg_ethernet
		        */
		        
		        pkg_ip = (IP_HEADER *)( pkg_ethernet + 1 ); 
		        
		       /* trace_ip (pkg_ip);*/
		        
		        switch (pkg_ip->protocol)
		        {
		            case TCP:
		                pkg_tcp = (TCP_HEADER *)(pkg_ip + 1);
		                /*trace_tcp (pkg_tcp);*/
						count_pkt_tcp++;
		                break;
		            case UDP:
		                /*trace_udp ((UDP_HEADER *)(pkg_ip + 1));*/
						count_pkt_udp++;
		                break;
		            case ICMP:
		                trace_icmp ((ICMP_HEADER *)(pkg_ip + 1));
						count_pkt_icmp++;
		                break;
		        }
		        break;
		    case ARP:
		       	count_pkt_arp++;
		        break;
		}
		
		/*trace_ethernet ( pkg_ethernet, ++count_pkt_ether, &frame_header );*/		
	}
	
	/*Impressão das informações no caso do funcionamento básico (Só deve imprimir estas informações se o modo for igual a BASIC)*/	
	if (modo == BASIC)
	{
		printf("\n");
		printf("ethernet frames: %d\n", count_pkt_ether);
		/*printf("ethernet broadcast: %d", count_pkt_broad);*/
		printf("ARP: %d\n",count_pkt_arp);
		printf("IP: %d\n",count_pkt_ip);
		printf("ICMP: %d\n",count_pkt_icmp);
		printf("UDP: %d\n",count_pkt_udp);
		printf("TCP: %d\n",count_pkt_tcp);
		/*printf("To this host: %d",count_pkt_me);*/
	}
   	
   	return 0;
}
