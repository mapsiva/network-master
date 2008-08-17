#include <stdlib.h>
#include "PackageHeader.h"
#include "Ethernet.h"
#include "Tcp.h"
#include "Ip.h"


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
	int counter_package = 1;

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
		
		/*Capturando um pacote ethernet*/
		pkg_ethernet = (ETHERNET_HEADER *)pkt_buf;
		
		/*Verifica o tipo do pacote ethernet*/
		switch (ntohs(pkg_ethernet->type))
		{
		    case IP:
		        /*Determina o inicio do cabecalho IP
		        * Deslocando sizeof (pkg_ethernet) +1, da posicao atual de pkg_ethernet
		        */
		        
		        pkg_ip = (IP_HEADER *)( pkg_ethernet + 1 ); 
		        
		        trace_ip (pkg_ip);
		        
		        switch (pkg_ip->protocol)
		        {
		            case TCP:
		                break;
		            case UDP:
		                break;
		            case ICMP:
		                break;
		        }
		        break;
		    case ARP:
		       
		        break;  	
		}
		
		/*trace_ethernet ( pkg_ethernet, counter_package++, &frame_header );*/
		
		
	}
   return 0;
}
