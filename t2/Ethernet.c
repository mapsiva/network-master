/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef ETHERNET_C_
#define ETHERNET_C_
#include "Ethernet.h"
#include "Arp.h"
#include "PackageHeader.h"
#include <stdio.h>
#include <netinet/in.h>

CHAR_T*
trace_ethernet(ETHERNET_HEADER* eth, int ID,  int modo, int *pkg_broadcast, int *broadcast)
{
	if (modo == VERB_EXT)
	{
		printf ("ETHER: ----- Ether Header -----\n");
		printf ("ETHER:\n");
		printf ("ETHER: Packet %d\n", ID);
		
		printf ("ETHER: Packet size = %u bytes\n", sizeof(ETHERNET_HEADER)+ sizeof(ETHERNET_PKT)+sizeof(ARP_HEADER));
			
		printf ("ETHER: Destination = %02X:%02X:%02X:%02X:%02X:%02X %s\n", eth->receiver[0], eth->receiver[1], eth->receiver[2], eth->receiver[3], eth->receiver[4], eth->receiver[5], (is_broadcast(eth->receiver)?"(brodcast)":""));	
		printf ("ETHER: Source      = %.02X:%02X:%02X:%02X:%02X:%.02X\n", eth->sender[0], eth->sender[1], eth->sender[2], eth->sender[3], eth->sender[4], eth->sender[5]);	
		printf ("ETHER: Ethertype 0x%04X %s\n",(unsigned int) ntohs(eth->type), ((unsigned int) ntohs(eth->type) == IP)?"(IP)":(((unsigned int) ntohs(eth->type) == ARP)?"(ARP)":""));
		printf ("ETHER:\n");
	}
	if (is_broadcast(eth->receiver))
	{
		(*pkg_broadcast) = (*pkg_broadcast) + 1;
		(* broadcast) = 1;
	}
	else
		(* broadcast) = 0;
	return 0;
}

int 
is_broadcast(BYTE * byte)
{
    return (*byte == 0xFF) && (*(byte+1) == 0xFF) && (*(byte+2) == 0xFF) && (*(byte+3) == 0xFF) && (*(byte+4) == 0xFF) && (*(byte+5) == 0xFF) ;
}
#endif 
