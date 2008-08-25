#ifndef ETHERNET_C_
#define ETHERNET_C_
#include "Ethernet.h"
#include "PackageHeader.h"
#include <stdio.h>
#include <netinet/in.h>

CHAR_T*
trace_ethernet(ETHERNET_HEADER* eth, int ID,  FRAME_HEADER *frh)
{ 
	printf ("ETHER: ----- Ether Header -----\n");
	printf ("ETHER:\n");
	printf ("ETHER: Packet %d\n", ID);
	printf ("ETHER: Packet size = %u bytes\n", (unsigned int) frh->capt_data);
	
		
	
	printf ("ETHER: Destination \t= %02X:%02X:%02X:%02X:%02X:%02X %s\n", eth->receiver[0], eth->receiver[1], eth->receiver[2], eth->receiver[3], eth->receiver[4], eth->receiver[5], (is_broadcast(eth->receiver)?"(brodcast)":""));
	
	printf ("ETHER: Source \t\t= %.02X:%02X:%02X:%02X:%02X:%.02X\n", eth->sender[0], eth->sender[1], eth->sender[2], eth->sender[3], eth->sender[4], eth->sender[5]);	
	printf ("ETHER: Ethertype %04X %s\n",(unsigned int) ntohs(eth->type), ((unsigned int) ntohs(eth->type) == 0x800)?"(IP)":"(ARP)");
	printf ("ETHER:\n");
	return 0;
}


int 
is_broadcast(BYTE * byte)
{
    return (*byte == 0xFF) && (*(byte+1) == 0xFF) && (*(byte+2) == 0xFF) && (*(byte+3) == 0xFF) && (*(byte+4) == 0xFF) && (*(byte+5) == 0xFF) ;
}
#endif 
