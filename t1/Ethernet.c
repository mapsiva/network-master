#ifndef ETHERNET_C_
#define ETHERNET_C_
#include "Ethernet.h"
#include "PackageHeader.h"
#include <stdio.h>

CHAR_T*
trace_ethernet(ETHERNET_HEADER* eth, int ID,  FRAME_HEADER *frh)
{ 
	printf ("ETHER: ----- Ether Header -----\n");
	printf ("ETHER:\n");
	printf ("ETHER: Packet %d\n", ID);
	printf ("ETHER: Packet size = %u\n", (unsigned int) frh->capt_data);
	printf ("ETHER: Destination  = %.02X:%02X:%02X:%02X:%02X:%.02X\n", eth->sender[0], eth->sender[1], eth->sender[2], eth->sender[3], eth->sender[4], eth->sender[5]);	
	printf ("ETHER: Source       = %02X:%02X:%02X:%02X:%02X:%02X\n", eth->receiver[0], eth->receiver[1], eth->receiver[2], eth->receiver[3], eth->receiver[4], eth->receiver[5]);
	printf ("ETHER: Ethertype %04X\n",(unsigned int) ntohs(eth->type));
	printf ("ETHER:\n\n");
	return 0;
}
#endif 
