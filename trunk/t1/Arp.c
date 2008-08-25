#ifndef ARP_C_
#define ARP_C_
#include "Arp.h"
#include "Ip.h"
#include "Ethernet.h"
#include "Types.h"
#include <netdb.h>
#include <stdio.h>

CHAR_T*
trace_arp( ARP_HEADER * pkg )
{
    printf("ARP: ----- ARP Header -----\n");
    printf("ARP:\n");
    printf("ARP: Hardware Type = %u\n", ntohs(pkg->hardware_type));
    printf("ARP: Protocol Type = %04X %s\n", ntohs(pkg->protocol_type), (ntohs(pkg->protocol_type) == 0x0800)?"(IP)":" ");
    printf("ARP: Length of hardware address = %u bytes\n", pkg->hardware_len);
    printf("ARP: Length of protocol address = %u bytes\n", pkg->protocol_len);
    printf("ARP: Opcode %u (%s)\n", ntohs(pkg->operation), (ntohs(pkg->operation) == 1)?"Echo Request":"Echo Reply");
    
    printf ("ARP: Sender’s hardware address = %.02X:%02X:%02X:%02X:%02X:%.02X\n", pkg->sender_hardware_addr[0], pkg->sender_hardware_addr[1], pkg->sender_hardware_addr[2], pkg->sender_hardware_addr[3], pkg->sender_hardware_addr[4], pkg->sender_hardware_addr[5]);	
    
    printf ("ARP: Target hardware address = %02X:%02X:%02X:%02X:%02X:%02X %s\n", pkg->target_hardware_addr[0], pkg->target_hardware_addr[1], pkg->target_hardware_addr[2], pkg->target_hardware_addr[3], pkg->target_hardware_addr[4], pkg->target_hardware_addr[5], (is_broadcast(pkg->target_hardware_addr)?"(brodcast)":""));
	
	
    printf("ARP:\n\n");
    return 0;
}

#endif
