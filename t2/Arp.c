/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef ARP_C_
#define ARP_C_
#include "Arp.h"
#include "Ip.h"
#include "Types.h"
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>

CHAR_T*
trace_arp( ARP_HEADER * pkg, int translation, int modo, int broadcast)
{
    CHAR_T *ip, *name;
    if (modo == VERB_EXT)
    {
		printf("ARP: ----- ARP Header -----\n");
		printf("ARP:\n");
		printf("ARP: Hardware Type = %u\n", ntohs(pkg->hardware_type));
		printf("ARP: Protocol Type = 0x%04X %s\n", ntohs(pkg->protocol_type), (ntohs(pkg->protocol_type) == IP)?"(IP)":" ");
		printf("ARP: Length of hardware address = %u bytes\n", pkg->hardware_len);
		printf("ARP: Length of protocol address = %u bytes\n", pkg->protocol_len);
		printf("ARP: Opcode %u (%s)\n", ntohs(pkg->operation), (ntohs(pkg->operation) == ARP_REQUEST)?"Echo Request":"Echo Reply");

		printf ("ARP: Sender’s hardware address \t= %.02X:%02X:%02X:%02X:%02X:%.02X\n", pkg->sender_hardware_addr[0], pkg->sender_hardware_addr[1], pkg->sender_hardware_addr[2], pkg->sender_hardware_addr[3], pkg->sender_hardware_addr[4], pkg->sender_hardware_addr[5]);	

		ip = format_address(pkg->sender_ip_addr);
		printf("ARP: Sender’s protocol address  = %s", ip );
		free (ip);
		if (translation && (name = resolve_address(pkg->sender_ip_addr)) != NULL )
		{
			printf(", %s", name);
			free(name);
		}
		
		printf ("\nARP: Target hardware address \t= %02X:%02X:%02X:%02X:%02X:%02X\n", pkg->target_hardware_addr[0], pkg->target_hardware_addr[1], pkg->target_hardware_addr[2], pkg->target_hardware_addr[3], pkg->target_hardware_addr[4], pkg->target_hardware_addr[5]);

		ip = format_address(pkg->target_ip_addr);
		printf("ARP: Target protocol address    = %s", ip );
		free (ip);
		if (translation && (name = resolve_address(pkg->target_ip_addr)) != NULL )
		{
			printf(", %s", name);
			free(name);
		}
		printf("\nARP:\n\n");
	}
	else if (modo == VERB)
	{
		/*Resolving IP or Name of Source*/
		if (translation && (name = resolve_address(pkg->sender_ip_addr)) != NULL )
		{
			printf("%s -> ", name);
			free(name);
		}
		else
		{
			ip = format_address(pkg->sender_ip_addr);
			printf("%s -> ", ip );
			free (ip);
		}
		
		/*Resolving IP or Name of Target*/
		if (broadcast)
		{
			if (translation)
				printf("(brodcast) ");
			else
			{
				ip = format_address(pkg->target_ip_addr);
				printf("%s ", ip );
				free (ip);
			}
		}
		else if (translation && (name = resolve_address(pkg->target_ip_addr)) != NULL )
		{
			printf("%s", name);
			free(name);
		}
		else
		{
			ip = format_address(pkg->target_ip_addr);
			printf("%s ", ip );
			free (ip);
		}		
		printf ("ARP ");
		
		if (ntohs(pkg->operation) == ARP_REQUEST)
		{
			printf("Who-has ");
			
			ip = format_address(pkg->target_ip_addr);
			printf("%s ", ip );
			free (ip);
			
			printf("tell ");
			
			ip = format_address(pkg->sender_ip_addr);
			printf("%s ", ip );
			free (ip);
		}
		else	/*pkg->operation == ECHO_REPLY*/
		{
			printf("Reply ");
			
			ip = format_address(pkg->sender_ip_addr);
			printf("%s ", ip );
			free (ip);
			
			printf("is-at %02X:%02X:%02X:%02X:%02X:%02X", pkg->sender_hardware_addr[0], pkg->sender_hardware_addr[1], pkg->sender_hardware_addr[2], pkg->sender_hardware_addr[3], pkg->sender_hardware_addr[4], pkg->sender_hardware_addr[5]);			
		}
		printf("\n");
	}
    return 0;
}

#endif
