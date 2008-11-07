/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
*/

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

#include "Xnoop.h"

int check_parameters(int argc, char *argv[], _XNOOP *_x)
{
	int i, aux;
	
	i = 1;
	while(i<argc)
	{
		if (!strcasecmp(argv[i], "-c"))
		{
			if ((i+1) < argc)
			{
				aux = atoi(argv[i+1]);
				if (aux)
					(*_x).npkgs_max = aux;
				else
				{
					printf("\nCorrect sintaxe for option -c is \"-c <number_packages>\"\n");
					return 0;
				}
				if (i >= (*_x).position)
					(*_x).position = i+2;
			}
			else
			{
				printf("\nCorrect sintaxe for option -c is \"-c <number_packages>\"\n");
				return 0;
			}
		}
		else if (!strcasecmp(argv[i], "-n"))
		{
			if (i >= (*_x).position)
				(*_x).position = i+1;
			(*_x).translation = 0;
		}
		else if (!strcmp(argv[i], "-v"))
		{
			if (i >= (*_x).position)
				(*_x).position = i+1;
			(*_x).modo = VERB;
		}
		else if (!strcmp(argv[i], "-V"))
		{
			if (i >= (*_x).position)		
				(*_x).position = i+1;
			(*_x).modo = VERB_EXT;			
		}
		i++;
	}	
	
	return 1;
}

int xnoop(int argc, char *argv[], ETHERNET_HEADER * pkg_ethernet, _XNOOP *_x, INTERFACE ifaces[])
{
    IP_HEADER * pkg_ip;      
	TCP_HEADER * pkg_tcp;
	
	int pkg_broadcast = 0;
		
	/*check_parameters(argc, argv, &translation, &modo, &npkgs_max, &position);*/
	
	if (pkg_ethernet) 
	{	
		(*_x).count[T_ETHER] ++;

		if((*_x).position < argc)
		{			
			if (!filter (pkg_ethernet, argc, argv, (*_x).position))
		    	return 0;
		}

		trace_ethernet (pkg_ethernet, (*_x).npkgs, (*_x).modo, &((*_x).count[T_BROAD]), &pkg_broadcast);		
		
		switch (ntohs (pkg_ethernet->type))
		{
		    case IP:
				(*_x).count[T_IP]++;
		        
		        pkg_ip = (IP_HEADER *)( pkg_ethernet + 1 ); 
		        
		        trace_ip (pkg_ip, (*_x).translation, (*_x).modo, &((*_x).count[T_PKG_ME]), pkg_broadcast, ifaces);
		        
		        switch (pkg_ip->protocol)
		        {
		            case TCP:
		                pkg_tcp = (TCP_HEADER *)(pkg_ip + 1);
		                trace_tcp (pkg_tcp, (*_x).modo);
						(*_x).count[T_TCP]++;
		                break;
		            case UDP:
		                trace_udp ((UDP_HEADER *)(pkg_ip + 1), (*_x).modo);
						(*_x).count[T_UDP]++;
		                break;
		            case ICMP:
		                trace_icmp ((ICMP_HEADER *)(pkg_ip + 1), (*_x).translation , (*_x).modo);
						(*_x).count[T_ICMP]++;
		                break;
		        }
		        break;
		    case ARP:
		        trace_arp ((ARP_HEADER *)(pkg_ethernet + 1), (*_x).translation, (*_x).modo, &((*_x).count[T_PKG_ME]), pkg_broadcast, ifaces);
		       	(*_x).count[T_ARP]++;
		        break;
		}	
	}

	if ((*_x).modo == BASIC)
	{
		printf("ethernet frames: %d\n", (*_x).count[T_ETHER]);
		printf("ethernet broadcast: %d\n", (*_x).count[T_BROAD]);
		printf("ARP: %d\n",(*_x).count[T_ARP]);
		printf("IP: %d\n",(*_x).count[T_IP]);
		printf("ICMP: %d\n",(*_x).count[T_ICMP]);
		printf("UDP: %d\n",(*_x).count[T_UDP]);
		printf("TCP: %d\n",(*_x).count[T_TCP]);
		printf("To this host: %d\n",(*_x).count[T_PKG_ME]);
	}
   	
   	return 1;
}
