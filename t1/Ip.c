#ifndef IP_C_
#define IP_C_
#include "Types.h"
#include "Ethernet.h"
#include "Ip.h"	
#include "Util.h"	
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

CHAR_T*
trace_ip( IP_HEADER * pkg, int translation, int modo)
{
    CHAR_T *ip, *name;
    
    if (modo == VERB_EXT)
    {
		printf("IP: ----- IP Header -----\n");
		printf("IP:\n");
		printf("IP: Version = %u, header length = %u bytes\n", IP_VER(pkg), IP_IHL(pkg));
		printf("IP: Type of service = 0x%X \n", pkg->type_service);

		printf("IP: \t.... ....  \n");
		printf("IP: \t.... ....  \n");
		printf("IP: \t.... ....  \n");
		printf("IP: \t.... ....  \n");

		printf("IP: Total length =  %u bytes\n", ntohs(pkg->total_length));
		printf("IP: Identification =  %u \n", ntohs(pkg->identification));
		
		ip_view_flags(pkg);
		
		printf("IP: Fragment offset =  %u bytes \n", IP_OFFSET(pkg));
		printf("IP: Time to alive =  %u seconds/hops \n", (pkg->time_alive));
		printf("IP: Protocol =  %u (%s)\n", (pkg->protocol), ((pkg->protocol==ICMP)?"ICMP":(pkg->protocol==TCP)?"TCP":"UDP"));
		printf("IP: Header ckecksum =  %X \n", ntohs(pkg->checksum));

		ip = format_address(pkg->source_address);
		printf("IP: Source address =  %s", ip );
		free (ip);
		if (translation && (name = resolve_address(pkg->source_address)) != NULL )
		{
			printf(", %s", name);
			free(name);
		}
		printf("\n");	

		ip = format_address(pkg->destination_address);
		printf("IP: Destination address =  %s", ip);
		free (ip);
		if (translation && (name = resolve_address(pkg->destination_address)) != NULL )
		{			
			printf(", %s", name);
			free(name);
		}
		printf("\n");	
	}
	else if(modo == VERB)
	{
		
		if (translation && (name = resolve_address(pkg->source_address)) != NULL )
		{
			printf("%s -> ", name);
			free(name);
		}
		else
		{
			ip = format_address(pkg->source_address);
			printf("%s -> ", ip );
			free (ip);
		}
		
		if (ip_is_broadcast(&pkg->destination_address))
		{
			if (translation)
				printf("(brodcast) ");
			else
			{
				ip = format_address(pkg->destination_address);
				printf("%s ", ip );
				free (ip);
			}
		}
		else if (translation && (name = resolve_address(pkg->destination_address)) != NULL )
		{
			printf("%s ", name);
			free(name);
		}
		else
		{
			ip = format_address(pkg->destination_address);
			printf("%s ", ip );
			free (ip);
		}
		
		printf ("%s ", (pkg->protocol==1)?"ICMP":(pkg->protocol==6)?"TCP":"UDP");
	}
    return 0;
}

/*Fun*/
CHAR_T*
resolve_address(WORD  address) 
{   
     CHAR_T * name;
     
     name = NULL;
    
     resolved = gethostbyaddr((unsigned char*)&address,  sizeof (address), AF_INET);
     
     if(resolved)
     {
     	name = (CHAR_T*) malloc (100);
        sprintf((char *)name, "%s", resolved->h_name);
     }
     
     return name;
}

CHAR_T*
format_address(WORD  address) 
{
    CHAR_T * IP = (CHAR_T *) &address,  *ip;
    
    ip = (CHAR_T*) malloc (16);
    
    sprintf((char *)ip, "%u.%u.%u.%u", *IP, *IP+1, *IP+2, *IP+3);
    
    return ip;
}

void
ip_view_flags ( IP_HEADER * pkg)
{  
	printf("IP: Flags =  0x%02x \n", pkg->fragment & 0x0040);
	printf("IP: \t.%d.. .... = %s fragment\n", (pkg->fragment & 0x0040) >> 6, ((pkg->fragment & 0x0040) >> 6)?"don't":"may");
	printf("IP: \t..%d. .... = %s fragment\n", (pkg->fragment & 0x0020) >> 5, ((pkg->fragment & 0x0020) >> 5)?"more":"last");
}

int 
ip_is_broadcast(WORD *ip)
{
    return (*ip == 255) && (*(ip+1) == 255) && (*(ip+2) == 255) && (*(ip+3) == 255) ;
}

#endif 
