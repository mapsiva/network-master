/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Cincia da Computao DCT - UFMS
	Redes de Computadores 2008
	
	Mrcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef IP_C_
#define IP_C_
#include "Types.h"
#include "Ip.h"	
#include "Util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

CHAR_T*
trace_ip( IP_HEADER * pkg, int translation, int modo, int *pkg_for_me, int broadcast, INTERFACE ifaces[])
{
    CHAR_T *ip, *name;   
    
    if (modo == VERB_EXT)
    {
		printf("IP: ----- IP Header -----\n");
		printf("IP:\n");
		printf("IP: Version = %u, header length = %u bytes\n", IP_VER(pkg), IP_IHL(pkg));
		
		ip_view_service(pkg);

		printf("IP: Total length = %u bytes\n", ntohs(pkg->total_length));
		printf("IP: Identification = %u \n", ntohs(pkg->identification));
		
		ip_view_flags(pkg);
		
		printf("IP: Fragment offset = %u bytes \n", IP_OFFSET(pkg));
		printf("IP: Time to alive = %u seconds/hops \n", (pkg->time_alive));
		printf("IP: Protocol = %u (%s)\n", (pkg->protocol), ((pkg->protocol==ICMP)?"ICMP":(pkg->protocol==TCP)?"TCP":"UDP"));
		printf("IP: Header ckecksum = %X \n", ntohs(pkg->checksum));

		ip = format_address(pkg->source_address);
		printf("IP: Source address      = %s", ip );
		free (ip);
		if (translation && (name = resolve_address(pkg->source_address)) != NULL )
		{
			printf(", %s", name);
			free(name);
		}
		printf("\n");	

		ip = format_address(pkg->destination_address);
		printf("IP: Destination address = %s", ip);
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
		
		if (broadcast)
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
	else /* modo == BASIC */
    {
		if(pkg->destination_address == ifaces[0].ip)
			(*pkg_for_me)++;
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
    
    sprintf((char *)ip, "%u.%u.%u.%u", *IP, *(IP+1), *(IP+2), *(IP+3));
    
    return ip;
}

void
ip_view_flags (IP_HEADER * pkg)
{  
	printf("IP: Flags =  0x%X \n", (pkg->fragment & 0x0060) >> 5);
	printf("IP: \t.%d.. .... = %s fragment\n", (pkg->fragment & BIN64) >> 6, ((pkg->fragment & BIN64) >> 6)?"don't":"may");
	printf("IP: \t..%d. .... = %s fragment\n", (pkg->fragment & BIN32) >> 5, ((pkg->fragment & BIN32) >> 5)?"more":"last");
}

void
ip_view_service (IP_HEADER * pkg)
{ 
	printf("IP: Type of service = 0x%02X \n", pkg->type_service);
	printf("IP: \t%u%u%u. .... = %s\n", (pkg->type_service & BIN128) >> 7, (pkg->type_service & BIN64) >> 6, (pkg->type_service & BIN32) >> 5, get_precedence_name(pkg->type_service));
	printf("IP: \t...%d .... = %s delay\n", (pkg->type_service & BIN16) >> 4, ((pkg->type_service & BIN16) >> 4)?"low":"normal");
	printf("IP: \t.... %d... = %s throughput\n", (pkg->type_service & BIN8) >> 3, ((pkg->type_service & BIN8) >> 3)?"high":"normal");
	printf("IP: \t.... .%d.. = %s relibility\n", (pkg->type_service & BIN4) >> 2, ((pkg->type_service & BIN4) >> 2)?"high":"normal");
}

int 
ip_is_broadcast (WORD *ip)
{
    return (*ip == 255) && (*(ip+1) == 255) && (*(ip+2) == 255) && (*(ip+3) == 255);
}

char * get_precedence_name(SWORD service)
{
	char *text = NULL;
	int aux;
	
	aux = service >> 5;
		
	switch(aux)
	{
		case 0:
			text="Routine";
		break;

		case 1:
			text="Priority";
		break;

		case 2:
			text="Immediate";
		break;

		case 3:
			text="Flash";
		break;

		case 4:
			text="Flash Override";
		break;

		case 5:
			text="CRITIC/ECP";
		break;

		case 6:
			text="Internetwork Control";
		break;

		case 7:
			text="Network Control";
	}	
	return text;
}

/*
* @param IP Ip da maquina
* @param MAC mac da maquina
* @param TTL tempo de vida da entrada
* 
* @return ArpTableEntry* retorna um ponteiro para a entrada criada
* 
* @since           2.0
*/


RouteTableEntry * BuildRouteTableEntry( CHAR_T* TARGET, CHAR_T* GATEWAY , CHAR_T* MASK, BYTE interface,  int TTL)
{
	 RouteTableEntry * _entry =  (RouteTableEntry *) malloc(sizeof(RouteTableEntry));
	 
	 _entry->TARGET =  	(WORD *)to_ip_byte ( TARGET );
	 _entry->MASK = 	(WORD *)to_ip_byte ( MASK );
	 _entry->GATEWAY = 	(WORD *)to_ip_byte ( GATEWAY );
	 _entry->interface = interface;
	 _entry->TTL = TTL;
	 _entry->next = NULL;
	 return _entry;
}

/*
* @param void
* @since           2.0
*/

RouteTable *
BuildRouteTable()
{
	 RouteTable * _table =  (RouteTable *) malloc(sizeof(RouteTable));
     
     _table->list = NULL;
     
     _table->length = 0;
     
     return _table;
}
/* Funcao que imprime a tabela de Roteamento na tela
 * 
 * @param void
 * @return void
 */
void DisplayRouteTable (RouteTable * table)
{
	RouteTableEntry *_entry = table->list;
	printf ("Destino\t\t\t Gateway\t\t Máscara\t\t Interface\t TTL\n");
	while (_entry)
	{
		printf ("%s\t\t\t %s\t\t %s\t\t %d\t %d\n", format_address((DWORD)*(_entry->TARGET)), 
											 format_address((DWORD)*(_entry->GATEWAY)),
											 format_address((DWORD)*(_entry->MASK)), 
											 (int)_entry->interface,
											 _entry->TTL);
		
		_entry = _entry->next;
	}
	
}


/*
* Busca um elemento na tabela de Roteamento baseado no valor do IP
* @param table ponteiro para a tabela de Roteamento
* @param entry uma entrada da tabela de roteamento que se deseja encontrar
* @param current flag que indica para funcao retornar o elemento corrente (1) na busca ou seu anterior(0)
*
* @return NULL ou uma entrada valida na tabela de Roteamento
*
* @since           2.0
*/
RouteTableEntry *
FindRouteTableEntry( RouteTable * table, RouteTableEntry * entry, int current )
{
	RouteTableEntry *_entry = table->list;
	
	while ( _entry )
	{
		
		if(current && *(_entry->TARGET) == *(entry->TARGET))
			break;
		else if(!current && _entry->next && *(_entry->next->TARGET) == *(entry->TARGET))
			break;
		else if(!current && *(table->list->TARGET) == *(entry->TARGET))	
			break;
		_entry = _entry->next;
	}
	return _entry;
	
}

/*
* @param table ponteiro para a tabela de Roteamento
* @param entry uma entrada da tabela de roteamento que se deseja adicionar
*
* @return void
*
* @since           2.0
*/

void AddRouteTableEntry( RouteTable * table, RouteTableEntry * entry)
{
	RouteTableEntry *_entry;
	
	if( !(_entry = FindRouteTableEntry (table, entry ,1)))
	{
		entry->next = table->list;
		
		table->list = entry;
		
		table->length ++;
	}
	else
		_entry->TTL = entry->TTL;
}

/*
* Remove um elemento da tabela de Roteamento
*
* @param table ponteiro para a tabela de Roteamento
* @param entry uma entrada da tabela de roteamento que se deseja remover
*
* @return NULL ou uma entrada valida na tabela de Roteamento
*
* @since           2.0
*/

RouteTableEntry * 
RemoveRouteTableEntry( RouteTable * table, RouteTableEntry * entry )
{
	RouteTableEntry *_entry = NULL, *_remove = NULL;
	
	if(!table->length)
		return NULL;		
	
	if( (_entry = FindRouteTableEntry (table, entry, 0 )))
	{
		if(_entry == table->list)
		{
			_remove = table->list; 
			table->list = table->list->next;
		}
		else
		{	
			_remove = _entry->next;
			_entry->next = _remove->next;
		}
		table->length --;		
	}
	
	return _remove;
}

/*
* Destrói a tabela de Roteamento
* @param table ponteiro para a tabela de Roteamento
*
* @return void
*
* @since           2.0
*/
void 
FlushRouteTable (RouteTable * table)
{
    RouteTableEntry *_remove,  *_entry = table->list;
    
    while (_entry)
    {
        _remove = _entry;
        
        _entry = _remove->next;
        
        free (_remove);
    }
    
    table->length = 0;
}

#endif 
