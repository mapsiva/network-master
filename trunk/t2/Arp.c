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
#include "Util.h"
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
		printf("ARP: Protocol Type = 0x%04X %s\n", ntohs(pkg->protocol_type), (ntohs(pkg->protocol_type) == IP)?"(IP)":"");
		printf("ARP: Length of hardware address = %u bytes\n", pkg->hardware_len);
		printf("ARP: Length of protocol address = %u bytes\n", pkg->protocol_len);
		printf("ARP: Opcode %u (%s)\n", ntohs(pkg->operation), (ntohs(pkg->operation) == ARP_REQUEST)?"Echo Request":((ntohs(pkg->operation) == ARP_REPLY)?"Echo Reply":""));

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
/*
* @param IP Ip da maquina
* @param MAC mac da maquina
* @param TTL tempo de vida da entrada
* 
* @return ArpTableEntry* retorna um ponteiro para a entrada criada
* 
* @since           2.0
*/


ArpTableEntry * BuildArpTableEntry( CHAR_T* IP, CHAR_T* MAC , int TTL)
{
	 ArpTableEntry * _entry =  (ArpTableEntry *) malloc(sizeof(ArpTableEntry));
	 
	 _entry->IP =  (WORD *)to_ip_byte ( IP);
	 _entry->MAC = to_mac_byte ( MAC );
	 _entry->TTL = TTL;
	 _entry->next = NULL;
	 return _entry;
}

/*
* @param void
* @since           2.0
*/

ArpTable *
BuildArpTable()
{
	 ArpTable * _table =  (ArpTable *) malloc(sizeof(ArpTable));
     
     _table->list = NULL;
     
     _table->length = 0;
     
     return _table;
}
/* Funcao que imprime a tabela ARP na tela
 * 
 * @param void
 * @return void
 */
void DisplayArpTable (ArpTable * table)
{
	
	
	ArpTableEntry *_entry = table->list;
	int seq = 0;
	printf ("\nEntrada\t\t\t Endereco IP\t\t Endereco Ethernet\tTTL\n");
	while (_entry)
	{
		printf ("%d\t\t\t %s\t\t %s\t %d\n", seq++ ,format_address((DWORD)*(_entry->IP)), format_mac_address((DWORD)*(_entry->MAC)), _entry->TTL);
		
		_entry = _entry->next;
	}
	
}


/*
* @param table ponteiro para a tabela arp
* @param entry uma entrada da table  arp que se deseja encontrar
* @param current flag que indica para funcao retornar o elemento corrente na busca ou seu anterior
*
* @return NULL ou uma entrada valida na tabela ARP
*
* @since           2.0
*/
ArpTableEntry *
FindArpTableEntry( ArpTable * table, ArpTableEntry * entry, int current )
{
	
	
	ArpTableEntry *_entry = table->list;
	
	while ( _entry )
	{
		
		if(current && *(_entry->IP) == *(entry->IP))
			return _entry;
		else if(!current && _entry->next && *(_entry->next->IP) == *(entry->IP))
			return _entry;
			
		_entry = _entry->next;
	}
	
	return NULL;
}
void * AddArpTableEntry( ArpTable * table, ArpTableEntry * entry)
{
	ArpTableEntry *_entry;
	
	if( !(_entry = FindArpTableEntry (table, entry ,1)))
	{
		entry->next = table->list;
		
		table->list = entry;
		
		table->length ++;
	}
	else
	{	
		_entry->IP = entry->IP;
		_entry->MAC = entry->MAC;
		_entry->TTL = entry->TTL;
	}
	
	return _entry;
}
void * RemoveArpTableEntry( ArpTable * table, ArpTableEntry * entry )
{
	ArpTableEntry *_entry, *_remove;
	
	if(!table->length)
		return NULL;
	
	if(table->length == 1)	
	{
		_remove = table->list;
		
		table->list = NULL;
		
	}	
	
	else if( (_entry = FindArpTableEntry (table, entry, 0 )))
	{
		_remove = _entry->next;
		_entry->next = _remove->next;
		
	}
	
	table->length --;
	
	return _remove;
}

void 
FlushArpTable (ArpTable * table)
{
    ArpTableEntry *_remove,  *_entry = table->list;
    
    while (_entry)
    {
        _remove = _entry;
        
        _entry = _remove->next;
        
        free (_remove);
    }
    
    table->length = 0;
}

#endif
