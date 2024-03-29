/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Subnet
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

/*
* Impressão do cabeçalho ARP
*/
CHAR_T*
trace_arp( ARP_HEADER * pkg, int translation, int modo, int *pkg_for_me, int broadcast, INTERFACE ifaces[])
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
	else /* modo == BASIC */
	{
		if(pkg->target_ip_addr == ifaces[0].ip)
			(*pkg_for_me)++;
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
	 if (MAC)
	 	_entry->MAC = to_mac_byte ( MAC );
	 else
	 	_entry->MAC = NULL;
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
* Busca um elemento na tabela ARP baseado no valor do IP
* @param table ponteiro para a tabela arp
* @param entry uma entrada da table  arp que se deseja encontrar
* @param current flag que indica para funcao retornar o elemento corrente (1) na busca ou seu anterior(0)
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
			break;
		else if(!current && _entry->next && *(_entry->next->IP) == *(entry->IP))
			break;
		else if(!current && *(table->list->IP) == *(entry->IP))	
			break;
		_entry = _entry->next;
	}
	return _entry;
	
}

/*
* @param table ponteiro para a tabela arp
* @param entry uma entrada da table  arp que se deseja adicionar
*
* @return void
*
* @since           2.0
*/

void AddArpTableEntry( ArpTable * table, ArpTableEntry * entry)
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
}

/*
* Remove um elemento da tabela arp
*
* @param table ponteiro para a tabela arp
* @param entry uma entrada da table  arp que se deseja remover
*
* @return NULL ou uma entrada valida na tabela ARP
*
* @since           2.0
*/

ArpTableEntry * 
RemoveArpTableEntry( ArpTable * table, ArpTableEntry * entry )
{
	ArpTableEntry *_entry = NULL, *_remove = NULL;
	
	if(!table->length)
		return NULL;		
	
	if( (_entry = FindArpTableEntry (table, entry, 0 )))
	{
		if(_entry == table->list && *(entry->IP) == *(_entry->IP))  //Remover o primeiro elemento da lista
		{
			_remove = table->list; 
			table->list = (table->list)->next;
		}
		else if (_entry == table->list)	//Remover segundo elemento da lista
		{
			_remove = _entry->next; 
			(table->list)->next = _remove->next;
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
* Destrói a tabela ARP
* @param table ponteiro para a tabela arp
*
* @return void
*
* @since           2.0
*/
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
