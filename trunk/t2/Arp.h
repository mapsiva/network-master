/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ci�ncia da Computa��o DCT - UFMS
	Redes de Computadores 2008
	
	M�rcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef ARP_H_
#define ARP_H_
#include "Types.h"
#include "Util.h"
#include <netdb.h>
#include <pthread.h>
#include <semaphore.h>

/*
 * acesso ao semaforo
 * */
sem_t allow_entry;

typedef struct  
{
    SWORD hardware_type;
    SWORD protocol_type;
    BYTE hardware_len;
    BYTE protocol_len;
    SWORD operation;
    BYTE sender_hardware_addr[6];
    WORD sender_ip_addr;
    BYTE target_hardware_addr[6];
    WORD target_ip_addr;
} ARP_HEADER;

typedef struct tArpTableEntry
{
    DWORD *MAC;
    WORD *IP;
    int TTL;    
    struct tArpTableEntry* next;
}ArpTableEntry;

typedef struct
{
    int length;
    struct tArpTableEntry *list ;
}ArpTable;

ArpTableEntry * 
FindArpTableEntry( ArpTable * table, ArpTableEntry * entry, int current);

ArpTableEntry * 
BuildArpTableEntry( CHAR_T*,CHAR_T* , int);

void * 
AddArpTableEntry( ArpTable * table, ArpTableEntry * entry);

void * 
RemoveArpTableEntry( ArpTable * table, ArpTableEntry * entry );

ArpTable * BuildArpTable();

void 
DisplayArpTable (ArpTable * table);

void 
FlushArpTable (ArpTable * table);

CHAR_T*
trace_arp( ARP_HEADER *, int, int, int);

void 
view_type_arp ( ARP_HEADER *);

#endif /*ARP_H_*/
