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
 * acesso ao semaforo,
 * */
sem_t allow_entry;

/*
* Cabeçalho ARP
*/
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

/*
* Entrada da tabela ARP com seus respectivos campos
*/
typedef struct tArpTableEntry
{
    DWORD *MAC;
    WORD *IP;
    int TTL;    
    struct tArpTableEntry* next;
}ArpTableEntry;

/*
*  tabela ARP, estrututa de controle para a tabela
*/
typedef struct
{
    int length;
    struct tArpTableEntry *list ;
}ArpTable;

/*
* Busca uma entrada na tabela ARP, caso sucesso retorna a entrada, caso contrário retorna NULL
*/
ArpTableEntry * 
FindArpTableEntry( ArpTable * table, ArpTableEntry * entry, int current);

/*
*constrói uma entrada para a tabela ARP
*/
ArpTableEntry * 
BuildArpTableEntry( CHAR_T*,CHAR_T* , int);

/*
*Adiciona uma entrada na tabela ARP
*/
void  
AddArpTableEntry( ArpTable * table, ArpTableEntry * entry);

/*
*Remove uma entrada da tabela ARP
*/
ArpTableEntry *
RemoveArpTableEntry( ArpTable * table, ArpTableEntry * entry );

/*
*Instancia uma tabela ARP
*/
ArpTable * 
BuildArpTable();

/*
*Imprime toda a tabela ARP na tela
*/
void 
DisplayArpTable (ArpTable * table);

/*
* Destrói uma tabela ARP
*/
void 
FlushArpTable (ArpTable * table);

/*
* Imprime um cabeçalho ARP
*/
CHAR_T*
trace_arp( ARP_HEADER *, int, int, int);

/*
* Visualiza o campo Type do pacote ARP
*/
void 
view_type_arp ( ARP_HEADER *);

#endif /*ARP_H_*/
