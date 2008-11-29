/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ci�ncia da Computa��o DCT - UFMS
	Redes de Computadores 2008
	
	M�rcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef IP_H_
#define IP_H_
#include "Types.h"
#include <arpa/inet.h> 
#include <pthread.h>
#include <semaphore.h>

/*
 * acesso ao semaforo,
 * */
sem_t allow_route_entry;

/*
 * ping running
 * */
 

typedef struct
{
    BYTE version;
    BYTE type_service;
    SWORD total_length;
    SWORD identification;
    SWORD fragment;
    BYTE time_alive;
    BYTE protocol;
    SWORD checksum;
    WORD source_address;
    WORD destination_address;
}IP_HEADER;

struct in_addr addr;
struct hostent *resolved;

CHAR_T*
trace_ip( IP_HEADER *, int, int, int*, int, INTERFACE []);

CHAR_T*
resolve_address( WORD ) ;

CHAR_T*
format_address( WORD ) ;

void
ip_view_service (IP_HEADER * );

char * get_precedence_name( SWORD );

void
ip_view_flags ( IP_HEADER * );

int 
ip_is_broadcast(WORD *) ;

/*
* Entrada da tabela de Roteamnto com seus respectivos campos
*/
typedef struct tRouteTableEntry
{
    WORD *TARGET;
    WORD *GATEWAY;
    WORD *MASK;
    int COST;
    BYTE interface;
    int TTL;    
    struct tRouteTableEntry* next;
}RouteTableEntry;

/*
*  tabela de Roteamnto, estrututa de controle para a tabela
*/
typedef struct
{
    int length;
    struct tRouteTableEntry *list ;
}RouteTable;

/*
* Busca uma entrada na tabela de Roteamnto, caso sucesso retorna a entrada, caso contrário retorna NULL
*/
RouteTableEntry * 
FindRouteTableEntry( RouteTable * table, RouteTableEntry * entry, int current);

RouteTableEntry *
FindRouteTableEntry2( RouteTable * table, RouteTableEntry * entry, int current );

RouteTableEntry *
FindProxNo( RouteTable * table, WORD _ip);

/*
*constrói uma entrada para a tabela de Roteamento
*/
RouteTableEntry * 
BuildRouteTableEntry( CHAR_T*, CHAR_T* , CHAR_T*, int, BYTE,  int);

/*
*Adiciona uma entrada na tabela de Roteamento
*/
void  
AddRouteTableEntry( RouteTable * table, RouteTableEntry * entry);

/*
*Remove uma entrada da tabela de Roteamento
*/
RouteTableEntry *
RemoveRouteTableEntry( RouteTable * table, RouteTableEntry * entry );

/*
*Instancia uma tabela de Roteamento
*/
RouteTable * 
BuildRouteTable();

/*
*Imprime toda a tabela de Roteamento na tela
*/
void 
DisplayRouteTable (RouteTable * table);

/*
* Destrói uma tabela de Roteamento
*/
void 
FlushRouteTable (RouteTable * table);
#endif 
