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
trace_ip( IP_HEADER *, int, int, int*, int);

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

#endif 
