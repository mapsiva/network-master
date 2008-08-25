#ifndef IP_H_
#define IP_H_
#include "Types.h"

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
trace_ip( IP_HEADER *, int, int);

CHAR_T*
resolve_address( WORD ) ;

CHAR_T*
format_address( WORD ) ;

int 
ip_is_broadcast(WORD *) ;

#endif 
