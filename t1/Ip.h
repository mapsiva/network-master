/*

    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	IP HEADER

*/

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

void
ip_view_service (IP_HEADER * );

char * get_precedence_name( SWORD );

void
ip_view_flags ( IP_HEADER * );

int 
ip_is_broadcast(WORD *) ;

#endif 
