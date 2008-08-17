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
    WORD options;
}IP_HEADER;		

CHAR_T*
trace_ip( IP_HEADER *);

int
resolve_address(WORD  address, CHAR_T *ip) ;


#endif 
