#ifndef ANALYZER_H_
#define ANALYZER_H_
#include "Types.h"

char * _current;

enum _tokens
{
    _NUMBER     = 0,
    _HEXA,
    _ADDRESS_IP,
    _MAC,
    _EQ,
    _AND,
    _OR,
    _NOT,
    _OPERATOR,
    _IP,
    _UDP,
    _TCP,
    _ICMP,
    _ARP,
    _ETHERTO,
    _ETHERFROM,
    _ETHERTYPE,
    _IPTO,
    _IPFROM,
    _IPPROTO,
    _UDPTOPORT,
    _UDPFROMPORT,
    _TCPTOPORT,
    _TCPFROMPORT,
    _ICMPTYPE
};


Token *
token( CHAR_T* argv);

int
is_ip( CHAR_T * );

int
is_hexa ( CHAR_T * );

DWORD *
to_ip_byte( CHAR_T * );

int
is_key_word( CHAR_T * );
#endif 
