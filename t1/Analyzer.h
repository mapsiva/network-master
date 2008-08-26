#ifndef ANALYZER_H_
#define ANALYZER_H_
#include "Types.h"

CHAR_T * _current;

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
token();

#endif 
