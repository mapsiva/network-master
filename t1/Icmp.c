#ifndef ICMP_C_
#define ICMP_C_
#include "Icmp.h"
#include "Types.h"
#include <netdb.h>
#include <stdio.h>

CHAR_T*
trace_icmp( ICMP_HEADER * pkg )
{
    printf("ICMP: ----- ICMP Header -----\n");
    printf("ICMP:\n");
    printf("ICMP: Type = %u\n", pkg->type);
    printf("ICMP: code = %u\n", pkg->code);
    printf("ICMP: Cheksum = %04X\n", ntohs(pkg->checksum));
    printf("ICMP:\n\n");
    return 0;
}

#endif
