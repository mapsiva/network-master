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
    view_type_icmp ( pkg );
    printf("ICMP: code = %u\n", pkg->code);
    printf("ICMP: Cheksum = %04X\n", ntohs(pkg->checksum));
    printf("ICMP:\n\n");
    return 0;
}

void
view_type_icmp ( ICMP_HEADER * pkg)
{
    printf("ICMP: Type = %u ", pkg->type);
    
    switch (pkg->type)
    {
        case ECHO_REPLAY:
             printf("(Echo Reply)");
            break;
        case DESTINATION_UN:
            printf("(Destination Unreachable)");
            break;
        case SOURCE_QUENCH:
            printf("(Source Quench)");
            break;
        case REDIRECT:
            printf("(Redirect)");
            break;
        case ECHO_REQUEST:
            printf("(Echo Request)");
            break;
        case ROUTER_AD:
            printf("(Router advertisement)");
            break;
        case ROUTER_SOL:
             printf("(Router Solicitation)");
            break;
        case TTL:
             printf("(TTL exceeded)");
            break;
        case PP:
             printf("(Parameter Problem)");
            break;
        case TIMESTAMP_REQUEST:
              printf("(Timestamp Request)");
            break;
        case TIMESTAMP_REPLY:
             printf("(Timestamp Reply)");
            break;
        case INFO_REQUEST:
             printf("(Information Request)");
            break;
        case INFO_REPLY:
             printf("(Information Reply)");
            break;
        case ADDRESS_MASK_REQUEST:
             printf("(Address Mask Request)");
            break;
        case ADDRESS_MASK_REPLY:
            printf("(Address Mask Reply)");
            break;
        default:
            printf("(Unknow code)");
        
    
    }
    printf("\n");
}

#endif
