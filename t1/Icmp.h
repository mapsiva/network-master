#ifndef ICMP_H_
#define ICMP_H_
#include "Types.h"
#include <netdb.h>

typedef struct
{
	BYTE type;
 	BYTE code;
	SWORD checksum;
}ICMP_HEADER;		

enum Types
{
    ECHO_REPLAY             = 0,
    DESTINATION_UN          = 3,
    SOURCE_QUENCH           = 4,
    REDIRECT                = 5,
    ECHO_REQUEST            = 8,
    ROUTER_AD               = 9,
    ROUTER_SOL              = 10,
    TTL                     = 11,
    PP                      = 12,
    TIMESTAMP_REQUEST       = 13,
    TIMESTAMP_REPLY         = 14,
    INFO_REQUEST            = 15,
    INFO_REPLY              = 16,
    ADDRESS_MASK_REQUEST    = 17,
    ADDRESS_MASK_REPLY      = 18
};

CHAR_T*
trace_icmp( ICMP_HEADER *);

void 
view_type_icmp ( ICMP_HEADER *);

#endif /*ICMP_H_*/
