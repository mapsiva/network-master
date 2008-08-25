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
	
CHAR_T*
trace_icmp( ICMP_HEADER *);


#endif /*ICMP_H_*/
