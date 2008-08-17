#ifndef ETHERNET_H_
#define ETHERNET_H_
#include "Types.h"
#include "PackageHeader.h"

typedef struct
{
	BYTE receiver[6];
	BYTE sender[6];
	SWORD type;
}ETHERNET_HEADER;		

CHAR_T*
trace_ethernet(ETHERNET_HEADER *, int,  FRAME_HEADER *); 



#endif /*ETHERNET_H_*/
