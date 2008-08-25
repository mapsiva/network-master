#ifndef UDP_H_
#define UDP_H_
#include "Types.h"
#include <netdb.h>

typedef struct
{
	SWORD src_port;
 	SWORD dest_port;
	SWORD length;
	SWORD checksum;
	BYTE fisrt_data;
}UDP_HEADER;		
	
CHAR_T*
trace_udp( UDP_HEADER *, int);

void
view_data_udp ( UDP_HEADER *);
#endif /*UDP_H_*/
