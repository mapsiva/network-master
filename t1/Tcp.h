#ifndef TCP_H_
#define TCP_H_
#include "Types.h"
#include <netdb.h>

typedef struct
{
	SWORD src_port;
 	SWORD dest_port;
	WORD seq_number_port;
	WORD ack;
	SWORD offset;
	SWORD window;
	SWORD checksum;
	SWORD urgent_pointer;
	WORD options;
}TCP_HEADER;		


void
view_service( SWORD );

	
CHAR_T*
trace_tcp( TCP_HEADER *);


#endif /*TCP_H_*/
