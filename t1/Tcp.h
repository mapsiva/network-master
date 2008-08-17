#ifndef TCP_H_
#define TCP_H_
#include "Types.h"

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

CHAR_T*
trace_tcp();


#endif /*TCP_H_*/
