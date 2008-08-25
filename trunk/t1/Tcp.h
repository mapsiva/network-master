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
	BYTE fisrt_data;
}TCP_HEADER;		

enum Flags
{
    URG = 0x0020,
    ACK = 0x0010, 
    PSH = 0x0008, 
    RST = 0x0004, 
    SYN = 0x0002, 
    FIN = 0x0001
};

void
view_service( SWORD , int);

	
CHAR_T*
trace_tcp( TCP_HEADER *, int);

void
view_flags ( TCP_HEADER * );

void
view_data ( TCP_HEADER * );

#endif /*TCP_H_*/
