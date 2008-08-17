#include "PackageHeader.h"
#include "Ethernet.h"

#define BUF_SIZE	2000
char byte_order; /* 0=little, 1=big endian*/

FILE_HEADER file_header;
FRAME_HEADER frame_header;

char pkt_buf[BUF_SIZE];
int main(int argc, char *argv[])
{
	FILE *inf;
	ETHERNET_HEADER * ethernet;
	int counter_package = 1;

	inf = fopen(argv[1], "rb");
	
	if (!inf) 
		error_exit("Could not open file: %s\n", argv[1]);

	/* read file header */
	fread(&file_header, sizeof(FILE_HEADER), 1, inf);
	
	if (file_header.magic_number != 0xa1b2c3d4) 
		invert_file_header(&file_header);
	
	while (fread(&frame_header, sizeof(FRAME_HEADER), 1, inf)) 
	{
		if (file_header.magic_number != 0xa1b2c3d4) 
			invert_pkt_header(&frame_header);
		
		  

		fread(pkt_buf, frame_header.capt_data, 1, inf);
		ethernet = (ETHERNET_HEADER *)pkt_buf;

		trace_ethernet ( ethernet, counter_package++, &frame_header );
	}
   return 0;
}
