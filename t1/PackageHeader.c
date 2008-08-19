#ifndef PACKAGEHEADER_C_
#define PACKAGEHEADER_C_

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "PackageHeader.h"

void
error_exit(char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    exit(1);
}

WORD 
invert_long(WORD n)
{
  char *s, d[4];
  WORD *rv = (WORD*)&d[0];
  s = (char *)&n;
  d[0] = s[3];  d[1] = s[2];  d[2] = s[1];  d[3] = s[0];
  return *rv;
}

SWORD 
invert_short(SWORD n)
{
  char *s, d[2];
  SWORD *rv = (SWORD*)&d[0];
  s = (char *)&n;
  d[0] = s[1];  d[1] = s[0]; 
  return *rv;
}

void 
invert_file_header(FILE_HEADER *fh)
{
  fh->major_version   = invert_short(fh->major_version);
  fh->minor_version   = invert_short(fh->minor_version);
  fh->time_zone_off   = invert_long(fh->time_zone_off);
  fh->time_stamp      = invert_long(fh->time_stamp);
  fh->snap_length     = invert_long(fh->snap_length);
  fh->link_layer_type = invert_long(fh->link_layer_type);
}


void
invert_pkt_header(FRAME_HEADER *fh)
{
  fh->seconds       = invert_long(fh->seconds);
  fh->mic_secs      = invert_long(fh->mic_secs);
  fh->capt_data     = invert_long(fh->capt_data);
  fh->actual_length = invert_long(fh->actual_length);

}

void 
print_pkt_header (FRAME_HEADER *fh)
{
	printf("Seconds: %u Micsecs %u %X %X \n", (unsigned int) fh->seconds,(unsigned int) fh->mic_secs, (unsigned int)fh->capt_data, (unsigned int)fh->actual_length );
}

#endif 
