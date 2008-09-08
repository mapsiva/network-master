/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef PACKAGEHEADER_H_
#define PACKAGEHEADER_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "Types.h"

typedef struct 
{
  WORD		magic_number;
  SWORD		major_version;
  SWORD		minor_version;
  WORD		time_zone_off;
  WORD		time_stamp;
  WORD		snap_length;
  WORD		link_layer_type;
} FILE_HEADER;

typedef struct 
{
  WORD		seconds;
  WORD		mic_secs;
  WORD		capt_data;
  WORD		actual_length;
} FRAME_HEADER;

void error_exit(char *fmt, ...);
WORD invert_long( WORD );
SWORD invert_short( SWORD );
void invert_file_header( FILE_HEADER * );
void invert_pkt_header( FRAME_HEADER * );
void print_pkt_header ( FRAME_HEADER * );



#endif 
