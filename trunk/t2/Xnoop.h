/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef XNOOP_H_
#define XNOOP_H_

#include "PackageHeader.h"
#include "Ethernet.h"
#include "Types.h"

#define BUF_SIZE	2000
char byte_order; /* 0=little, 1=big endian*/

char pkt_buf[BUF_SIZE];

int check_parameters(int, char *[], _XNOOP *);
int xnoop(int, char *[], ETHERNET_HEADER *, _XNOOP *);

#endif 
