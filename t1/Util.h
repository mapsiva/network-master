/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ci�ncia da Computa��o DCT - UFMS
	Redes de Computadores 2008
	
	M�rcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef UTIL_H_
#define UTIL_H_

#define IP_VER(p) (p->version >> 4)/*Version*/
#define IP_IHL(p) ((p->version & 0xf)*2)/*internet header length*/

#define IP_DELAY(p) ((p->type_service >> 4) & 0x1)
#define IP_THROU(p) ((p->type_service >> 3) & 0x1)
#define IP_RELIA(p) ((p->type_service >> 2) & 0x1)
#define IP_FLAGS(p) ((ntohs(p->fragment) >> 13))/*Flags*/
#define IP_OFFSET(p) ((ntohs(p->fragment) & 0x1FFF))/*fragment offset*/

#endif 
