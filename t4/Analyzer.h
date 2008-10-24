/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ci�ncia da Computa��o DCT - UFMS
	Redes de Computadores 2008
	
	M�rcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef ANALYZER_H_
#define ANALYZER_H_
#include "Types.h"
#include "Util.h"
#include <arpa/inet.h> 

char * _current;

Token *
Advance( CHAR_T* argv);

#endif 
