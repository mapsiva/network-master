/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef STACK_H_
#define STACK_H_
#include "Types.h"

typedef struct NODE
{
   DWORD value;
   struct NODE *next;
}Node;

typedef struct STACK
{
   Node *top;
   int length;
}Stack;


void
push ( Stack *, DWORD);

Node *
pop ( Stack * );

Stack*
make_stack ();

void
flush ( Stack * );

#endif 
