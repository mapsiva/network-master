/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Subnet
*/
#ifndef STACK_H_
#define STACK_H_
#include "Types.h"

/*Nó da pilha de operandos*/
typedef struct NODE
{
   DWORD value;
   struct NODE *next;
}Node;

/*Estrutura de controle e topo da pilha*/
typedef struct STACK
{
   Node *top;
   int length;
}Stack;

/*Empilha um elemento na pilha*/
void
push ( Stack *, DWORD);

/*desempilha um elemento da pilha*/
Node *
pop ( Stack * );

/*Incializa uma pilha*/
Stack*
make_stack ();

/*destrói a pilha*/
void
flush ( Stack * );

#endif 
