/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef STACK_C_
#define STACK_C_
#include "Stack.h"
#include "stdlib.h"
#include <stdio.h>

void
push ( Stack * stack, DWORD value)
{
    Node * _node =  (Node *) malloc(sizeof(Node));
   
    _node->value = value;
    
    _node->next = stack->top;
    
    stack->top = _node;
    
    stack->length++;
}

Node *
pop (Stack * stack)
{
    Node * _node = stack->top;
    
    if (stack->top)
    {
        stack->top = _node->next;
        stack->length--;
    }
    
    return _node;
}

Stack*
make_stack ()
{
     Stack * _stack =  (Stack *) malloc(sizeof(Stack));
     
     _stack->top = NULL;
     
     _stack->length = 0;
     
     return _stack;
}

void
flush (Stack * stack)
{
    Node * _node = pop(stack);
    while (_node)
    {
        free (_node);
        _node = pop(stack);
    }
    stack->length = 0;
}

#endif 
