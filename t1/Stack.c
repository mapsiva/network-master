#ifndef STACK_C_
#define STACK_C_
#include "Stack.h"
#include "stdlib.h"

void
push ( Stack * stack, void * value)
{
    Node * _node =  (Node *) malloc(sizeof(Node));
   
    _node->value = value;
    
    _node->next = stack->top;
    
    stack->top = _node; 
}

Node *
pop (Stack * stack)
{
    Node * _node = stack->top;
    
    if (stack->top)
        stack->top = _node->next;
    
    return _node;
}

Stack*
make_stack ()
{
     Stack * _stack =  (Stack *) malloc(sizeof(Stack));
     
     _stack->top = NULL;
     
     return _stack;
}



#endif 
