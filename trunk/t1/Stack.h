#ifndef STACK_H_
#define STACK_H_
#include "Types.h"

typedef struct NODE
{
   void * value;
   struct NODE *next;
}Node;

typedef struct STACK
{
   Node *top;
}Stack;


void
push ( Stack *, void *);

Node *
pop ( Stack * );

Stack*
make_stack ();



#endif 
