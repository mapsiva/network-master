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