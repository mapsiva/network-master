#include <stdio.h>
#include "Thread.h"

int main(int argv , char * argc[])
{
	Thread *t = new Thread();
	Thread *c = new Thread();
	
	t->Start(NULL);
	c->Start(NULL);
	while(true)
	{
		sleep(2);
	}
	return 0;
}
