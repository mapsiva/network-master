#include <stdio.h>
#include "Thread.h"
#include "Syncronize.h"
int main(int argv , char * argc[])
{
	sem_t s;
	Syncronize **t = new Syncronize*[100];
	
	for (int i=0; i<100; i++)
	{
		t[i] = new Syncronize();
		t[i]->SetSemaphore(&s);
		t[i]->Start(0,1);
	}
	while(true)
	{
		sleep(2);
	}
	return 0;
}
