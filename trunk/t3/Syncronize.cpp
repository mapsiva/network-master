#include "Syncronize.h"
int Syncronize::shared = 0;

Syncronize::Syncronize()
{
}
void Syncronize::SetSemaphore(sem_t *s)
{
	Semaphore = s;
}
void Syncronize::Acquire()
{
	
	sem_wait(Semaphore);
	printf("Acquire!\n");
	printf("Enter critical section!\n");
}
		
void Syncronize::Release()
{
	printf("Release!\n");
	sem_post(Semaphore); sleep(2);
	
}
void Syncronize::Start(int pshared, int value)
{
	sem_init(Semaphore, pshared, value);
	Thread::Start(NULL);
}
void Syncronize::Execute()
{  
   Syncronize::shared++;
   printf("Shared Object = %d\n",  Syncronize::shared);
   WhoIAm();
  
}
