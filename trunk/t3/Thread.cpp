#include <pthread.h>
#include <stdio.h>
#include <semaphore.h>
#include <signal.h>
#include <unistd.h>
#include "Thread.h"


Thread::Thread() {Thread::_id++;}

int Thread::Start(void * arg)
{
   Arg(arg); // store user data
  
   int code = pthread_create(&_ThreadId,NULL,Thread::EntryPoint, this);

   return code;
}

int Thread::Run(void * arg)
{
   
   while(true)
   {
   		printf("thread rodando\n");
   		sleep(2);
   }
   return 0;
}

/*static */
void * Thread::EntryPoint(void * pthis)
{
	Thread * pt = (Thread*)pthis;
	if(!pthis)
	{
		printf("NULO");
		return 0;
	}
   pt->Run( pt->Arg() );
   return 0;
}
inline void Thread::WhoIAm()
{
	printf("I am thread %d", Thread::_id);
}
