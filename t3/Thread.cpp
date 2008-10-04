#include <pthread.h>
#include <stdio.h>
#include <semaphore.h>
#include <signal.h>
#include <unistd.h>
#include "Thread.h"

int Thread::_Instances = 0;

Thread::Thread() 
{
	Thread::_Instances ++;
}

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
   		WhoIAm();
   		sleep(1);
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
void Thread::WhoIAm()
{
	printf("I am thread %d\n", (int)_ThreadId);
}
