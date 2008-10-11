#include <pthread.h>
#include <stdio.h>
#include <semaphore.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "Thread.h"
#include "FileManager.h"

int Thread::_Instances = 0;

Thread::Thread(FileManager *f, int sock) 
{
	file = f;
	socket = sock;
	Thread::_Instances ++;	
}

int Thread::Start(void * arg)
{
   Arg(arg); // store user data
  
   int code = pthread_create(&_ThreadId,NULL,Thread::EntryPoint, this);

   return code;
}

int Thread::Run()
{
   //Acquire();
   Execute();
   //Release();
   return 0;
}

/*static */
void * Thread::EntryPoint(void * pthis)
{
	Thread * pt = (Thread*)pthis;
	if(!pthis)
	{
		printf("NULO\n");
		return 0;
	}
   	pt->Run();
   	return 0;
}

void Thread::Acquire(){}
void Thread::Execute()
{
	WhoIAm();
	file->Write();
}
void Thread::Release(){}

void Thread::WhoIAm()
{
	printf("I am thread %d\n", (int)_ThreadId);
}
