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

Thread::Thread(FileManager *fm, int *sock) 
{
	f = fm;
	ssock = sock;
	Thread::_Instances ++;	
}
Thread::~Thread() 
{
	Thread::_Instances--;
}
int Thread::Start(void * arg)
{
   Arg(arg); // store user data
  
   int code = pthread_create(&_ThreadId,NULL,Thread::EntryPoint, this);

   return code;
}

int Thread::Run()
{
	Acquire();
	Execute();
	Release();
	close(*ssock);
   return 1;
}

/*static */
void * Thread::EntryPoint(void * pthis)
{
	Thread * pt = (Thread*)pthis;
	if(!pthis)
	{
		return 0;
	}
   	pt->Run();
  delete pt;
   	return 0;
}

void Thread::Load (FileManager * fm)
{
	f = fm;
}
void Thread::Acquire(){}
void Thread::Execute()
{
   	f->Write();
   	//delete this;
}
void Thread::Release(){}

void Thread::WhoIAm()
{
	printf("I am thread %d\n", (int)_ThreadId);
}
