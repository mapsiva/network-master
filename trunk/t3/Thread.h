#ifndef THREAD_H_
#define THREAD_H_

#include <pthread.h>
#include <stdio.h>

#include <signal.h>
#include <unistd.h>

class Thread
{
   public:
      Thread();
      int Start(void * arg);
      static int _Instances;
   protected:
     virtual  int Run();
     
      static void * EntryPoint(void*);
     
      void * Arg() const {return _Arg;}
     
      void Arg(void* a){_Arg = a;}
     
      virtual void Acquire();
      virtual void Execute();
      virtual void Release();
      
      void WhoIAm();
	  
	  pthread_t _ThreadId;
	  
	  void * _Arg;
	  int SleepTime;
     

};

#endif /*THREAD_H_*/
