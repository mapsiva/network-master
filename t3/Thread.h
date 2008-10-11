#ifndef THREAD_H_
#define THREAD_H_

#include <pthread.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include "FileManager.h"

class Thread
{
   public:
   	  Thread();
      Thread(FileManager *, int);
      int Start(void * arg);
      static int _Instances;
   protected:
   	  //Attributes
   	  pthread_t _ThreadId;
	  FileManager *file;
	  int socket;
	  void * _Arg;
	  int SleepTime;
      
      //Methods
      int Run();
      static void * EntryPoint(void*);     
      void * Arg() const {return _Arg;}     
      void Arg(void* a){_Arg = a;}     
      void Acquire();
      void Execute();
      void Release();      
      void WhoIAm();
};

#endif /*THREAD_H_*/
