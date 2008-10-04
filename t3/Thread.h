#ifndef THREAD_H_
#define THREAD_H_

#include <pthread.h>
#include <stdio.h>
#include <semaphore.h>
#include <signal.h>
#include <unistd.h>

class Thread
{
   public:
      Thread();
      int Start(void * arg);
   protected:
      int Run(void * arg);
      static void * EntryPoint(void*);
      void * Arg() const {return _Arg;}
      void Arg(void* a){_Arg = a;}
      inline void WhoIAm();
   private:
      pthread_t _ThreadId;
      void * _Arg;
      static int _id;

};

#endif /*THREAD_H_*/
