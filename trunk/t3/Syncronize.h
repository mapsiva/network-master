#ifndef SYNCRONIZE_H_
#define SYNCRONIZE_H_

#include <semaphore.h>
#include "Thread.h"

class Syncronize : public Thread
{
	private:
		sem_t *Semaphore;
	public:
		Syncronize();
		void SetSemaphore(sem_t*);
		void Start( int, int );
		void Acquire();
		void Execute();
		void Release();
		static int shared;
		
};
#endif /*SYNCRONIZE_H_*/
