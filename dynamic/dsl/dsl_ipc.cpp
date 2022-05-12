#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include <cassert>


#include <iostream>

#include "janus_api.h"

#include "dsl_ipc.h"
#include "dsl_thread_manager.h"

/*--- IPC Declarations Start ---*/

/*--- IPC Declarations Finish ---*/

//const int DEFAULT_QUEUE_SIZE = 100000000;
const int DEFAULT_QUEUE_SIZE = 2500000;
//const int DEFAULT_QUEUE_SIZE = 50000;
//const int DEFAULT_QUEUE_SIZE = 5000;

BasicQueue *IPC_QUEUE;
CometQueue *IPC_QUEUE_2;

BasicQueue* initialise_queue()
{
    std::cout << "Creating basic queue" << std::endl;
        
    return new BasicQueue(DEFAULT_QUEUE_SIZE);
}

CometQueue* initialise_comet_queue()
{
    std::cout << "Creating Comet queue" << std::endl;

    return new CometQueue(DEFAULT_QUEUE_SIZE);
}
