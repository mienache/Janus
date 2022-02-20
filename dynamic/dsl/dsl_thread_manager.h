#ifndef __DSL_THREAD_MANAGER__
#define __DSL_THREAD_MANAGER__

extern bool CHECKER_THREAD_CREATED;

/*
    Create the number of threads specified in `rsched_info.number_of_threads`.
    Currently the threads are created using `fork`.
    TODO: this will need to change in the future probably to clone.
    TBD once we decide where the communication queue will be implemented.
*/
void create_checker_thread();

#endif
