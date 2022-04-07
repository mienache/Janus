#ifndef __DSL_THREAD_MANAGER__
#define __DSL_THREAD_MANAGER__

#include <atomic>
#include <map>

#include "handler.h"

/*
    Create the number of threads specified in `rsched_info.number_of_threads`.
    Currently the threads are created using `fork`.
    TODO: this will need to change in the future probably to clone.
    TBD once we decide where the communication queue will be implemented.
*/

class AppThread;

extern AppThread *main_thread;
extern AppThread *checker_thread;
extern int NUM_THREADS;
extern std::atomic<bool> CHECKER_THREAD_FINISHED;
extern std::atomic<bool> PAST_THREAD_CREATION_STAGE;
extern void *NEW_THREAD_START_PTR;

enum ThreadRole {
    UNKNOWN,
    MAIN,
    CHECKER,
};

class AppThread {
  public:
    pid_t pid;
    ThreadRole threadRole;

    AppThread(pid_t pid_): pid(pid_) {}
};

extern std::map <pid_t, AppThread*> app_threads;

AppThread* register_thread(ThreadRole threadRole, void* drcontext);

void create_checker_thread(void *raw_app_thread);

void init_num_threads(int num_threads);

// Helper function to perform the steps required before creating thread, such as forwarding the
// rewrite rules to the new basic block that gets created after the call is inserted in the
// original basic block. This maintenance function is needed to avoid exposing too many
// Janus or DynamoRIO details to the Cinnamon interface.
void do_pre_thread_creation_maintenance(JANUS_CONTEXT);

#endif
