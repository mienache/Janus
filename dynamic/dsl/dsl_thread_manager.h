#ifndef __DSL_THREAD_MANAGER__
#define __DSL_THREAD_MANAGER__

#include <atomic>
#include <map>

/*
    Create the number of threads specified in `rsched_info.number_of_threads`.
    Currently the threads are created using `fork`.
    TODO: this will need to change in the future probably to clone.
    TBD once we decide where the communication queue will be implemented.
*/

extern bool MAIN_THREAD_REGISTERED;
extern bool CHECKER_THREAD_REGISTERED;
extern std::atomic<bool> CHECKER_THREAD_FINISHED;
extern std::atomic<bool> PAST_THREAD_CREATION_STAGE;

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

void register_thread(ThreadRole threadRole, void* drcontext);

//void create_checker_thread(uint64_t pc);
void create_checker_thread();

#endif
