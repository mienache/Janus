#ifndef __DSL_THREAD_MANAGER__
#define __DSL_THREAD_MANAGER__

#include <atomic>
#include <map>
#include <set>

#include "handler.h"

class AppThread;

const int NUM_THREAD_SPILL_SLOTS = 10;


/*--- Thread Manager Declarations Start ---*/

extern AppThread *main_thread;
extern AppThread *checker_thread;

/*--- Thread Manager Declarations Finish ---*/

extern int NUM_THREADS;
extern std::atomic<bool> CHECKER_THREAD_FINISHED;
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

    /*
    The current basic block processed by the thread.
    This field is used for thread-specific instrumentation.
    To be set in the basic block handler before the code is
    executed from the code cache.
    */
    uint64_t curr_bb;


    /*
    Thread-specific variable for holding the rules that need to be forwarded in the case of an exception.
    Consider the following basic block:

    I1 -> I2 -> I3 -> I4 -> I5

    If an exception happens at I3, after the signal handler deals with it, when execution is resumed
    from I3, DynamoRIO will consdier I3-I5 to be a new basic block. Thus, all rules from I1 must be
    forwarded to I3. In the case of COMET, the `bb_to_required_rules` will be filled in the DR's
    event signal handler.

    The key of the map is the start of the basic block. The value of the map (the set) holds the
    starting addresses of the basic blocks from which the rules should be forwarded.
    */
    std::map <int64_t, std::set<long> > bb_to_required_rules;

    const int num_spill_slots;
    int64_t spill_slots[NUM_THREAD_SPILL_SLOTS];

    reg_id_t curr_queue_reg;
    bool instrumented_start_and_end_of_bb;
    int curr_disp;

    AppThread(pid_t pid_);
};

extern std::map <pid_t, AppThread*> app_threads;

AppThread* register_thread(const char *thread_role_as_str, void* drcontext);

void run_thread(void *raw_app_thread);

void init_num_threads(int num_threads);

// Helper function to perform the steps required before creating thread, such as forwarding the
// rewrite rules to the new basic block that gets created after the call is inserted in the
// original basic block. This maintenance function is needed to avoid exposing too many
// Janus or DynamoRIO details to the Cinnamon interface.
void do_pre_thread_creation_maintenance(JANUS_CONTEXT);

void wait_for_checker();

void mark_checker_thread_finished();

#endif
