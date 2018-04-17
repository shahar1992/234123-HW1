#include <linux/sched.h>

#define ADMIN_PSWD 234123


int sys_enable_policy (pid_t pid ,int size, int password){
    if(pid < 0)
        return -ESRCH;

    task_t* task = find_task_by_pid(pid);
    if(!task)
        return -ESRCH;

    if(password != ADMIN_PSWD)
        return -EINVAL;
    
    if(task->p_state == ALLOW_POLICY)
        return -EINVAL;

    if(size < 0)
        return -EINVAL;

    //allocate memory for log.

    task->p_state = ALLOW_POLICY;
    task->p_lvl = LEVEL_2;
    return 0;


}



// .long SYMBOL_NAME(sys_enable_policy) /* 243 */
// 	.long SYMBOL_NAME(sys_disable_policy) /* 244 */
// 	.long SYMBOL_NAME(sys_set_process_capabilities) /* 245 */
// 	.long SYMBOL_NAME(sys_get_process_log)
