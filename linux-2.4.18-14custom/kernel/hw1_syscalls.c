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


int sys_disable_policy(pid_t pid ,int password){
    if(pid < 0)
        return -ESRCH;

    task_t* task = find_task_by_pid(pid);
    if(!task)
        return -ESRCH;
    
    if(task->p_state == BLOCK_POLICY)
        return -EINVAL;

    if(password != ADMIN_PSWD)
        return -EINVAL;


    task->p_state = BLOCK_POLICY;
    return 0;
    //delete the process log and free allocated memory

}


int sys_set_process_capabilities(pid_t pid,int new_level,int password){
    if(pid < 0)
        return -ESRCH;

    task_t* task = find_task_by_pid(pid);
    if(!task)
        return -ESRCH;
    
    if(new_level < 0 || new_level > 2)
        return -EINVAL;

    if(password != ADMIN_PSWD)
        return -EINVAL;
    
    if(task->p_state == BLOCK_POLICY)
        return -EINVAL;
    
    task->p_lvl = new_level;

    return 0;
}
/*
int get_process_log(pid_t pid,int size,struct forbidden_activity_info* user_mem)    
    if(pid < 0)
        return -ESRCH;

    task_t* task = find_task_by_pid(pid);
    if(!task)
        return -ESRCH; 
    
    if(size > task->log.size)
        return -EINVAL;

    if(size < 0)
        return -EINVAL;

    if(task->p_state == BLOCK_POLICY)
        return -EINVAL;
    
    user_mem = task->log;

    return 0;
}
*/





