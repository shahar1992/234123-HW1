#include <linux/sched.h>
#include <linux/slab.h>

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
    task->log_arr_init_alloc=kmalloc(sizeof(*(task->log_arr_init_alloc))*size,GFP_KERNEL);
    if(!(task->log_arr_init_alloc)) return -ENOMEM;
    task->log_arr_init_size=size;
    task->log_arr_actual_size=0;
    task->log_arr_actual_head=task->log_arr_init_alloc;
    

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
    kfree(task->log_arr_init_alloc);
    task->log_arr_init_alloc=NULL;
    task->log_arr_actual_head=NULL;
    task->log_arr_init_size=0;
    task->log_arr_actual_size=0;
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

int sys_get_process_log(pid_t pid,int size,struct forbidden_activity_info* user_mem){
    int i;
    if(pid < 0)
        return -ESRCH;

    task_t* task = find_task_by_pid(pid);
    if(!task)
        return -ESRCH; 
    
    if(size > task->log_arr_actual_size)
        return -EINVAL;

    if(size < 0)
        return -EINVAL;

    if(task->p_state == BLOCK_POLICY)
        return -EINVAL;
    for(i=0;i<size;i++){
        user_mem[i].syscall_req_level=task->log_arr_actual_head[i].syscall_req_level;
        user_mem[i].proc_level=task->log_arr_actual_head[i].proc_level;
        user_mem[i].time=task->log_arr_actual_head[i].time;
    }
    task->log_arr_actual_head+=size;
    task->log_arr_actual_size-=size;

    return 0;
}






