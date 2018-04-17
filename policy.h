#include <errno.h>

int enable_policy (pid_t pid ,int size, int password){
    int res;
        __asm__(
        "int $0x80;"
        : "=a" (res)
        : "0" (243), "b" (pid), "c" (size), "d" (password)
        :"memory"
    );
    if ((res) < 0) {
        errno = (-res);
        return -1;
    }
    return res;
}

int disable_policy (pid_t pid ,int password){
        int res;
        __asm__(
        "int $0x80;"
        : "=a" (res)
        : "0" (244), "b" (pid), "d" (password)
        :"memory"
    );
    if ((res) < 0) {
        errno = (-res);
        return -1;
    }
    return res;
}

int enable_policy (pid_t pid ,int size, int password){
    int res;
        __asm__(
        "int $0x80;"
        : "=a" (res)
        : "0" (243), "b" (pid), "c" (size), "d" (password)
        :"memory"
    );
    if ((res) < 0) {
        errno = (-res);
        return -1;
    }
    return res;
}

int enable_policy (pid_t pid ,int size, int password){
    int res;
        __asm__(
        "int $0x80;"
        : "=a" (res)
        : "0" (243), "b" (pid), "c" (size), "d" (password)
        :"memory"
    );
    if ((res) < 0) {
        errno = (-res);
        return -1;
    }
    return res;
}