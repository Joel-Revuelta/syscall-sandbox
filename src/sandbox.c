#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <string.h>

int parse_args(int argc, char *argv[], int *k, int *blocked, int *size_blocked){
    
    int b = 0;
    
    for(int i = 0; i < argc; i++ ){
        if(strcmp(argv[i], "-k") == 0){
            *k = 1;
        }else if(strcmp(argv[i], "-b") == 0){
            blocked[b] = atoi(argv[i+1]);
            i++;
            b++;
            *size_blocked = *size_blocked + 1;    
        }else if(strcmp(argv[i], "--") == 0){
            return i + 1;
        }
    }    

    return 0;
}

int main(int argc, char *argv[])
{   
    int *blocked = malloc(sizeof(int) * argc);
    struct user_regs_struct regs;
    int k = 0;
    int size_blocked = 0;
    int status = 0;
    int sig = 0;
    int start = 0;
    

    int prog = parse_args(argc, argv, &k, blocked, &size_blocked);
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s program [args...]\n", argv[prog]);
        return 1;
    }

    pid_t child = fork();

    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        execvp(argv[prog], &argv[prog]);
        perror("execvp");        
        _exit(127);
    }
     
    waitpid(child, &status, __WALL);
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
    ptrace(PTRACE_SYSCALL, child, 0, sig);

    int entered = 0;

    while(1){
        waitpid(-1, &status, __WALL);
        
        if(WIFEXITED(status) || WIFSIGNALED(status)){
            break;
        }
        if(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)){
            if(entered == 0){
                
                ptrace(PTRACE_GETREGS, child, 0, &regs);

                for(int i = 0; i < size_blocked; i++){
                    if(blocked[i] == regs.orig_rax){
                        printf("Caught to block\n");
                        if(k != 0){
                            fprintf(stderr, "[sandbox] KILLED (syscall %lld)\n", regs.orig_rax);
                            kill(child, SIGKILL);
                        }else{
                            fprintf(stderr, "[sandbox] Blocked (syscall %lld)\n", regs.orig_rax);
                            regs.orig_rax = (unsigned long long) - 1;
                            ptrace(PTRACE_SETREGS, child, 0, &regs);
                        }
                    }
                }
                entered = 1;
            }else{
                entered = 0;    
            }
            
            
        }else if(WIFSTOPPED(status) && WSTOPSIG(status) != (SIGTRAP | 0x80)){
            sig = WSTOPSIG(status);
            if(sig == SIGTRAP && start == 0){
                sig = 0;
                start += 1;
            }
        }
             
        ptrace(PTRACE_SYSCALL, child, 0, sig); 
        sig = 0;       
    }


    printf("[sandbox] child pid: %d\n", child);

    free(blocked);

    return 0;
}
