#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdint.h>

// #define DEBUG

#define MAXNUM 200

long long numbers[MAXNUM];

#ifdef RANDOMSTUFF
int random_fd = -1;

void init_random(void){
    random_fd = open("/dev/urandom", O_RDONLY);
    if (random_fd < 0){
        puts("Failed Initialize random!");
        exit(-1);
    }
}

int rand_int(void){
    int ret;
    read(random_fd, &ret, sizeof(ret));
    return ret;
}
#endif

long long get_int(){
    int num;
    char buf[200];
    read(0, buf, sizeof(buf));
    return atoll(buf);
}

void add_numbers(){
    long long * tmp;
    int size;
    int i, j;
    long long num;
    printf("How many would you add?");
    printf("> ");
    size = get_int();
    if (size <= 0 && size > MAXNUM){
        printf("No one?\n OK!\n");
        return;
    }
    tmp = alloca(size * sizeof(int));
    #ifdef DEBUG
        printf("%#x\n", tmp);
        for (i = 0; i < size/2; i++){
            printf("%#lx\n", tmp[i]);
        }
    #endif
    printf("#> ");
    num = get_int();
    for (i = 0; i < size && num >= 0; i++){
        tmp[i] = num;
        printf("[%d]#> ", i);
        num = get_int();
    }
    for (j = 0; j <= i; j++){
        numbers[j] += tmp[j];
    }
}

void print_numbers(){
    int i;
    for (i = 0; i < MAXNUM; i++){
        printf("%lld\n", numbers[i]);
    }
}

void menu(){
    puts("");
    puts("**************");
    puts("0. Add Numbers");
    puts("1. Print Numbers");
    puts("2. Exit");
}

int main() {
    int choice;
    setvbuf(stdin, NULL, _IONBF, 0); 
    setvbuf(stdout, NULL, _IONBF, 0); 
    setvbuf(stderr, NULL, _IONBF, 0); 

    while (2){
        menu();
        printf("> ");
        switch(get_int()){
            case 0:
                add_numbers();
                break;
            case 1:
                print_numbers();
                break;
            default:
                exit(0);
        }
    }
}
