
#include <stdio.h>
#include <string.h>

void gadget_trap(void) {
    printf("Oops! You are trapped in a dead loop.\n");
    /* 故意制造死循环，易诱发 angr 路径爆炸或资源耗尽 */
    while (1) { }
}

int check_password(char *input) {
    if (strlen(input) < 4) {
        puts("Wrong password!");
        return 0;
    }
    if (input[0] == 'A') {
        if (input[1] == 'B') {
            gadget_trap();
        }
        if (input[1] == 'Z') {
            if ((input[2] ^ 0x12) == 'q') {
                if ((input[3] + 3) == 'H') {
                    puts("Success! Flag is found.");
                    return 1;
                }
            }
        }
    }
    puts("Wrong password!");
    return 0;
}

int main(void) {
    char password[10];
    printf("Enter password: ");
    scanf("%9s", password);
    check_password(password);
    return 0;
}
