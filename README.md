# dynamic-code-instrumentation
A small code snippet illustrating self and dynamic code instrumentation

Compilation:
-----------
gcc -g -O0 ./intercept.c -o intercept

Simple run:
-----------
```
localhost:~/github/dynamic-code-instrumentation]$ gcc -g -O0 intercept.c -o intercept
localhost:~/github/dynamic-code-instrumentation]$ ./intercept
Enter the function name to override
jumpFromHere
I have jumped to this location now
jumpFromHere() returned --->5
localhost:~/github/dynamic-code-instrumentation]$
```

