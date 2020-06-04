# THM: Reverse Engineering

Original challenge can be found at:<https://tryhackme.com/room/reverseengineering>

#### Task 2 - crackme2:

We get a binary called crackme1.bin. and should reverse the password that it asks us for.

If we want to know what kind of file this is we can simply look right into the header or use the file command that do basically the same but in a fancier way.

```bash
$ file crackme1.bin
crackme1.bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3864320789154e8960133afdf58ddf65f6f8273d, not stripped
```
Or via the magic values represented in the header of the file
```bash
$ head -n 1 crackme1.bin
ELF>`@�@8	@@@@�888 
$ readelf -a crackme1.bin
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64

```
So this is a 64 Bit ELF file. This means it runs natively under *nix systems as Linux or Unix.

The simplest way to obtain the password is via strings.

```bash
$ strings crackme1.bin
...
hax0r
...
```
Which will give you all strings in that file. The obvious solution is right there behind the password statements.

Another approach is to look into the binary via objdump or start a debugger. As this is an ELF64 file the string is not located on the stack but rather in rodata section. Which is better analyzed via objedump or reversing tools.

#### Task 3 - crackme2:

Original challenge can be found at:<https://tryhackme.com/room/reverseengineering>

The second challenge is basically as easy as the first one. But this time there is no string stored. So lets find out how we can crack this one!

If we examine the file with a disassembler we get something like this:

```bash
0x00000738      call    puts       ; sym.imp.puts ; int puts(const char *s)
0x0000073d      lea     rax, [var_ch]
0x00000741      mov     rsi, rax
0x00000744      lea     rdi, [0x00000838] ; 2104 ; const char *format
0x0000074b      mov     eax, 0
0x00000750      call    __isoc99_scanf ; sym.imp.__isoc99_scanf ; int scanf(const char *format)
0x00000755      mov     eax, dword [var_ch]
0x00000758      cmp     eax, 0x137c
0x0000075d      jne     0x76d
```

What stands out that after the scanf call there is just a cmp (compare) followed by the jne instruction, which jumps dependent on the flags register. So the jump says which branch is taken and the compare states what our input is compared to. 

Therefore

```
cmp     eax, 0x137c
```
In eax the reference to our input from scanf is stored. And 0x137c is just a hex value. The format parameter states that this is a integer (if we try chars, it would be only non printable ones). So we just have to convert the hex value into a integer representation. This can be achieved with bc
```bash
$ echo 'ibase=16; 137C' | bc
4988
```
Well this is it! We found the correct password.

#### Task 4 - crackme2:

Original challenge can be found at:<https://tryhackme.com/room/reverseengineering>

The last challenge is a bit more challinging :)

If we take closer look, we see that the password is not compared in a whole, but rather Byte or Word wise. Luckily this time the password is stored on the stack. So it also can be found via debugger easily.

The relevant disassembly:

```hex
0x00000731      mov     word [var_23h], 0x7a61 ; 'az'
0x00000737      mov     byte [var_21h], 0x74 ; 't'
0x0000073b      lea     rdi, str.enter_your_password ; 0x854 ; const char *s
0x00000742      call    puts       ; sym.imp.puts ; int puts(const char *s)
0x00000747      lea     rax, [var_20h]
0x0000074b      mov     rsi, rax
0x0000074e      lea     rdi, [0x00000868] ; 2152 ; const char *format
0x00000755      mov     eax, 0
0x0000075a      call    __isoc99_scanf ; sym.imp.__isoc99_scanf ; int scanf(const char *format)
0x0000075f      mov     dword [var_28h], 0
0x00000766      jmp     0x797
0x00000768      mov     eax, dword [var_28h]
0x0000076b      cdqe
0x0000076d      movzx   edx, byte [rbp + rax - 0x20]
0x00000772      mov     eax, dword [var_28h]
0x00000775      cdqe
0x00000777      movzx   eax, byte [rbp + rax - 0x23]
0x0000077c      cmp     dl, al
0x0000077e      je      0x793
```
We can either follow the comparison loop or examine the arguments of the main function. An our input is basically compared to the 3 Bytes "azt" -- which is the password for this task.
