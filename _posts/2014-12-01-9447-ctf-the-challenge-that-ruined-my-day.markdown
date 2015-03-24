---
layout: post
title: The 'rolling' reverse challenge that ruined my day, 9447.plumbing
category: blog
tags: ctf writeup reverse 
description: This 100pts reverse challenge from 9477 cft ruined my day. I thought it was a very tough reverse engineering challenge. However, it turned out to be a very easy one. My difficult was due to some unintentional problem of the challenge binary.
---

rolling - reverse 100pts, or trolling?
======================================

This reverse challenge was really driving me crazy. I spent a few hours trying 
to figure out why it got segmentation fault all the time on my PC. I checked 
every bit of this binary, but still I did not succeed to get it run. But I do 
understand where came the segmentation fault. Let's first check the main function.

{% highlight asm linenos %}
.text:000000000040074C                 mov     [rbp+argc], edi
.text:000000000040074F                 mov     [rbp+argv], rsi
.text:0000000000400753                 cmp     [rbp+argc], 2
.text:0000000000400757                 jnz     short error
.text:0000000000400759                 mov     rax, [rbp+argv]
.text:000000000040075D                 add     rax, 8
.text:0000000000400761                 mov     rax, [rax]
.text:0000000000400764                 movzx   eax, byte ptr [rax]
.text:0000000000400767                 movsx   eax, al
.text:000000000040076A                 mov     edi, eax
.text:000000000040076C                 call    rolling
{% endhighlight %}

The main function checked whether the number of arguments was 2 (line 3). 
If not, we got the 
error message (line 3). Otherwise, the first letter of argv[1] was passed to the 
*rolling* function (line 5 to 11).

{% highlight asm linenos %}
.text:0000000000400681                 mov     r9d, 0          ; offset
.text:0000000000400687                 mov     r8d, 0FFFFFFFFh ; fd
.text:000000000040068D                 mov     ecx, 22h        ; flags
.text:0000000000400692                 mov     edx, 7          ; prot
.text:0000000000400697                 mov     rsi, rax        ; len 0x87c
.text:000000000040069A                 mov     edi, 0          ; addr
.text:000000000040069F                 call    _mmap
{% endhighlight %}

Then the *rolling* function would call *mmap* to allocate 0x87c bytes memory area
(line 1 to 7).
Depending on the first letter of argv[1], *rolling* would either copy the
memory content from 0x601060 (0x87c bytes) or from 0x6018E0 (ox874 bytes) to 
the previously mapped memory.

{% highlight asm linenos %}
.text:0000000000400606                 mov     eax, [rbp+inner_loop]
.text:0000000000400609                 cdqe
.text:000000000040060B                 lea     rdx, ds:0[rax*4]
.text:0000000000400613                 mov     rax, [rbp+code]
.text:0000000000400617                 add     rax, rdx
.text:000000000040061A                 mov     edx, [rbp+inner_loop]
.text:000000000040061D                 movsxd  rdx, edx
.text:0000000000400620                 lea     rcx, ds:0[rdx*4]
.text:0000000000400628                 mov     rdx, [rbp+code]
.text:000000000040062C                 add     rdx, rcx
.text:000000000040062F                 mov     ecx, [rdx]
.text:0000000000400631                 mov     edx, [rbp+inner_loop]
.text:0000000000400634                 movsxd  rdx, edx
.text:0000000000400637                 shl     rdx, 2
.text:000000000040063B                 lea     rsi, [rdx-4]
.text:000000000040063F                 mov     rdx, [rbp+code]
.text:0000000000400643                 add     rdx, rsi
.text:0000000000400646                 mov     edx, [rdx]
.text:0000000000400648                 xor     edx, ecx
.text:000000000040064A                 mov     [rax], edx
{% endhighlight %}

Then the *rolling* function was supposed to perform a xor operation on the mapped memory.
However, it actually used memory that was not allocated. 
It first load the last byte (0x874 - 0x1) as the array index (line 1) and then multiplied the 
index by 4 (line 3)
(strangely, it considered this memory area as an array of dword, that was 4
bytes). Next it loaded the dword before the last one (line 12 to 18) and xored it with 
the last dword (line 19). Finally, it overwrote the last dword by the result of xor (line 20).
At this moment, I got the segmentation fault.

{% highlight bash linenos %}
$ strace ./rolling password
...
mmap(NULL, 2164, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1,
0) = 0x7f19900d4000
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_ACCERR, si_addr=0x7f19900d5ffc} ---
+++ killed by SIGSEGV (core dumped) +++
zsh: segmentation fault (core dumped)  strace ./rolling password
{% endhighlight %}

The above was part of the strace log on my PC.
Apart from this result, there was anonther possibility. If I passed an
augment that began with 1, for instance, it would not try to do the xor operation and would
call data at 0x601060 as code.

{% highlight bash linenos %}
$ strace ./rolling 1
...
mmap(NULL, 2172, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1,
0) = 0x7f8568f16000
--- SIGILL {si_signo=SIGILL, si_code=ILL_ILLOPN, si_addr=0x7f8568f16014} ---
+++ killed by SIGILL (core dumped) +++
zsh: illegal hardware instruction (core dumped)  strace ./rolling 1
{%endhighlight %}
But this did not work, because there was illegal hardware instruction (line 4 
to 6). I was stuck here for all the day and I waited eagerly for the writeup of
this challenge.

But but, what a surprise. Just saw the [writeup](http://theevilbit.blogspot.fr/
2014/12/9447-ctf-2014-writeup-reversing-125100.html) and I was stunned. This 
challenge could run correctly on Ubuntu and it was not difficult at all. I
setup an Ubuntu VM and tested a bit. It did work on Ubuntu.

{% highlight bash linenos %}
strace ./rolling password
...
mmap(NULL, 2164, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1,
0) = 0x7f6fe8285000
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 3), ...}) = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) =
0x7f6fe8284000
write(1, "Nac oes. Ceisiwch eto.\n", 23Nac oes. Ceisiwch eto.
) = 23
exit_group(0)                           = ?
{% endhighlight %}

Why??? What happened? There was no segmentation fault in the above log of 
strace on my Ubuntu VM

{% highlight asm linenos %}
$ cat /proc/4157/maps 
00400000-00401000 r-xp 00000000 07:00 290840         /home/ubuntu/rolling
00600000-00601000 r--p 00000000 07:00 290840         /home/ubuntu/rolling
00601000-00603000 rw-p 00001000 07:00 290840         /home/ubuntu/rolling
7ffff7a1a000-7ffff7bcf000 r-xp 00000000 07:00 235566 /lib/x86_64-linux-gnu/libc-2.15.so
7ffff7bcf000-7ffff7dcf000 ---p 001b5000 07:00 235566 /lib/x86_64-linux-gnu/libc-2.15.so
7ffff7dcf000-7ffff7dd3000 r--p 001b5000 07:00 235566 /lib/x86_64-linux-gnu/libc-2.15.so
7ffff7dd3000-7ffff7dd5000 rw-p 001b9000 07:00 235566 /lib/x86_64-linux-gnu/libc-2.15.so
7ffff7dd5000-7ffff7dda000 rw-p 00000000 00:00 0 
7ffff7dda000-7ffff7dfc000 r-xp 00000000 07:00 235578 /lib/x86_64-linux-gnu/ld-2.15.so
7ffff7fde000-7ffff7fe1000 rw-p 00000000 00:00 0 
7ffff7ff7000-7ffff7ff8000 rwxp 00000000 00:00 0 
7ffff7ff8000-7ffff7ffa000 rw-p 00000000 00:00 0 
7ffff7ffa000-7ffff7ffc000 r-xp 00000000 00:00 0                          [vdso]
7ffff7ffc000-7ffff7ffd000 r--p 00022000 07:00 235578 /lib/x86_64-linux-gnu/ld-2.15.so
7ffff7ffd000-7ffff7fff000 rw-p 00023000 07:00 235578 /lib/x86_64-linux-gnu/ld-2.15.so
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0      [stack]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0 [vsyscall]

(gdb) i r
rax            0x7ffff7ff7000    140737354100736
rbx            0x0    0
rcx            0xffffffffffffffff    -1
rdx            0x7    7
rsi            0x874    2164
rdi            0x0    0
{% endhighlight %}

We can see from GDB (line 20 to 26), the allocated memory address in *rolling* 
function was 0x7ffff7ff7000. In the memory maps of this process, there was another 
memory area 7ffff7ff8000-7ffff7ffa000 that could be read and written 
(line 12 and 13). Thus, 
there would not be any segmentation fault. But where did this memory area come from? 

{% highlight asm linenos %}
strace ./rolling dd
execve("./rolling", ["./rolling", "dd"], [/* 38 vars */]) = 0
brk(0)                                  = 0x604000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f6fe8286000
...
mmap(NULL, 2164, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f6fe8285000
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 3), ...}) = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f6fe8284000
write(1, "Nac oes. Ceisiwch eto.\n", 23Nac oes. Ceisiwch eto.
) = 23
exit_group(0)                           = ?
{% endhighlight %}

Let's look at another result of *strace* on the Ubuntu VM. Accidentally, one of 
the memory area used by *ld.so* (line 5) was adjacent with the memory area 
used by the *rolling* function (line 7). However, it was no the case in my PC 
that had an archlinux distribution.

{% highlight asm linenos %}
$ cat /proc/30144/maps
00400000-00401000 r-xp 00000000 08:03 7130392                            /home/archlinux/rolling
00600000-00601000 r--p 00000000 08:03 7130392                            /home/archlinux/rolling
00601000-00603000 rw-p 00001000 08:03 7130392                            /home/archlinux/rolling
7ffff7a38000-7ffff7bd1000 r-xp 00000000 08:02 394074                     /usr/lib/libc-2.20.so
7ffff7bd1000-7ffff7dd1000 ---p 00199000 08:02 394074                     /usr/lib/libc-2.20.so
7ffff7dd1000-7ffff7dd5000 r--p 00199000 08:02 394074                     /usr/lib/libc-2.20.so
7ffff7dd5000-7ffff7dd7000 rw-p 0019d000 08:02 394074                     /usr/lib/libc-2.20.so
7ffff7dd7000-7ffff7ddb000 rw-p 00000000 00:00 0 
7ffff7ddb000-7ffff7dfd000 r-xp 00000000 08:02 394051                     /usr/lib/ld-2.20.so
7ffff7fcd000-7ffff7fd0000 rw-p 00000000 00:00 0 
7ffff7ff7000-7ffff7ff8000 rwxp 00000000 00:00 0 
7ffff7ff8000-7ffff7ffa000 r-xp 00000000 00:00 0                          [vdso]
7ffff7ffa000-7ffff7ffc000 r--p 00000000 00:00 0                          [vvar]
7ffff7ffc000-7ffff7ffd000 r--p 00021000 08:02 394051                     /usr/lib/ld-2.20.so
7ffff7ffd000-7ffff7ffe000 rw-p 00022000 08:02 394051                     /usr/lib/ld-2.20.so
7ffff7ffe000-7ffff7fff000 rw-p 00000000 00:00 0 
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
{% endhighlight %}

The memory area used by *rolling* function was 7ffff7ff7000-7ffff7ff8000 
(line 12). The memory area that came after was 7ffff7ff8000-7ffff7ffa000 
(line 12) that was no writable, so that I got the segmentation fault.

In conclusion, there was some error in this challenge. IMHO, the challenge 
designer might want to apply the xor operation on dword but the array index was
somehow messed up. Very very upset to find out that I was stuck by this 
unintentional problem.
