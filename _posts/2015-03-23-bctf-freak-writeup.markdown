---
layout: post
title: BCTF 2015 freak writeup
category: blog
tags: ctf writeup reverse 
description: BCTF2015 freak reverse challenge
---

Introduction
========
This is actually a Microsoft Visual C++ 8 32bit executable. If you execute it in 
a cmd, nothing is displayed.
After a few checks in IDA, the interesting part is in *__cinit* function,
more precisely the following code.
{% highlight asm linenos %}
.text:00403151                 mov     dword ptr [esp], offset array_end
.text:00403158                 push    offset array_start
.text:0040315D                 call    callFuncInArray
{% endhighlight %}

The *callFuncInArray* executes every function that is between *array_start* and
*array_end*. Let's take a look at this array.

{% highlight asm linenos %}
.rdata:0040D13C array_start     dd 0                ; DATA XREF: __cinit+50o
.rdata:0040D140                 dd offset funcInit
.rdata:0040D144                 dd offset exceptionInit
{% endhighlight %}

It has indeed two function pointers. *funcInit* is responsible for loading
function addresses that are used later.

{% highlight asm linenos %}
.text:00401000 funcInit        proc near               ; DATA XREF:
...
.text:00401022                 mov     ReadFile_2, eax
.text:00401027                 mov     eax, ds:CryptAcquireContextW
.text:0040102C                 sub     eax, 2
.text:0040102F                 mov     CryptAcquireContextW_2, eax
.text:00401034                 mov     eax, ds:CryptStringToBinaryW
.text:00401039                 sub     eax, 2
.text:0040103C                 mov     CryptStringToBinaryW_2, eax
.text:00401041                 mov     eax, ds:CryptDecodeObjectEx
.text:00401046                 sub     eax, 2
.text:00401049                 mov     CryptDecodeObjectEx_2, eax
.text:0040104E                 mov     eax, ds:CryptImportPublicKeyInfo
.text:00401053                 sub     eax, 2
.text:00401056                 mov     CryptImportPublicKeyInfo_2, eax
.text:0040105B                 mov     eax, ds:CryptDecrypt
.text:00401060                 sub     eax, 2
.text:00401063                 mov     CryptDecrypt_2, eax
.text:00401068                 mov     eax, ds:CryptDestroyKey
...
.text:004010B6                 retn
.text:004010B6 funcInit        endp
{% endhighlight %}

Exception handler initialization
================================

While *exceptionInit* is the real main function. 

{% highlight asm linenos %}
.text:004010C0 exceptionInit   proc near               ; DATA XREF:
.text:004010C0                 call    ds:GetTickCount
.text:004010C6                 push    offset Handler  ; Handler
.text:004010CB                 push    1               ; First
.text:004010CD                 mov     tickCount_start, eax
.text:004010D2                 call    ds:AddVectoredExceptionHandler
.text:004010D8                 push    offset exceptionTrigger ; Ptr
.text:004010DD                 call    onexit
.text:004010E2                 add     esp, 4
.text:004010E5                 mov     dword_413FA0, 0
.text:004010EF                 retn
.text:004010EF exceptionInit   endp
{% endhighlight %}

Basically, this functions does three things:

    1) save the number of milliseconds that have elapsed since the system was started to *tickCount_start*
    2) add function *Handler* as the first exception handler
    3) set function *exceptionTrigger* to be called on program exit

#Exception Trigger

The function definition of *exceptionTrigger* is the following.
{% highlight asm linenos %}
.text:00401810 exceptionTrigger proc near              ; DATA XREF:exceptionInit+18o
.text:00401810                 int     1               ; - internal hardware - SINGLE-STEP
.text:00401812                 inc     ecx
.text:00401813                 mov     ecx, PtrBct2015
.text:00401819                 lea     edx, [ecx+1]
.text:0040181C                 lea     esp, [esp+0]
.text:00401820
.text:00401820 nextUntilZero:                          ; CODE XREF:
.text:00401820                 mov     al, [ecx]
.text:00401822                 inc     ecx
.text:00401823                 test    al, al
.text:00401825                 jnz     short nextUntilZero
.text:00401827                 sub     ecx, edx
.text:00401829                 lea     eax, [ecx+1]
.text:0040182C                 cmp     dataLen, eax
.text:00401832                 jnz     short loc_401837
.text:00401834                 int     1               ; - internal hardware -SINGLE-STEP
.text:00401836                 inc     edx
.text:00401837
.text:00401837 loc_401837:                             ; CODE XREF:
.text:00401837                 cmp     decryptedDataOk, 0
.text:0040183E                 jz      short locret_401843
.text:00401840                 int     1               ; - internal hardware - SINGLE-STEP
.text:00401842                 inc     ebx
.text:00401843
.text:00401843 locret_401843:                          ; CODE XREF:
.text:00401843                 retn
.text:00401843 exceptionTrigger endp
{% endhighlight %}

As we can see above, this function will generate three exceptions, at line 2,
17, 23 respectively. At each exception, the pre-defined handler function *Handler* will be
executed. *Handler* is actually the orchestrator that controls the program's
execution.

Handler - orchestrator
======================

{% highlight asm linenos %}
.text:00401740 ; LONG __stdcall Handler(struct _EXCEPTION_POINTERS *ExceptionInfo)
.text:00401740 Handler         proc near               ; DATA XREF:
.text:00401740
.text:00401740 ExceptionInfo   = dword ptr  8
.text:00401740
.text:00401740                 push    ebp
.text:00401741                 mov     ebp, esp
.text:00401743                 call    ds:GetTickCount
.text:00401749                 mov     tickCount_exception, eax
.text:0040174E                 sub     eax, tickCount_start
.text:00401754                 cmp     eax, 20h
.text:00401757                 jbe     short loc_401761
.text:00401759                 push    0               ; uExitCode
.text:0040175B                 call    ds:ExitProcess
{% endhighlight %}
*Handler* function first checks the time elapsed between *tickCount_start* and its
execution. If the delta is bigger than 20h, it will quit. In order to bypass
this, just patch *jbe* instruction to *ja*.

Then *Handler* function executes different check routine depending on the
address that generates the exception. More precisely, code from line 1 to 21 is
responsible for the exception generated at 00401810, code from line 25 to 41
for the exception generated at 00401834 and code from line 43 to 57 for
exception generated at 00401840.

{% highlight asm linenos %}
.text:00401761 ;
---------------------------------------------------------------------------
.text:00401761                 mov     edx, [ebp+ExceptionInfo]
.text:00401764                 mov     eax, [edx]      ; ExceptionRecord
.text:00401766                 mov     ecx, [eax+0Ch]  ; ExceptionAddress
.text:00401769                 cmp     byte ptr [ecx], 0CDh ; Opcode check
.text:0040176C                 jnz     loc_401805
.text:00401772                 mov     al, [ecx+2]          ; Opcode check
.text:00401775                 cmp     al, 41h
.text:00401777                 jnz     short loc_4017A5
.text:00401779                 mov     eax, [edx+4]    ; ContextRecord
.text:0040177C                 add     ecx, 3          ; ExceptionAddress+3
.text:0040177F                 add     dword ptr [eax+0C4h], 0FFFFFFFCh
.text:00401786                 mov     eax, [edx+4]
.text:00401789                 mov     eax, [eax+0C4h] ; esp
.text:0040178F                 mov     [eax], ecx      ; return address
.text:00401791                 mov     eax, [edx+4]
.text:00401794                 mov     dword ptr [eax+0B8h], offset decryptData ; eip
.text:0040179E                 or      eax, 0FFFFFFFFh
.text:004017A1                 pop     ebp
.text:004017A2                 retn    4
.text:004017A5 ;
---------------------------------------------------------------------------
.text:004017A5
.text:004017A5 loc_4017A5:                             ; CODE XREF: Handler+37
.text:004017A5                 cmp     al, 42h
.text:004017A7                 jnz     short loc_4017D5
.text:004017A9                 mov     eax, [edx+4]
.text:004017AC                 add     ecx, 3
.text:004017AF                 add     dword ptr [eax+0C4h], 0FFFFFFFCh
.text:004017B6                 mov     eax, [edx+4]
.text:004017B9                 mov     eax, [eax+0C4h]
.text:004017BF                 mov     [eax], ecx
.text:004017C1                 mov     eax, [edx+4]
.text:004017C4                 mov     dword ptr [eax+0B8h], offset checkDecryptedData
.text:004017CE                 or      eax, 0FFFFFFFFh
.text:004017D1                 pop     ebp
.text:004017D2                 retn    4
.text:004017D5 ;
---------------------------------------------------------------------------
.text:004017D5
.text:004017D5 loc_4017D5:                             ; CODE XREF: Handler+67
.text:004017D5                 cmp     al, 43h
.text:004017D7                 jnz     short loc_401805
.text:004017D9                 mov     eax, [edx+4]
.text:004017DC                 add     ecx, 3
.text:004017DF                 add     dword ptr [eax+0C4h], 0FFFFFFFCh
.text:004017E6                 mov     eax, [edx+4]
.text:004017E9                 mov     eax, [eax+0C4h]
.text:004017EF                 mov     [eax], ecx
.text:004017F1                 mov     eax, [edx+4]
.text:004017F4                 mov     dword ptr [eax+0B8h], offset rc4
.text:004017FE                 or      eax, 0FFFFFFFFh
.text:00401801                 pop     ebp
.text:00401802                 retn    4
{% endhighlight %}
For each exception, *Handler* retrieves the address of exception (line 3 to
line 5), checks the opcodes (line 6 to 10, 26, 27 and 43, 44), call different
routines (line 18, 35 and 52) and sets the return address to
the_exception_address + 3 (line 12, 29, 46).  To better understand this part,
please refer to the offical microsoft documentation:
[EXCEPTION_POINTER](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679331(v=vs.85).aspx)
[EXCEPTION_RECORD](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363082(v=vs.85).aspx)
[CONTEXT](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679284(v=vs.85).aspx).

Decryption check
================

The first handler *decryptData*'s behavoir can be resumed as following:

    1) Open existing file *Critical:Secret*
    2) Read file content
    3) Create cryptography context
    4) Import a public key (that is hardcoed in the program)
    5) Decrypt the file content (with the public key? I missed this part, if anyone knows please let me know)
    6) If decryption has no error, return the decrypted data and its size.

As explained above, after each exception, the return address will be set to
the_exception_address + 3. This means that after the execution of handler
function, we will go back to [Exception Trigger](#exception-trigger) function. 
So after the first exception generated at line 2 (please refer to the code of
[Exception Trigger](#exception-trigger) above), we continue the execution at line 4. The following
part (line 4 to line 16) implements a check on the size of decrypted data,
which should be 10. If the check is good, it will generate the second
exception. Otherwise, it quits.

XOR check
=========

The second exception generated at 0x0401834 will be handled by
*checkDecryptedData* function.
{% highlight asm linenos %}
.text:004014C0 checkDecryptedData proc near            ; DATA XREF: Handler+84
.text:004014C0
.text:004014C0 ms_exc          = CPPEH_RECORD ptr -18h
.text:004014C0
.text:004014C0                 push    ebp
.text:004014C1                 mov     ebp, esp
.text:004014C3                 push    0FFFFFFFEh      ; TryLevel
.text:004014C5                 push    offset ScopeTable
.text:004014CA                 push    offset ExceptionHandler
.text:004014CF                 mov     eax, large fs:0
.text:004014D5                 push    eax             ; Next
.text:004014D6                 sub     esp, 8
.text:004014D9                 push    ebx
.text:004014DA                 push    esi
.text:004014DB                 push    edi
.text:004014DC                 mov     eax, ___security_cookie
.text:004014E1                 xor     [ebp+ms_exc.registration.ScopeTable], eax
.text:004014E4                 xor     eax, ebp
.text:004014E6                 push    eax
.text:004014E7                 lea     eax, [ebp+ms_exc.registration]
.text:004014EA                 mov     large fs:0, eax
.text:004014F0                 mov     [ebp+ms_exc.old_esp], esp
.text:004014F3                 mov     [ebp+ms_exc.registration.TryLevel], 0
.text:004014FA                 xor     ecx, ecx
.text:004014FC                 idiv    ecx
.text:004014FE                 jmp     short loc_401561
.text:00401500 ;
{% endhighlight %}

*checkDecryptedData* generates also an exception at line 25. Note that this
exception will be handled by another function instead of *Handler*. Because
from line 7 to 12, a frame-based exception was added. The following code
illustrates the data structure provided by IDA.
{% highlight asm linenos %}
00000000 CPPEH_RECORD    struc ; (sizeof=0x18, align=0x4) 
00000000 old_esp         dd ?                    ; 
00000004 exc_ptr         dd ?                    ;
00000008 registration    _EH3_EXCEPTION_REGISTRATION ? 
00000018 CPPEH_RECORD    ends
00000000
00000000 _EH3_EXCEPTION_REGISTRATION struc ; (sizeof=0x10, align=0x4)
00000000 Next            dd ?
00000000                     
00000008 ScopeTable      dd ?
00000008                     
0000000C TryLevel        dd ?
00000010 _EH3_EXCEPTION_REGISTRATION ends
{% endhighlight %}

This handler function is actually defined in *ScopeTable* structure as shown
below.
{% highlight asm linenos %}
.rdata:00411198 ScopeTable      dd 0FFFFFFFEh           ; GSCookieOffset
.rdata:00411198                 dd 0                    ; GSCookieXOROffset ;
.rdata:00411198                 dd 0FFFFFFD8h           ; EHCookieOffset
.rdata:00411198                 dd 0                    ; EHCookieXOROffset
.rdata:00411198                 dd 0FFFFFFFEh           ; ScopeRecord.EnclosingLevel
.rdata:00411198                 dd offset loc_401500    ; ScopeRecord.FilterFunc
.rdata:00411198                 dd offset divBy0Handler ; ScopeRecord.HandlerFunc
{% endhighlight %}

In my IDA, I called this function *divBy0Handler*.
{% highlight asm linenos %}
.text:00401506 divBy0Handler:                          ; DATA XREF:.rdata:ScopeTable
.text:00401506                 mov     esp, [ebp+ms_exc.old_esp] 
.text:00401509                 xor     edx, edx
.text:0040150B                 mov     ebx, decryptedData
.text:00401511                 mov     esi, PtrBctf2015 ;"BCT2015!"
.text:00401517
.text:00401517 loc_401517:                             ; CODE XREF:
.text:00401517                 mov     eax, esi
.text:00401519                 lea     edi, [eax+1]
.text:0040151C                 lea     esp, [esp+0]
.text:00401520
.text:00401520 loc_401520:                             ; CODE XREF:
.text:00401520                 mov     cl, [eax]
.text:00401522                 inc     eax
.text:00401523                 test    cl, cl
.text:00401525                 jnz     short loc_401520
.text:00401527                 sub     eax, edi
.text:00401529                 cmp     edx, eax
.text:0040152B                 jnb     short loc_401557
.text:0040152D                 mov     al, [ebx+edx+1] ;decryptedData[i+1]
.text:00401531                 xor     al, [ebx+edx]   ;decryptedData[i]
.text:00401534                 cmp     al, [esi+edx]   ;PtrBctf2015[i]
.text:00401537                 jnz     short loc_40153C
.text:00401539                 inc     edx
.text:0040153A                 jmp     short loc_401517
{% endhighlight %}

This function implements another check on the decrypted data. Basically, the
decrypted data should satisfy this condition *decryptedData[i+1] ^
decryptedData[i] = PtrBctf2015[i]* where *PtrBctf2015* is the string
"BCT2015!".
If this check passed, we will go back to  [Exception Handler](#exception-trigger) the last time and
generate the last exception, which will trigger the execution of *rc4* function.

RC4 decryption
==============

{% highlight asm linenos %}
.text:004016D0 rc4             proc near 
...
.text:004016E3                 push    102h            ; size_t
.text:004016E8                 lea     eax, [ebp+rc4Blob]
.text:004016EE                 push    0               ; int
.text:004016F0                 push    eax             ; rc4blob
.text:004016F1                 call    _memset
.text:004016F6                 mov     edx, dataLen    ; dataSize
.text:004016FC                 lea     eax, [ebp+rc4Blob]
.text:00401702                 mov     ecx, decryptedData ; decryptedData
.text:00401708                 push    eax             ; size
.text:00401709                 call    rc4Init
.text:0040170E                 mov     ecx, ptr_ptr_rc4_encrypted
.text:00401714                 lea     eax, [ebp+rc4Blob]
.text:0040171A                 push    eax             ; rc4blob
.text:0040171B                 mov     edx, [ecx+4]    ; rc4_encrypted_data_size
.text:0040171E                 mov     ecx, [ecx]      ; rc4_encrypted_data
.cext:00401720                 call    rc4Decrypt
...
{% endhighlight %}
As its name indicates, this function use *decryptedData* as key for the RC4
algorithm to decrypt some data. Since we know that *decryptedData* should
satisfy the condition *decryptedData[i+1] ^ decryptedData[i] = PtrBctf2015[i]*,
we have only 256 possible keys. In order to decrypt the message, we can just 
brute force the RC4 key (I missed this idea in the ctf). 

{% highlight python linenos %}
cat bt.py
import rc4                                                                      
import sys                                                                      
import string                                                                   
                                                                                
def xor(byte, choices, key, letter):                                            
    for j in choices:                                                           
        if byte ^ j == ord(letter):                                             
            key.append(j)                                                       
                                                                                
encrypted = open("rc4_encrypted", "rb").read()[0:98]                            
bytes_array = [ i for i in range(0x100)]                                        
check_string = "BCTF2015!"                                                      
                                                                                
for k0 in bytes_array:                                                          
    key = []                                                                    
    key.append(k0)                                                              
                                                                                
    for i, letter in enumerate(check_string):                                   
        xor(key[i], bytes_array, key, letter)                                   
    #rc4 decrypt                                                                
    keystream = rc4.RC4(key)                                                    
    output = ''                                                                 
    ok = True                                                                   
    for c in encrypted:                                                         
        c = chr(ord(c) ^ keystream.next())                                      
        if c not in string.printable:                                           
            ok = False                                                          
            break                                                               
        output += c                                                             
    if ok:                                                                      
        print(output)                                                           

python2 bt.py
Ok, take it easy!
The REAL Flag is BCTF{Hex(Prime1^Prime2).upper()}.
No '0x' before the hex value.
{% endhighlight %}
After have dumped the RC4 encrypted data, I used the script above to get the 
clear message, with [this RC4 script](https://github.com/bozhu/RC4-Python/blob/master/rc4.py).
To get the final flag, all we need to do is crack the public key inside *decryptData*
function. Well, I can't really help for the RSA stuff. Maybe you can try
[this](http://cado-nfs.gforge.inria.fr/).
