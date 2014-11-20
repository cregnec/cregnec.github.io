---
layout: post
title: My solution for You like Python, security challenge and traveling?
tags: reverse engineering, python, quarkslab
category: blog
description:
    In September 2014, Quarkslab launched a Python challenge. I like pretty much python so I tried it. The challenge had two steps, a highly nested python lambda function and a custom python interpreter." By reversing the lambda function, I got the link for downloading the custom python interpreter. The second step is more interesting that required to reverse the obfuscated python opcodes.I learned much about python internals.
---

Contents
======
{:.no_toc}
*   toc
{:toc}

Warmup
======

The following code snippet presents the first step of this challenge.
It’s a highly nested *Python* lambda function. We need to find an URL
pointing to a file so that we can pass to the second step.

The first thing I’ve noticed is that the function takes 3 arguments *g,
c, d* and it has a default argument *\$* that is initialized to *None*.
In order to understand what does the function, I adopted a bottom-up
approach to dissect it, from the most nested one to the first one.

{% highlight python %}
(lambda g, c, d: (lambda _: (_.__setitem__('$', ''.join([(_['chr']
 if ('chr'in _) else chr)((_['_'] if ('_' in _) else _)) for _['_'
] in (_['s'] if ('s'in _) else s)[::(-1)]])), _)[-1])( (lambda _:
(lambda f, _: f(f, _))((lambda__,_: ((lambda _: __(__, _))((lambda
 _: (_.__setitem__('i', ((_['i'] if ('i'in _) else i) + 1)),_)[(-1
)])((lambda _: (_.__setitem__('s',((_['s'] if ('s'in _) else s) +
[((_['l'] if ('l' in _) else l)[(_['i'] if ('i' in _) else i)] ^ (
_['c'] if ('c' in _) else c))])), _)[-1])(_))) if (((_['g'] if ('g
' in_) else g) % 4) and ((_['i'] if ('i' in _) else i)< (_['len']
if ('len' in _) else len)((_['l'] if ('l' in _) else l)))) else _)
), _) ) ( (lambda _: (_.__setitem__('!', []), _.__setitem__('s', _
['!']), _)[(-1)] ) ((lambda _: (_.__setitem__('!', ((_['d'] if ('d
' in _) else d) ^ (_['d'] if ('d' in _) elsed))), _.__setitem__('i
', _['!']), _)[(-1)])((lambda _: (_.__setitem__('!', [(_['j'] if (
'j' in _) else j) for  _[ 'i'] in (_['zip'] if ('zip' in _) elsezi
p)((_['l0'] if ('l0' in _) else l0), (_['l1'] if ('l1' in _) else
l1)) for_['j'] in (_['i'] if ('i' in _) else i)]), _.__setitem__('
l', _['!']), _)[-1])((lambda _: (_.__setitem__('!', [1373, 1281, 1
288, 1373, 1290, 1294, 1375,1371,1289, 1281, 1280, 1293, 1289, 128
0, 1373, 1294, 1289, 1280, 1372, 1288,1375,1375, 1289, 1373, 1290,
 1281, 1294, 1302, 1372, 1355, 1366, 1372, 1302,1360, 1368, 1354,
1364, 1370, 1371, 1365, 1362, 1368, 1352, 1374, 1365, 1302]), _.__
setitem__('l1',_['!']), _)[-1])((lambda _: (_.__setitem__('!',[137
5,1368, 1294, 1293, 1373, 1295, 1290, 1373, 1290, 1293, 1280, 1368
, 1368,1294,1293, 1368, 1372, 1292, 1290, 1291, 1371, 1375, 1280,
1372, 1281, 1293,1373,1371, 1354, 1370, 1356, 1354, 1355, 1370, 13
57, 1357, 1302, 1366, 1303,1368,1354, 1355, 1356, 1303, 1366, 1371
]), _.__setitem__('l0', _['!']), _)[(-1)])
({ 'g': g, 'c': c, 'd': d, '$': None})))))))['$'])
{% endhighlight %}

In total, there are 7 lambda functions. I present first the final
pseudocode and the details of each function comes after. The pseudocode
is the following:

{% highlight python %}
(
  lambda g, c, d: (dollar=reversedS)(
      (s=listXorC) (
          (s=listofZip) (
              (setIto0)(
                  (ziplist)(
                      (list1)(
                          (list0)(
                            { 'g': g, 'c': c, 'd': d, '$': None}
                          )
                      )
                  )
              ) 
          ) 
      )
  )['$']
)
{% endhighlight %}
-   *list0* adds to the dictionary a list of integers with key ’l0’.

-   *list1* adds another list of integers with key ’l1’.

-   *ziplist* applies Python built-in function ZIP to ’l0’ and ’l1’

-   *setIto0* adds to the dictionary an element with value 0 (by XORing
    the argument *d* with itself) and key ’i’. ’i’ is used later as the
    counter of iteration.

-   *s=listofZip* creates a list ’s’ from the list of tuples created by
    ’ziplist’

-   *s=listXorC* applies XOR operation on each element of list ’s’ with
    the argument *c* in condition that the argument $g\%4 != 0$

-   *dollar=reversedS* sets ’\$’ to the character chain that contains
    each element of list ’s’ in the reversed order.

Therefore, I can trigger the decryption routine with g=2 (1, or 3),
c=key, d=0:
{% highlight python %}
>>> func = (lambda g, c, d: ...)
>>> for key in range(0x500, 0x500+100):
...   func(2, key, 0)
...
{% endhighlight %}

To find the right key (0x570), I’ve brute forced about 100 numbers and
the URL to the next step is the following:

    /blog.quarkslab.com/static/resources/b7d8438de09fffb12e39
    50e7ad4970a4a998403bdf3763dd4178adf

Custom Python interpreter
=========================

#### The goal:

to find the title of a fan song hidden in the program. Its salted SHA256
(with bacalhau as salt) is:

     61b42c223973996c797a9a366c64c3595052ff71089b4ff13d3251b66b6366e9

Built-in module: do\_not\_run\_me
---------------------------------

The commands *file* and *strings* revealed the following information.
For the reason of brevity, only some interesting strings are presented.
By reading other strings, it turned out that this file is a *Python
interpreter*.

{% highlight bash %}
$ mv b7d8438de09fffb12e3950e7ad4970a4a998403bdf3763dd4178adf python
$ file python python: ELF 64-bit LSB executable, x86-64, version 1
(SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.26, not
stripped
$ strings ./python
...
obfuscate/gen.pys
<genexpr>
Truet
quarkslabt
appendt
join(
obfuscate/gen.pyt
True(
Robert_Forsyth(
obfuscate/gen.pyt
There are two kinds of people in the world: those who say there is no
 such thing as infinite recursion, and those who say ``There are two
 kinds of people in the world: those who say there is no such thing 
as infinite recursion, and those who say ...
a9bd62e4d5f2+
nvcs/newopcodes
...
{% endhighlight %}

With IDA Pro, I found quickly the referece of these strings and discovered that a new built-in module is added.
{% highlight bash %}
$ export PYTHONPATH=/usr/lib/python2.7:/usr/lib/python2.7/plat-
linux2:/usr/lib/python2.7/lib-old:/usr/lib/python2.7/lib-dynloa
d:/usr/local/lib/python2.7/dist-packages:/usr/lib/python2.7/dis
t-packages:/usr/lib/pymodules/python2.7
$ chmod u+x ./python
$ ./python
>>> import sys
>>> sys.builtin_module_names
('_builtin_', '_main_', 'do_not_run_me', ...}
>>> import do_not_run_me
>>> dir(do_not_run_me)
['_doc_', '_name_', '_package_', 'run_me']
>>> do_not_run_me.run_me()
 Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  TypeError: function takes exactly 1 argument (0 given)
>>> do_not_run_me.run_me("aaaa")
zsh: segmentation fault  ./python
{% endhighlight %}
Built-in function: run\_me
--------------------------

After have tested the function *run\_me*, I found that it takes one
argument and usually generates a segmentation fault by calling it. So I
started to reverse this function. The assembler code of this function
can be found in the [Appendix](#appendix). The following pseudocode
presents the reversed *run\_me* function. It loads three functions and
executes them all. One of these functions in particular is read from
*run\_me*’s argument and the other two are loaded from memory.
Obviously, I needed to reverse the two functions loaded from memory.

{% highlight c %}
PyObject *run_me(PyObject *self, PyObject *args){
  char *input;
  int size;
  if(PyArg_ParseTuple(args, 's#', &input, &size)){
    PyObject* code_obj;
    code_obj = PyMarshal_ReadObjectFromString(0x56c940, 0x91);
    PyObject* incr = PyFunction_New(code_obj,
                        _PyThreadState_Current->frame->f_globals);
    PyObject* arg = PyTuple_New(0);
    PyObject_Call(incr, arg, NULL);

    code_obj = PyMarshal_ReadObjectFromString(input, size);
    PyObject* func = PyFunction_New(code_obj,
                        _PyThreadState_Current->frame->f_globals);
    arg = PyTuple_New(0);
    PyObject_Call(func, arg, NULL);

    code_obj = PyMarshal_ReadObjectFromString(0x56c720, 0x217);
    PyObject* decr = PyFunction_New(code_obj,
                        _PyThreadState_Current->frame->f_globals);
    arg = PyTuple_New(0);
    return PyObject_Call(decr, arg, NULL);
  }
  return NULL;
}
{% endhighlight %}

Analysis of functions called inside run\_me
-------------------------------------------

Firstly, I dumped the concerned memory zones with GDB. Then I tried the
Python package *dis*. But it couldn’t disassembly them because some
attributes were removed.
{% highlight bash %}
$ gdb -q ./python
Reading symbols from ./python...done.
gdb-peda$ dump memory incr.9351 0x56c940 0x56c940+0x91
gdb-peda$ dump memory decr.9357 0x56c720 0x56c720+0x217
gdb-peda$ q $ python2
>>> import marshal
>>> import dis
>>> code_obj = marshal.load(open("incr.9351"))
>>> code_obj
<code object foo at 0x7ffff7ec8d30, file "obfuscate/gen.py", line 5>
>>> dis.dis(code_obj)
6           0 LOAD_CONST               1 (1)
3 LOAD_CLOSURE             0
Traceback (most recent call last):
File "<stdin>", line 1, in <module>
File "/usr/lib/python2.7/dis.py", line 43, in dis
disassemble(x)
File "/usr/lib/python2.7/dis.py", line 107, in disassemble
print '(' + free[oparg] + ')',
IndexError: tuple index out of range
>>> code_obj = marshal.load(open("decr.9357"))
>>> code_obj
<code object foo at 0x7ffff7e77f30, file "obfuscate/gen.py", line 17>
>>> dis.dis(code_obj)
19     >>    0 LOAD_FAST                0
Traceback (most recent call last):
File "<stdin>", line 1, in <module>
File "/usr/lib/python2.7/dis.py", line 43, in dis
disassemble(x)
File "/usr/lib/python2.7/dis.py", line 101, in disassemble
print '(' + co.co_varnames[oparg] + ')',
IndexError: tuple index out of range
{% endhighlight %}

In Quarkslab's blog, there is another article *Building an obfuscated Python interpreter: we need more opcodes* that explains how to add new opcodes for a custom Python interpreter. In the same article,  author cites *Looking inside the (Drop) box)* that explained Dropbox was using a custom Python interpreter with permuted opcodes. I'm not sure that it's intended to be a hint, but it explains the challenge itself.

| Permuted opcode                          | Original opcode          |
|------------------------------------------|--------------------------|
| LOAD\_CLOSURE                            | STORE\_FAST              |
| LOAD\_FAST                               | LOAD\_GLOBAL             |
| STORE\_SUBSCR                            | BINARY\_ADD              |
| BINARY\_TRUE\_DIVIDE                     | RETURN\_VALUE            |
| CONTINUE\_LOOP                           | MAKE\_FUNCTION           |
| RETURN\_VALUE                            | GET\_ITER                |
| MAKE\_CLOSURE                            | CALL\_FUNCTION           |
| IMPORT\_STAR                             | POP\_TOP                 |
| SETUP\_WITH                              | LOAD\_FAST               |
| BUILD\_CLASS                             | YIELD\_VALUE             |
{: class="table"}

I checked that this Python interpreter does have permuted opcodes and a few new opcodes.The above table illustrates the permuted opcodes and their [original opcodes](https://docs.python.org/2/library/dis.html#python-bytecode-instructions) In order to revsere the permuted opcodes, I compared their assembler code with the [source code](http://svn.python.org/projects/python/trunk/Python/ceval.c). 
I've written a Python script that used *dis* package to map opcode and its name. The source code can be found in [Appendix](#appendix). As for the new opcodes, there are actually only two:

*    LOAD_CONST and setCustomOpcodeOffset

*    LOAD_CONST and unsetCustomOpcodeOffset

The first one is always called before the second in order to set up a jump conditon (setCustomOpcodeOffset) so that the following opcode will jump to the expected address.

{% highlight asm %}
  gdb-peda$ x/10i 0x4b18a5
  => 0x4b18a5 <PyEval_EvalFrameEx+4837>:  mov    rax,QWORD PTR [rsp+0x58]
  0x4b18aa <PyEval_EvalFrameEx+4842>:  movsxd r8,r8d
  0x4b18ad <PyEval_EvalFrameEx+4845>:  mov    r13,rcx
  0x4b18b0 <PyEval_EvalFrameEx+4848>:  add    rbp,0x8
  0x4b18b4 <PyEval_EvalFrameEx+4852>:  mov    r14d,0x1 ;setCustomOpcodeOffset
  0x4b18ba <PyEval_EvalFrameEx+4858>:  xor    ebx,ebx
  0x4b18bc <PyEval_EvalFrameEx+4860>:  mov    r12,QWORD PTR [rax+r8*8+0x18]
  0x4b18c1 <PyEval_EvalFrameEx+4865>:  add    QWORD PTR [r12],0x1
  0x4b18c6 <PyEval_EvalFrameEx+4870>:  mov    QWORD PTR [rbp-0x8],r12
  0x4b18ca <PyEval_EvalFrameEx+4874>:  jmp    0x4b08f1 <PyEval_EvalFrameEx+817>
{% endhighlight %}
The second opcode loads the value ’setCustomOpcodeOffset’ and use it as
an index for the jump table. Since the first opcode always set this
value to 1, the following opcode jumps to the same address and do a
LOAD\_CONST operation and unsetCustomOpcodeOffset, no matter what is its
opcode.

{% highlight asm %}
  gdb-peda$ x/10i 0x4b0938
  => 0x4b0938 <PyEval_EvalFrameEx+888>:   test   r14d,r14d
  0x4b093b <PyEval_EvalFrameEx+891>:   je     0x4b0950 <PyEval_EvalFrameEx+912>
  0x4b093d <PyEval_EvalFrameEx+893>:   cmp    r14d,0xad
  0x4b0944 <PyEval_EvalFrameEx+900>:   ja     0x4b0950 <PyEval_EvalFrameEx+912>
  0x4b0946 <PyEval_EvalFrameEx+902>:   jmp    QWORD PTR [r14*8+0x55e780]
  gdb-peda$ x/10i 0x4b1073
  => 0x4b1073 <PyEval_EvalFrameEx+2739>:  mov    rax,QWORD PTR [rsp+0x58]
  0x4b1078 <PyEval_EvalFrameEx+2744>:  movsxd r8,r8d
  0x4b107b <PyEval_EvalFrameEx+2747>:  mov    r13,rcx
  0x4b107e <PyEval_EvalFrameEx+2750>:  add    rbp,0x8
  0x4b1082 <PyEval_EvalFrameEx+2754>:  xor    r14d,r14d ;unsetCustomOpcodeOffset
  0x4b1085 <PyEval_EvalFrameEx+2757>:  xor    ebx,ebx
  0x4b1087 <PyEval_EvalFrameEx+2759>:  mov    r12,QWORD PTR [rax+r8*8+0x18]
  0x4b108c <PyEval_EvalFrameEx+2764>:  add    QWORD PTR [r12],0x1
  0x4b1091 <PyEval_EvalFrameEx+2769>:  mov    QWORD PTR [rbp-0x8],r12
  0x4b1095 <PyEval_EvalFrameEx+2773>:  jmp    0x4b08f1 <PyEval_EvalFrameEx+817>
{% endhighlight %}

In the following sections, I analyze the two code objects *incr.9351*
and *decr.9357* thanks to the previously created disassembler.

### incr.9351: code object at 0x56c940

As his name indicates, it add one to the global variable *’True’* and
store it.

{% highlight python %}
co_consts: (None, 1)
co_varnames: ('Robert_Forsyth',)
co_names: ('True',)
co_cellvars: ()

LOAD_CONST: 1     #co_consts[1]=1
STORE_FAST: 0
LOAD_GLOBAL: 0    #global variable 'True'
LOAD_CONST: 1     #co_consts[1]=1
BINARY_ADD        #add global variable 'True' by 1
STORE_GLOBAL: 0
LOAD_GLOBAL: 0
RETURN_VALUE
{% endhighlight %}

### decr.9357: code object at 0x56c720

This function first loads the global variable ’True’ and check if it’s
equal to 3. Then if the global variable ’quarkslab’ exists, it loads
two Python built-in functions *append* and *join*, one empty string and
another code object in memory. Actually there is no need to reverse this
code object, I found the right song title without studying it. Anyway,
I’ve put a few explanation of this code object in [Appendix](#appendix).
 Then it creates a new function with this code object.
After that, it builds a list of integers and call the new function by
passing this list as argument. Finally it creates a string by
concatenating all elements in the list generated by previous function,
append this string to the global variable ’quarkslab’ and return.

{% highlight python %}
co_consts: (None, 3, 1, '', <code object <genexpr> at 0x7ffff7e77eb0,
 file "obfuscate/gen.py", line 22>, 75, 98, 127, 45, 89, 101, 104,
 67, 122, 65, 120, 99, 108, 95, 125, 111, 97, 100, 110)
co_varnames: ()
co_names: ('True', 'quarkslab', 'append', 'join')
co_cellvars: ()
LOAD_GLOBAL: 0          #global variable 'True'
LOAD_CONST: 1           #co_consts[1]=3
COMPARE_OP: 3           #dis.cmp_op[3]="!="
POP_JUMP_IF_FALSE: 25   #jump if variable 'True' equal to 3

LOAD_GLOBAL: 1          #global variable 'quarkslab'
LOAD_ATTR: 2            #getattr(quarkslab, 'append')
LOAD_CONST: 3           #co_consts[3]=''
LOAD_ATTR: 3            #getattr(quarkslab, 'join')
LOAD_CONST: 4           #co_consts[4]=code object <genexpr>
MAKE_FUNCTION: 0

LOAD_CONST: 5           #co_consts[5]
LOAD_CONST: 6           #co_consts[6]
LOAD_CONST: 7           #co_consts[7]
LOAD_CONST: 8           #co_consts[8]
LOAD_CONST: 9           #co_consts[9]
LOAD_CONST: 10          #co_consts[10]
LOAD_CONST: 11          #co_consts[11]
LOAD_CONST: 8           #co_consts[12]
LOAD_CONST: 12          #co_consts[11]
LOAD_CONST: 11          #co_consts[13]
LOAD_CONST: 13          #co_consts[8]
LOAD_CONST: 8           #co_consts[6]
LOAD_CONST: 14          #co_consts[14]
LOAD_CONST: 15          #co_consts[15]
LOAD_CONST: 16          #co_consts[16]
LOAD_CONST: 17          #co_consts[17]
LOAD_CONST: 7           #co_consts[7]
LOAD_CONST: 8           #co_consts[8]
LOAD_CONST: 18          #co_consts[18]
LOAD_CONST: 11          #co_consts[11]
LOAD_CONST: 19          #co_consts[19]
LOAD_CONST: 15          #co_consts[15]
LOAD_CONST: 20          #co_consts[20]
LOAD_CONST: 21          #co_consts[21]
LOAD_CONST: 22          #co_consts[22]
LOAD_CONST: 23          #co_consts[23]
BUILD_LIST: 26          #list0
GET_ITER
CALL_FUNCTION: 1        #list1=genexpr(iter(list0))
CALL_FUNCTION: 1        #str0=''.join(list1)
CALL_FUNCTION: 1        #quarkslab.appen(str0)
POP_TOP
LOAD_CONST: 0
RETURN_VALUE

{% endhighlight %}
Solution
--------

In conclusion, *run\_me* function first reads a code object from
argument. Then it calls *incr.9351* that increments the global variable
’True’ to 2. After this, the submitted code object is called and
finally the function *decr.9357*. In order to call the in memory code
object *genexpr*, two conditions should be satisfied:

1.  the global variable ’True’ = 3.

2.  the global variable ’quarkslab’ is a not empty list.

My solution is simple: pass the same code object as *incr.9351* and set
the global variable ’quarkslab’ before calling *run\_me*.

{% highlight python %}
$ cat ./run_me.py
from do_not_run_me import run_me                                                                                                                                                 
global quarkslab                                                                                                                                                                 
quarkslab = ['aaa']                                                                                                                                                              
run_me(open('incr.9351').read())
print(quarkslab[-1])

$ ./python ./run_me.py
For The New Lunar Republic
$ echo -n 'bacalhauFor The New Lunar Republic' | sha256sum
61b42c223973996c797a9a366c64c3595052ff71089b4ff13d3251b66b6366e9  -
{% endhighlight %}

Appendix
========

run\_me
-------

{% highlight python linenos%}
gdb -q ./python
Reading symbols from ./python...done.
gdb-peda$ disassemble run_me
Dump of assembler code for function run_me:
   0x0000000000513d90 <+0>:     push   rbp
   0x0000000000513d91 <+1>:     mov    rdi,rsi
   0x0000000000513d94 <+4>:     xor    eax,eax
   0x0000000000513d96 <+6>:     mov    esi,0x56c70b
   0x0000000000513d9b <+11>:    push   rbx
   0x0000000000513d9c <+12>:    sub    rsp,0x28
   0x0000000000513da0 <+16>:    lea    rcx,[rsp+0x10]
   0x0000000000513da5 <+21>:    mov    rdx,rsp
   0x0000000000513da8 <+24>:    call   0x4cf430 <PyArg_ParseTuple>
   0x0000000000513dad <+29>:    xor    edx,edx
   0x0000000000513daf <+31>:    test   eax,eax
   0x0000000000513db1 <+33>:    je     0x513e5e <run_me+206>
   0x0000000000513db7 <+39>:    mov    rax,QWORD PTR [rip+0x2d4342]
   0x0000000000513dbe <+46>:    mov    esi,0x91
   0x0000000000513dc3 <+51>:    mov    edi,0x56c940
   0x0000000000513dc8 <+56>:    mov    rax,QWORD PTR [rax+0x10]
   0x0000000000513dcc <+60>:    mov    rbx,QWORD PTR [rax+0x30]
   0x0000000000513dd0 <+64>:    call   0x4dc020 <PyMarshal_ReadObjectFromString>
   0x0000000000513dd5 <+69>:    mov    rdi,rax
   0x0000000000513dd8 <+72>:    mov    rsi,rbx
   0x0000000000513ddb <+75>:    call   0x52c630 <PyFunction_New>
   0x0000000000513de0 <+80>:    xor    edi,edi
   0x0000000000513de2 <+82>:    mov    rbp,rax
   0x0000000000513de5 <+85>:    call   0x478f80 <PyTuple_New>
   0x0000000000513dea <+90>:    xor    edx,edx
   0x0000000000513dec <+92>:    mov    rdi,rbp
   0x0000000000513def <+95>:    mov    rsi,rax
   0x0000000000513df2 <+98>:    call   0x422b40 <PyObject_Call>
   0x0000000000513df7 <+103>:   mov    rsi,QWORD PTR [rsp+0x10]
   0x0000000000513dfc <+108>:   mov    rdi,QWORD PTR [rsp]
   0x0000000000513e00 <+112>:   call   0x4dc020 <PyMarshal_ReadObjectFromString>
   0x0000000000513e05 <+117>:   mov    rsi,rbx
   0x0000000000513e08 <+120>:   mov    rdi,rax
   0x0000000000513e0b <+123>:   call   0x52c630 <PyFunction_New>
   0x0000000000513e10 <+128>:   xor    edi,edi
   0x0000000000513e12 <+130>:   mov    rbp,rax
   0x0000000000513e15 <+133>:   call   0x478f80 <PyTuple_New>
   0x0000000000513e1a <+138>:   xor    edx,edx
   0x0000000000513e1c <+140>:   mov    rdi,rbp
   0x0000000000513e1f <+143>:   mov    rsi,rax
   0x0000000000513e22 <+146>:   call   0x422b40 <PyObject_Call>
   0x0000000000513e27 <+151>:   mov    esi,0x217
   0x0000000000513e2c <+156>:   mov    edi,0x56c720
   0x0000000000513e31 <+161>:   mov    rbp,rax
   0x0000000000513e34 <+164>:   call   0x4dc020 <PyMarshal_ReadObjectFromString>
   0x0000000000513e39 <+169>:   mov    rsi,rbx
   0x0000000000513e3c <+172>:   mov    rdi,rax
   0x0000000000513e3f <+175>:   call   0x52c630 <PyFunction_New>
   0x0000000000513e44 <+180>:   xor    edi,edi
   0x0000000000513e46 <+182>:   mov    rbx,rax
   0x0000000000513e49 <+185>:   call   0x478f80 <PyTuple_New>
   0x0000000000513e4e <+190>:   xor    edx,edx
   0x0000000000513e50 <+192>:   mov    rsi,rax
   0x0000000000513e53 <+195>:   mov    rdi,rbx
   0x0000000000513e56 <+198>:   call   0x422b40 <PyObject_Call>
   0x0000000000513e5b <+203>:   mov    rdx,rbp
   0x0000000000513e5e <+206>:   add    rsp,0x28
   0x0000000000513e62 <+210>:   mov    rax,rdx
   0x0000000000513e65 <+213>:   pop    rbx
   0x0000000000513e66 <+214>:   pop    rbp
   0x0000000000513e67 <+215>:   ret
End of assembler dump.
{% endhighlight %}

disassembler.py
---------------
{% highlight python lineos %}
import dis
import marshal
from binascii import hexlify

permutedOpcodes = [ 0 for i in range(0x100) ]
permutedOpcodes[0x87] = dis.opmap['STORE_FAST']
permutedOpcodes[0x7c] = dis.opmap['LOAD_GLOBAL']
permutedOpcodes[0x3c] = dis.opmap['BINARY_ADD']
permutedOpcodes[0x1b] = dis.opmap['RETURN_VALUE']
permutedOpcodes[0x77] = dis.opmap['MAKE_FUNCTION']
permutedOpcodes[0x53] = dis.opmap['GET_ITER']
permutedOpcodes[0x86] = dis.opmap['CALL_FUNCTION']
permutedOpcodes[0x54] = dis.opmap['POP_TOP']
permutedOpcodes[0x8f] = dis.opmap['LOAD_FAST']
permutedOpcodes[0x59] = dis.opmap['YIELD_VALUE']

def disassembly(code):
    i = 0
    customOpcode = False
    hex_code = hexlify(code)
    while i < len(hex_code):
        opcode = int(hex_code[i:i+2], 16)
        i += 2
        #remap permuted opcodes
        if permutedOpcodes[opcode] != 0:
            opcode = permutedOpcodes[opcode]

        if opcode > 0x59:
            operand = (int(hex_code[i:i+2], 16) + (int(hex_code[i+2:i+4], 16)<<8) )
            i += 4
            if opcode == 0xa0:
                print("LOAD_CONST: %d and setCustomOpcodeOffset"%(operand))
                customOpcode = True
            elif customOpcode:
                print("LOAD_CONST: %d and unsetCustomOpcodeOffset"%(operand))
                customOpcode = False
            else:
                print("%s: %d"%(dis.opname[opcode], operand))

            if opcode == dis.opmap['POP_JUMP_IF_FALSE']:
                print("######Start of disassembling jmp target######")
                disassembly(code[operand:])
                print("######End of disassembling jmp target######")
            elif opcode == dis.opmap['JUMP_FORWARD']:
                i += operand * 2
        else:
            print("%s"%(dis.opname[opcode]))

incr = marshal.load(open("incr.9351", "rb"))
decr = marshal.load(open("decr.9357", "rb"))


print("########Disassembling incr.9351########")
code = incr.co_code
print("co_consts: %s"%repr(incr.co_consts))
print("co_varnames: %s"%repr(incr.co_varnames))
print("co_names: %s"%repr(incr.co_names))
print("co_cellvars: %s"%repr(incr.co_cellvars))
disassembly(code)

print("######Disassembling decr.9357#######")
code = decr.co_code
print("co_consts: %s"%repr(decr.co_consts))
print("co_varnames: %s"%repr(decr.co_varnames))
print("co_names: %s"%repr(decr.co_names))
print("co_cellvars: %s"%repr(decr.co_cellvars))
disassembly(code)

print("######Disassembling genexpr#######")
disassembly(decr.co_consts[4].co_code)
{% endhighlight %}

code object genexpr
-------------------
This function apply a XOR operation on each element in the list with the
value 13.

{% highlight python %}
co_consts: (13, None)
%co_varnames: ('.0', '_')
co_names: ('chr',)
co_cellvars: ()

LOAD_FAST: 0
FOR_ITER: 21
STORE_FAST: 1
LOAD_GLOBAL: 0
LOAD_FAST: 1
LOAD_CONST: 0
INPLACE_XOR
CALL_FUNCTION: 1
YIELD_VALUE
POP_TOP
JUMP_ABSOLUTE: 3
LOAD_CONST: 1
RETURN_VALUE
{% endhighlight %}
