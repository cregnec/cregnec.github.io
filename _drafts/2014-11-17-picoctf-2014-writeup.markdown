---
layout: post
title: picoctf 2014 writeup
category: blog
---

*[picoCTF](https://picoctf.com/) is a computer security game targeted at middle and high school students.* Never mind, I'm not a high school student, but I still did this ctf with my friends just for fun. Most of the challenges were straightforward except the last level ones. This ctf was designed for learning so that there was a hint for each challenge. I did four of them, three binary exploit (*Nevernote*, *CrudeCrypt*, *Fancy Cache*) and one reverse engineering (*Baleful*).

Nevernote
=========
*In light of the recent attacks on their machines, Daedalus Corp has implemented a buffer overflow detection library. Nevernote, a program made for Daedalus Corps employees to take notes, uses this library. 
Can you bypass their protection and read the secret?*

CrudeCrypt
==========
*Without proper maintainers, development of Truecrypt has stopped! CrudeCrypt has emerged as a notable alternative in the open source community. The author has promised it is 'secure' but we know better than that. Take a look at the code and read the contents of flag.txt*

Fancy Cache
============
*Margaret wrote a fancy in-memory cache server. For extra security, she made a custom string structure that keeps strings on the heap. However, it looks like she was a little sloppy with her mallocs and frees. Can you find and exploit a bug to get a shell?*


Baleful
=======
*This program seems to be rather delightfully twisted! Can you get it to accept a password? We need it to get access to some Daedalus Corp files.*
