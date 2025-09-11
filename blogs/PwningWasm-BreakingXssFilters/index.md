---
layout: default
title: "Pwning WebAssembly: Bypassing XSS Filters in the WASM Heap Sandbox"
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
        <h3><code>Pwning WebAssembly: Bypassing XSS Filters in the WASM Heap Sandbox</code></h3>
            <p>
                Lately, I’ve been trying to level up my pwn game, so I decided to dive into WebAssembly security. 
                Everyone hypes WASM as this safe, sandboxed thing that makes running C/C++ in the browser “secure,” 
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
        To wrap up this deep dive into WebAssembly security, let’s look at a vulnerable web application challenge from <code>Pentathon CTF 2025, called "chaat"</code>. This challenge demonstrates how a seemingly safe WASM app can still be exploited due to logic flaws and insecure data handling to drop a XSS payload. You can download the vulnerable application files <a href="{{ '/blogs/PwningWasm-BreakingXssFilters/assets/' | relative_url }}">here</a> and try it out yourself.
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
                <li><em>msg_data</em>: Pointer to dynamically allocated memory holding the actual text.</li>
                <li><em>msg_data_len</em>: The length of the message (after sanitization).</li>
                <li><em>msg_time</em>: A timestamp (Unix epoch) indicating when it was created.</li>
                <li><em>msg_status</em>: Status flags (e.g., edited or not).</li>
            </ul>
            </li>
            <li><strong>stuff</strong> — This is the chat application state, essentially a dynamic array of <code>msg</code> structs:
            <ul>
                <li><em>mess</em>: Pointer to a heap-allocated array of messages.</li>
                <li><em>size</em>: Number of messages currently stored.</li>
                <li><em>capacity</em>: Maximum number of messages allocated (grows dynamically).</li>
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
    </div>
    
</section>
</section>



<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/prism.min.js" integrity="sha512-UOoJElONeUNzQbbKQbjldDf9MwOHqxNz49NNJJ1d90yp+X9edsHyJoAs6O4K19CZGaIdjI5ohK+O2y5lBTW6uQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/components/prism-python.min.js" integrity="sha512-3qtI9+9JXi658yli19POddU1RouYtkTEhTHo6X5ilOvMiDfNvo6GIS6k2Ukrsx8MyaKSXeVrnIWeyH8G5EOyIQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/components/prism-c.min.js" integrity="sha512-EWIJI7uQnA8ClViH2dvhYsNA7PHGSwSg03FAfulqpsFiTPHfhdQIvhkg/l3YpuXOXRF2Dk0NYKIl5zemrl1fmA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/components/prism-javascript.min.js" integrity="sha512-yvw5BDA/GQu8umskpIOBhX2pDLrdOiriaK4kVxtD28QEGLV5rscmCfDjkrx52tIgzLgwzs1FsALV6eYDpGnEkQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>