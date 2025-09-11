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
            <p>
                Lately, I’ve been trying to level up my pwn game, so I decided to dive into WebAssembly security. 
                Everyone hypes WASM as this safe, sandboxed thing that makes running C/C++ in the browser “secure,” 
                but the more I played with it, the more I realized there’s a lot going on under the hood that most devs 
                don’t even think about. It’s fast, yeah, but that speed comes with complexity: weird memory models, JS glue code, 
                runtimes, and a whole new attack surface. This post is basically me dumping what I’ve been learning so far — 
                how WASM works, what it does well, and where it can be broken.
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
                <li><a href="#direct-vs-indirect">Direct vs Indirect Calls in WASM</a></li>
                <li><a href="#attack-surface">The Real Attack Surface in WASM</a></li>
                <li><a href="#rust-wasm">Rust and WASM: Memory Safety. </a></li>
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
            When you write code in <code>C</code>, <code>C++</code>, or <code>Rust</code> and compile it to WASM, 
            you’re essentially turning it into a tiny binary program designed to run safely and fast on any platform. 
            Think of it as a <code>virtual CPU</code> that lives inside your browser tab.
        </p>
        <p>
            Here’s what actually happens: your high-level code hits a compiler like 
            <code>Emscripten</code> or Rust’s <code>wasm32-unknown-unknown</code> target, 
            and out comes WASM bytecode — a compact, low-level binary format. 
            This bytecode isn’t tied to your machine’s CPU; it’s designed to run inside a 
            <code>sandboxed virtual machine</code>. 
            That’s why WASM is portable — the same <code>.wasm</code> file can run on Chrome, Firefox, 
            or Node.js with almost identical performance.
        </p>
        <p>
            The <code>V8 engine</code> (used in Chrome and Edge) starts by parsing this binary. 
            Think of it as unpacking a box full of labeled components: functions, variables, memory blocks, 
            and function tables. V8 doesn’t execute anything yet; it’s just organizing the pieces 
            in a way that makes them runnable:
        </p>
        <ul>
            <li>
                <code>Functions:</code> Every function you wrote in C, Rust, or C++ becomes a WASM function. 
                V8 builds an internal function table mapping each WASM function to a memory location.
            </li>
            <li>
                <code>Globals:</code> Variables shared across functions — counters, flags, constants — 
                are stored in a global section for quick access.
            </li>
            <li>
                <code>Memory segments:</code> Arrays, strings, and static data are placed in linear memory, 
                forming the module’s memory space.
            </li>
            <li>
                <code>Tables:</code> Jump tables for indirect calls or virtual functions in C/C++ 
                allow dynamic function dispatch.
            </li>
        </ul>
        <p>
            At this stage, everything is defined but <code>not yet executing</code>. 
            The pieces are ready, waiting for execution to begin.
        </p>
    </div>
    <div id="tiered-compilation" class="section-content">
        <h4 class='text'>Tiered Compilation: Liftoff and Turbofan (also Maglev in modern v8 Engine)</h4>
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
        </ul>
        <p>
            After a few iterations, the same function that first ran through Liftoff 
            is now executing at <code>near-native CPU speed</code>, 
            making WASM code feel almost indistinguishable from native applications.
        </p>
    </div>
    <div id="memory-model" class="section-content">
    <h4 class='text'>Memory Model: The Heart of the Sandbox</h4>
    <p>
        One of the most important concepts to understand in WebAssembly (<code>WASM</code>) security is its memory model. 
        Unlike higher-level languages that abstract away memory management, or native applications that work directly with system memory, 
        <code>WASM</code> takes a very particular approach: it gives each module a single, flat, contiguous block of memory called <code>linear memory</code>.
    </p>
    <p>
        This design choice makes <code>WASM</code> both efficient and relatively safe — but it also defines the limits and behaviors that an attacker must consider. 
        Let’s walk through how this “sandboxed memory apartment” is structured.
    </p>
    <h6 class="sidetext">Linear Memory: The WASM Sandbox</h6>
    <p>
        At its core, linear memory is just a giant array of bytes. Imagine you started your program with:
    </p>
    <pre><code class="language-python">char memory[65536]; // 64 KB</code></pre>
    <p>
        That’s essentially what WASM gives you at the start — one continuous region of memory that your module can read from and write to. 
        When you compile <code>C</code>, <code>C++</code>, or <code>Rust</code> code to <code>WASM</code>, all variables, arrays, and data structures are mapped into this space.
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
        This is the sandbox guarantee: your module is isolated from the world outside. No matter what bugs exist in your code, they can’t overwrite Browser's process memory or the Or the renderer's memory.
    </p>
    <p><code>At least, that’s what they claim. They say WASM is safe, but sandbox escapes to renderer process keep proving otherwise.</code></p>
     <h6 class="sidetext">Bugs Still Matter (Inside the Sandbox)</h6>
    <p>
        However, mistakes inside the apartment can still cause chaos. Consider this example in <code>C</code>:
    </p>
    <pre><code class="language-c">
int arr[10];
arr[11] = 42; // out-of-bounds write
    </code></pre>
    <p>
        On a native system, this could overwrite a saved return address, change control flow, corrupt unrelated process memory, or crash the entire application.
        On <code>WASM</code>, <code>arr</code> can’t reach outside the sandbox. But it can corrupt another piece of data within the module’s own linear memory.
        Maybe it overrides a cryptographic key, an index into a function table, or user input buffers. That’s still dangerous — just not system-level catastrophic.
    </p>
    <h6 class="sidetext">Memory Growth and Limits</h6>
    <p>
        Linear memory isn’t infinite; it’s divided into fixed-size pages of 64 KB each. When a <code>WASM</code> module starts, it requests an initial number of pages (say, 1 page = 64 KB).
        As the program runs, it can explicitly request more pages if needed — for example, a game suddenly loading a massive map, or an editor opening a large file.
        But the browser enforces an upper ceiling, so runaway programs can’t consume infinite memory. This paged growth mechanism keeps memory predictable and adds another safety layer.
    </p>
    <h4><code>Memory Pages in WASM: Code, Data, and More</code></h4>
    <p>
        It’s important to understand that <code>WASM</code> memory isn’t one big undifferentiated blob. Internally, the virtual machine separates things into different types of pages:
    </p>
    <h6 class="sidetext">Code Pages</h6>
    <p>
        Code — your actual executable instructions — does not live inside linear memory. Instead, compiled functions are placed in separate, read-only code pages.
        This design prevents accidental or malicious attempts to overwrite instructions in memory.
        In traditional native programs, code and data sometimes lived in the same region (<code>writable/executable memory</code>), which is how classic code injection attacks worked. 
        <code>WASM</code> blocks this by enforcing separation.
    </p>
    <p>Example:</p>
    <pre><code class="language-c">
int add_numbers(int a, int b) {
    return a + b;
}</code></pre>
    <p>
        The machine instructions for <code>add_numbers</code> live in a code page. The integers <code>a</code> and <code>b</code> live in linear memory (data pages).
        While the CPU executes the function, it fetches instructions from the code page and operates on values inside linear memory.
        The key is that those two memory regions cannot overlap. You can’t store instructions in linear memory and then trick the engine into executing them.
    </p>
    <h6 class='sidetext'>Linear Memory Pages (Data)</h6>
    <p>
        The actual working storage of your program — arrays, structs, buffers, strings, global variables — all live in linear memory data pages.
        Every function shares this memory pool, which is both a performance advantage (fast data exchange) and a risk factor (bugs in one function spill into others).
    </p>
    <p>Example:</p>
    <ul>
        <li>In an image editor compiled to <code>WASM</code>, the raw pixel data from a photo lives in linear memory pages.</li>
        <li>Filter functions write their results back to buffers in the same space.</li>
        <li>Temporary states, like undo history or intermediate filter layers, also occupy linear memory.</li>
    </ul>
    <p>
        One buffer overflow in a function applying a Gaussian blur could corrupt unrelated data like the undo stack — creating bugs or exploitable behavior, though still contained to the module.
    </p>
    <h5 class='sidetext'>Stack and Globals</h5>
    <p>
        The stack for local function variables and the global section (counters, constants shared across functions) also reside inside linear memory.
        Functions don’t get a private CPU-backed call stack like they would with native execution. Instead, local variables are mapped into memory offsets within linear memory.
        Globals are similarly layered into reserved regions for predictable access.
    </p>
    <p>
        This unified layout creates a predictable memory model. Predictability matters: it makes execution efficient, but also makes it interesting for attackers, 
        since knowing where everything lives opens possibilities for memory corruption attacks — albeit bounded by the sandbox.
    </p>
</div>

</section>
</section>
