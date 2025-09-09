---
layout: default
title: "Pwning WebAssembly: Bypassing XSS Filters in the WASM Sandbox"
description: "A deep dive into WebAssembly security, exploring how to analyze and exploit client-side XSS filters using WASM linear memory vulnerabilities."
og_description: "Explore WebAssembly security and learn how to bypass XSS filters using WASM sandbox insights and memory manipulation techniques."
og_type: "article"
keywords: "WebAssembly, WASM, XSS, sandbox security, client-side security, binary exploitation, linear memory, web pwning, zoozoo-sec"
permalink: /blogs/PwningWasm-BreakingXssFilters/
---

<!-- Link Bootstrap CSS (add this to your <head> if it's not already included) -->
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/9000.0.1/themes/prism-tomorrow.min.css" integrity="sha512-kSwGoyIkfz4+hMo5jkJngSByil9jxJPKbweYec/UgS+S1EgE45qm4Gea7Ks2oxQ7qiYyyZRn66A9df2lMtjIsw==" crossorigin="anonymous" referrerpolicy="no-referrer" />
<link rel="stylesheet" href="{{ '/blogs/blog-page.css' | relative_url }}" />



<section id="back" class="back">
    <div id="challenge-links">
        <h1 class="text"><code>Pwning WebAssembly: Bypassing XSS Filters in the WASM Sandbox</code></h1>
    </div>
</section>

<section id="back">
<section id="blueback" class="container">
    <div id="intro" class="challenge-section">
        <div class="section-content">
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
            <h1>Table of Contents</h1>
            <ul>
                <li><a href="#what-is-wasm">What’s WebAssembly Anyway?</a></li>
                <li><a href="#under-the-hood">How WebAssembly Works Under the Hood</a></li>
                <li><a href="#tiered-compilation">Tiered Compilation: Liftoff and Turbofan</a></li>
                <li><a href="#memory-model">Memory Model: The Heart of the Sandbox</a></li>
                <li><a href="#js-glue">The JS Glue: WASM’s Gateway to the Outside World</a></li>
                <li><a href="#why-not-classic">Why Traditional C/C++ Exploits Don’t Work in WASM</a></li>
                <li><a href="#direct-vs-indirect">Direct vs Indirect Calls in WASM</a></li>
                <li><a href="#attack-surface">The Real Attack Surface in WASM</a></li>
                <li><a href="#rust-wasm">Rust and WASM: Memory Safety, But Not a Free Pass</a></li>
            </ul>
        </div>
    </div>
</section>
</section>
