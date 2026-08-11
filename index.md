---
layout: default
title: "Sarvesh Aadhithya"
author: "Sarvesh Aadhithya"
---

<section id="profile">
  <div class="identity">
    <span>Sarvesh Aadhithya</span>
    <span class="sep">/</span>
    <span class="handle">@zoozoo</span>
    <span class="sep">/</span>
    <div class="social-links">
      <a href="https://x.com/_zoozoo/" target="_blank" rel="noopener">Twitter</a>
      <a href="https://github.com/zoozoo-sec" target="_blank" rel="noopener">GitHub</a>
      <a href="mailto:this.sarvesh@gmail.com">Mail</a>
    </div>
  </div>

  <h1 class="hero-name">Sarvesh Aadhithya</h1>
  <p class="hero-role">Low-level <del class="hero-role-strike">Security Researcher</del> <span class="hero-role-alt">- Someone who Probably Knows C and Assembly</span></p>
  <p class="hero-bio">
    I dig into binaries, kernels, firmwares and browser internals to understand how they work and find out where they
    break. I write about the things I learn here, mostly through CTF writeups and posts on exploit development, memory corruption, and vulnerability research.
  </p>

  <div class="terminal-window" aria-label="Recent activity">
    <div class="terminal-titlebar">
      <span class="dot"></span><span class="dot"></span><span class="dot"></span>
      <span class="terminal-title">gdb</span>
    </div>
    <div class="terminal-body">
      <p class="terminal-line prompt">(gdb) info recent</p>
      {% for item in site.data.recent %}
      <p class="terminal-line">
        <span class="t-tag">[+]</span><span class="t-date">{{ item.date }}</span>{% if item.url %}<a href="{{ item.url | relative_url }}">{{ item.text }}</a>{% else %}{{ item.text }}{% endif %}
      </p>
      {% endfor %}
      <p class="terminal-line prompt">(gdb) <span class="cursor">_</span></p>
    </div>
  </div>
</section>

<div class="particle-game-hud" id="particle-game-hud">
  <span class="pg-dot"></span>
  <span class="pg-text">
    <span class="pg-hook">Tired of doomscrolling? Let's Test your attention span.</span>
    <span id="particle-game-msg">follow the glowing dot</span>
    <span class="pg-stats">focus <span id="particle-game-timer">0.0s</span> · best <span id="particle-game-best">0.0s</span></span>
  </span>
</div>

