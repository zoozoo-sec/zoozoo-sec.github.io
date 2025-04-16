---
layout: default
title: "Home"
author: "Sarvesh Aadhithya"
---


<section id="profile">
  <div class="section__pic-container">
    <img src="{{ '/assets/img/profile.png' | relative_url }}" alt="Profile picture" />
  </div>
  <div class="section__text">
    <p class="section__text__p1">I'm</p>
    <h1 class="title">Sarvesh Aadhithya</h1>
    <p class="section__text__p2">Security Researcher</p>
    <div class="btn-container">
      <a href="{{ '/assets/SarveshAadhithya-CV.pdf' | relative_url }}" class="btn btn-color-2">Download CV</a>
      <a href="{{ '/#contact' | relative_url }}" class="btn btn-color-1">Contact Info</a>
    </div>
    <div id="socials-container">
      <a href="https://x.com/meeeSarvesh/" target="_blank">
        <img src="{{ '/assets/img/x.png' | relative_url }}" alt="X" class="icon" />
      </a>
      <a href="https://github.com/zoozoo-sec" target="_blank">
        <img src="{{ '/assets/img/github.png' | relative_url }}" alt="GitHub" class="icon" />
        
      </a>
    </div>
      <p>Get To Know More</p>
      <img src="{{ '/assets/img/downarrow.png' | relative_url }}" alt="downarrow" class="icon" />
  </div>

</section>

<!-- ABOUT SECTION -->
<section id="about">
<div class="about-wrapper">
  <div class="about-container">
    <h1>About Me</h1>
    <p>
      💻 <strong>Cybersecurity enthusiast</strong> driven by a passion for 
      <strong>uncovering vulnerabilities and pushing boundaries</strong>. 
      Always exploring the depths of <strong>exploit development,</strong> and <strong>web security</strong>. 
      Skilled in <strong>low-level programming, kernel exploitation,</strong> and 
      <strong>vulnerability research</strong>, with hands-on experience in 
      <strong>memory corruption</strong> and <strong>privilege escalation</strong>.
    </p>
    <h2>Skills</h2>
      <div class="skills-box">    
        <div class="skill">Binary Exploitation</div>
        <div class="skill">System Security</div>
        <div class="skill">Penetration testing</div>
        <div class="skill">Reverse Engineering</div>
        <div class="skill">Linux Kernel Security</div>
        <div class="skill">Exploit Development</div>
      </div>
     <h2>Tools and Frameworks</h2>
    <div class="tools-box">    
      <div class="skill">Burp Suite</div>
      <div class="skill">GDB</div>
      <div class="skill">IDA</div>
      <div class="skill">Metasploit</div>
      <div class="skill">Wireshark</div>
      <div class="skill">Docker</div>
      <div class="skill">Express Framework</div>
      <div class="skill">Node JS</div>
      <div class="skill">Pwntools</div>
    </div>
  </div>
</div>
 </section>



<section id="done">

<div class="done-container">
  <p class="section__text__p2">Want to Know More ?</p>
  <a href="https://tryhackme.com/p/zoozoo" class="section__text__p2"><u>TryHackMe</u></a>
  <div class="experience-container">
    <!-- Logo and Badge side by side -->
    <div class="thm-stats"> 
      <!-- Badge -->
      <iframe 
        src="https://tryhackme.com/api/v2/badges/public-profile?userPublicId=502322" 
        class="badge-frame">
      </iframe>

    </div>
  </div>

  </div>
</section>

<section id="done">
<div class="done-container">
    <a href="https://portswigger.net/web-security/hall-of-fame" class="section__text__p2"><u>Portswigger Academy</u></a>


  <div class="experience-container">
    <!-- Logo and Badge side by side -->
    <div class="thm-stats">
              <img src="{{ '/assets/img/webacademy.png  ' | relative_url }}" alt="PwnCollege" class="webacademy" />
    </div>
    
  </div>
  </div>
</section>

<section id="done">
<div class="done-container">
  <a href="https://pwn.college/hacker/12566" class="section__text__p2"><u>Pwn.College</u></a>

  <div class="experience-container">
    <!-- Flex container for side-by-side images -->
    <div class="image-container">
      <img src="{{ '/assets/img/pwncollege.png' | relative_url }}" alt="PwnCollege" class="side-image" />
      <img src="{{ '/assets/img/pwncollege1.png' | relative_url }}" alt="PwnCollege Badge" class="side-image" />
    </div>
  </div>
  </div>
</section>


<!-- CONTACT SECTION -->
<section id="contact">
  <p class="section__text__p2">Get in Touch</p>
  <div class="contact-container">
    <div class="contact-card">
      <img src="{{ '/assets/img/email.png' | relative_url }}" alt="Email icon" class="contact-icon" />
      <p><a href="mailto:this.sarvesh@gmail.com">Mail</a></p>
    </div>
    <div class="contact-card">
      <img src="{{ '/assets/img/linkedin.png' | relative_url }}" alt="LinkedIn icon" class="contact-icon" />
      <p><a href="https://www.linkedin.com/in/sarvesh-/" target="_blank">LinkedIn</a></p>
    </div>
  </div>
</section>



