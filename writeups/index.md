---
layout: default   # or any layout you're using
title: "CTF Writeups"
permalink: /writeups/
description: "Explore my CTF writeups."
keywords: "Ctf writeups ,Sarvesh Aadhithya, writeups,zoozoo-sec, zoozoo"
og_type: "CTF Writeups"
og_description: "Explore my CTF writeups."

---
<link rel="stylesheet" href="{{ '/writeups/writeups.css' | relative_url }}" />

<section id="writeups">
  <div class="category-filter">
    <button type="button" class="category-btn is-active" data-filter="all">All</button>
    <button type="button" class="category-btn" data-filter="ctf">Binary Exploitation</button>
    <button type="button" class="category-btn" data-filter="windows">Windows</button>
    <button type="button" class="category-btn" data-filter="linux">Linux</button>
    <button type="button" class="category-btn" data-filter="ad">Active Directory</button>
  </div>

  <div class="category-group" data-category="ctf">
    <h3 class="category-heading">Binary Exploitation</h3>
    <div class="writeup-grid">
      <a href="{{ '/writeups/JustCTF2025' | relative_url }}" class="writeup-card">
        <h2>JustCTF 2025</h2>
        <p>🔹 Shellcode Printer: fmt-string write → shellcode drip<br>
        🔹 Baby Heap: UAF → tcache poison → libc leak<br>
        🔹 Prospector: buffer overflow → ret2linker</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/Pentathon2025' | relative_url }}" class="writeup-card">
        <h2>Pentathon</h2>
        <p>NCIIPC-AICTE Pentathon 2025<br>Qualifier Round<br>
        🔹 Placeholder: arbitrary R/W via DOB → exit-handler hijack<br>
        🔹 Handout: heap OOB → tcache poison → FSOP ROP</p>
        <span class="date">April 2025</span>
      </a>
      <a href="{{ '/writeups/HackTheBox-CyberApocalypse2025' | relative_url }}" class="writeup-card">
        <h2>HackTheBox</h2>
        <p>Cyber Apocalypse 2025<br>
        🔹 Quack-Quack: canary leak → ret2win<br>
        🔹 Blessing: off-by-one write → read_flag()<br>
        🔹 Laconic: stack overflow → SROP → execve<br>
        🔹 Crossbow: negative-index write → ROP shell<br>
        🔹 Contractor: stack leak → overwrite fn ptr<br>
        🔹 Strategist: off-by-one → tcache poison → ROP</p>
        <span class="date">March 2025</span>
      </a>
    </div>
  </div>

  <div class="category-group" data-category="windows">
    <h3 class="category-heading">Pentesting · Windows</h3>
    <div class="writeup-grid">
      <a href="{{ '/writeups/PentestingWindows/#authby' | relative_url }}" class="writeup-card">
        <h2>AuthBy</h2>
        <p>Proving Grounds · FTP creds → JuicyPotato to SYSTEM</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingWindows/#billyboss' | relative_url }}" class="writeup-card">
        <h2>Billyboss</h2>
        <p>Proving Grounds · Nexus default creds RCE → GodPotato</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingWindows/#craft' | relative_url }}" class="writeup-card">
        <h2>Craft</h2>
        <p>Proving Grounds · ODT macro RCE → GodPotato SYSTEM</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingWindows/#dvr4' | relative_url }}" class="writeup-card">
        <h2>Dvr4</h2>
        <p>Proving Grounds · DVR traversal → cracked hash, PsExec</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingWindows/#fish' | relative_url }}" class="writeup-card">
        <h2>Fish</h2>
        <p>Proving Grounds · GlassFish traversal leaks flags directly</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingWindows/#hepet' | relative_url }}" class="writeup-card is-extra">
        <h2>Hepet</h2>
        <p>Proving Grounds · Mail macro → unquoted service path</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingWindows/#jacko' | relative_url }}" class="writeup-card is-extra">
        <h2>Jacko</h2>
        <p>Proving Grounds · H2 console RCE → SeImpersonate SYSTEM</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingWindows/#medjed' | relative_url }}" class="writeup-card is-extra">
        <h2>Medjed</h2>
        <p>Proving Grounds · SQLi webshell → BarracudaServer privesc</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingWindows/#mice' | relative_url }}" class="writeup-card is-extra">
        <h2>Mice</h2>
        <p>Proving Grounds · Remote Mouse RCE → local exploit</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingWindows/#nickel' | relative_url }}" class="writeup-card is-extra">
        <h2>Nickel</h2>
        <p>Proving Grounds · Leaked API creds → SYSTEM endpoint</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingWindows/#shenzi' | relative_url }}" class="writeup-card is-extra">
        <h2>Shenzi</h2>
        <p>Proving Grounds · WordPress creds → AlwaysInstallElevated MSI</p>
        <span class="date">August 2025</span>
      </a>
    </div>
    <button type="button" class="show-more-btn">Show 6 more</button>
  </div>

  <div class="category-group" data-category="ad">
    <h3 class="category-heading">Pentesting · Active Directory</h3>
    <div class="writeup-grid">
      <a href="{{ '/writeups/PentestingActiveDirectory/#access' | relative_url }}" class="writeup-card">
        <h2>Access</h2>
        <p>Proving Grounds · File upload bypass → kerberoast → SeManageVolume</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingActiveDirectory/#active' | relative_url }}" class="writeup-card">
        <h2>Active</h2>
        <p>HTB · GPP cpassword → kerberoast → DA hash</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingActiveDirectory/#blackfield' | relative_url }}" class="writeup-card">
        <h2>Blackfield</h2>
        <p>HTB · AS-REP roast → Backup Operators → DCSync</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingActiveDirectory/#cicada' | relative_url }}" class="writeup-card">
        <h2>Cicada</h2>
        <p>HTB · Share creds → Backup Operators → PtH</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingActiveDirectory/#escape' | relative_url }}" class="writeup-card">
        <h2>Escape</h2>
        <p>HTB · Leaked SQL creds → ADCS ESC1</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingActiveDirectory/#forest' | relative_url }}" class="writeup-card is-extra">
        <h2>Forest</h2>
        <p>HTB · Kerberoast → Account Operators → DCSync</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingActiveDirectory/#hokkaido' | relative_url }}" class="writeup-card is-extra">
        <h2>Hokkaido</h2>
        <p>Proving Grounds · Password spray → targeted kerberoast → Server Operator</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingActiveDirectory/#monteverde' | relative_url }}" class="writeup-card is-extra">
        <h2>Monteverde</h2>
        <p>HTB · LDAP creds → Azure AD Connect abuse</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingActiveDirectory/#nagoya' | relative_url }}" class="writeup-card is-extra">
        <h2>Nagoya</h2>
        <p>Proving Grounds · GenericAll chain → silver ticket → MSSQL RCE</p>
        <span class="date">August 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingActiveDirectory/#resourced' | relative_url }}" class="writeup-card is-extra">
        <h2>Resourced</h2>
        <p>Proving Grounds · Leaked NTDS dump → RBCD → DCSync</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingActiveDirectory/#sauna' | relative_url }}" class="writeup-card is-extra">
        <h2>Sauna</h2>
        <p>HTB · AS-REP roast → cached creds → DA</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingActiveDirectory/#timelapse' | relative_url }}" class="writeup-card is-extra">
        <h2>Timelapse</h2>
        <p>HTB · Cracked pfx cert → LAPS reader</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingActiveDirectory/#vault' | relative_url }}" class="writeup-card is-extra">
        <h2>Vault</h2>
        <p>Proving Grounds · SMB write → Responder NTLM → GPO abuse</p>
        <span class="date">September 2025</span>
      </a>
    </div>
    <button type="button" class="show-more-btn">Show 8 more</button>
  </div>

  <div class="category-group" data-category="linux">
    <h3 class="category-heading">Pentesting · Linux</h3>
    <div class="writeup-grid">
      <a href="{{ '/writeups/PentestingLinux/#bitforge' | relative_url }}" class="writeup-card">
        <h2>Bitforge</h2>
        <p>Proving Grounds · .git leak → SOPlanning RCE → sudo flask</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#bullybox' | relative_url }}" class="writeup-card">
        <h2>Bullybox</h2>
        <p>Proving Grounds · BoxBilling RCE via leaked git creds</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#clamav' | relative_url }}" class="writeup-card">
        <h2>ClamAV</h2>
        <p>Proving Grounds · Sendmail/ClamAV exploit → direct root</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#cockpit' | relative_url }}" class="writeup-card">
        <h2>Cockpit</h2>
        <p>Proving Grounds · SQLi bypass → Cockpit console → tar sudo</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#exfiltrated' | relative_url }}" class="writeup-card">
        <h2>Exfiltrated</h2>
        <p>Proving Grounds · Subrion default creds → exiftool CVE root</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#extplorer' | relative_url }}" class="writeup-card is-extra">
        <h2>Extplorer</h2>
        <p>Proving Grounds · WordPress setup abuse → disk group PwnKit</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#fanatastic' | relative_url }}" class="writeup-card is-extra">
        <h2>Fanatastic</h2>
        <p>Proving Grounds · Grafana traversal → cracked creds → disk group</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#fired' | relative_url }}" class="writeup-card is-extra">
        <h2>Fired</h2>
        <p>Proving Grounds · Openfire CVE → DB creds leak root</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#flu' | relative_url }}" class="writeup-card is-extra">
        <h2>Flu</h2>
        <p>Proving Grounds · Confluence RCE → cron script overwrite</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#hetemit' | relative_url }}" class="writeup-card is-extra">
        <h2>Hetemit</h2>
        <p>Proving Grounds · Eval RCE → writable config → sudo reboot</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#lavita' | relative_url }}" class="writeup-card is-extra">
        <h2>LaVita</h2>
        <p>Proving Grounds · Laravel RCE → writable cron → composer sudo</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#marketing' | relative_url }}" class="writeup-card is-extra">
        <h2>Marketing</h2>
        <p>Proving Grounds · LimeSurvey RCE → credential chain → sudo</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#mzeeav' | relative_url }}" class="writeup-card is-extra">
        <h2>Mzeeav</h2>
        <p>Proving Grounds · Magic byte bypass → renamed find binary</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#nukem' | relative_url }}" class="writeup-card is-extra">
        <h2>Nukem</h2>
        <p>Proving Grounds · Plugin upload RCE → DOSBox setuid</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#ochima' | relative_url }}" class="writeup-card is-extra">
        <h2>Ochima</h2>
        <p>Proving Grounds · Maltrail RCE → writable cron script</p>
        <span class="date">September 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#pc' | relative_url }}" class="writeup-card is-extra">
        <h2>PC</h2>
        <p>Proving Grounds · ttyd terminal → PwnKit root</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#payday' | relative_url }}" class="writeup-card is-extra">
        <h2>Payday</h2>
        <p>Proving Grounds · CS-Cart RCE → weak SSH password</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#pelican' | relative_url }}" class="writeup-card is-extra">
        <h2>Pelican</h2>
        <p>Proving Grounds · Exhibitor RCE → gcore leaks root pass</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#peppo' | relative_url }}" class="writeup-card is-extra">
        <h2>Peppo</h2>
        <p>Proving Grounds · Plugin upload RCE → DOSBox setuid</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#postfish' | relative_url }}" class="writeup-card is-extra">
        <h2>Postfish</h2>
        <p>Proving Grounds · Phishing → postfix group → mail sudo</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#quackerjack' | relative_url }}" class="writeup-card is-extra">
        <h2>QuackerJack</h2>
        <p>Proving Grounds · rConfig RCE → find setuid root</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#readys' | relative_url }}" class="writeup-card is-extra">
        <h2>Readys</h2>
        <p>Proving Grounds · Redis LFI RCE → tar wildcard root</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#scrutiny' | relative_url }}" class="writeup-card is-extra">
        <h2>Scrutiny</h2>
        <p>Proving Grounds · TeamCity bypass → leaked key → systemctl CVE</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#snookums' | relative_url }}" class="writeup-card is-extra">
        <h2>Snookums</h2>
        <p>Proving Grounds · Photo gallery LFI → writable passwd</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#sorcerer' | relative_url }}" class="writeup-card is-extra">
        <h2>Sorcerer</h2>
        <p>Proving Grounds · SCP-jailed key → start-stop-daemon root</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#spx' | relative_url }}" class="writeup-card is-extra">
        <h2>SPX</h2>
        <p>Proving Grounds · Path traversal → cracked hash → makefile sudo</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#spideysociety' | relative_url }}" class="writeup-card is-extra">
        <h2>SpideySociety</h2>
        <p>Proving Grounds · FTP creds → sudoers service abuse</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#vmdak' | relative_url }}" class="writeup-card is-extra">
        <h2>Vmdak</h2>
        <p>Proving Grounds · SQLi/LFI RCE → Jenkins CVE root</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#walla' | relative_url }}" class="writeup-card is-extra">
        <h2>Walla</h2>
        <p>Proving Grounds · RaspAP RCE → Python library hijack</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#wallpaperhub' | relative_url }}" class="writeup-card is-extra">
        <h2>WallpaperHub</h2>
        <p>Proving Grounds · LFI creds leak → happy-dom CVE sudo</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#womb' | relative_url }}" class="writeup-card is-extra">
        <h2>Womb</h2>
        <p>Proving Grounds · Unauth Redis RCE → root service</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#xposedapi' | relative_url }}" class="writeup-card is-extra">
        <h2>Xposedapi</h2>
        <p>Proving Grounds · WAF bypass header → wget setuid root</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#zab' | relative_url }}" class="writeup-card is-extra">
        <h2>Zab</h2>
        <p>Proving Grounds · Terminal foothold → Zabbix creds → rsync sudo</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#zenphoto' | relative_url }}" class="writeup-card is-extra">
        <h2>ZenPhoto</h2>
        <p>Proving Grounds · Old RCE → PwnKit root</p>
        <span class="date">October 2025</span>
      </a>
      <a href="{{ '/writeups/PentestingLinux/#zipper' | relative_url }}" class="writeup-card is-extra">
        <h2>Zipper</h2>
        <p>Proving Grounds · LFI via zip wrapper → 7z wildcard root</p>
        <span class="date">October 2025</span>
      </a>
    </div>
    <button type="button" class="show-more-btn">Show 30 more</button>
  </div>
</section>

<script src="{{ '/writeups/filter.js' | relative_url }}"></script>


