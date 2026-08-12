// Minimal drifting particle background.
(function () {
  const canvas = document.getElementById("bg-particles");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  const DENSITY = 1500; 
  const MAX_SPEED = 0.5;
  const RADIUS = 1.1;
  const REPEL_RADIUS = 210; 
  const CHOSEN_SPEED_MULTIPLIER = 3.5;
  const REPEL_STRENGTH = 5.2; 

  const GAME_ENABLED = document.body.dataset.particleGame === "on";
  const FOCUS_RADIUS = 20;  
  const CHOSEN_MARGIN = RADIUS + 8; 
  const hud = document.getElementById("particle-game-hud");
  const hudTimer = document.getElementById("particle-game-timer");
  const hudBest = document.getElementById("particle-game-best");

  const headerEl = document.querySelector("header") || document.querySelector("nav");
  const footerEl = document.querySelector("footer");

  
  const obstacleEls = GAME_ENABLED
    ? Array.from(document.querySelectorAll(".terminal-window"))
    : [];
  let chosenIndex = -1;
  let focusTime = 0;
  let bestTime = parseFloat(localStorage.getItem("particleGameBest") || "0");
  let lastFrameTime = performance.now();

 
  function bounceOffRect(p, rect) {
    const left = rect.left - CHOSEN_MARGIN;
    const right = rect.right + CHOSEN_MARGIN;
    const top = rect.top - CHOSEN_MARGIN;
    const bottom = rect.bottom + CHOSEN_MARGIN;
    if (p.x <= left || p.x >= right || p.y <= top || p.y >= bottom) return;

    const distLeft = p.x - left;
    const distRight = right - p.x;
    const distTop = p.y - top;
    const distBottom = bottom - p.y;
    const minDist = Math.min(distLeft, distRight, distTop, distBottom);

    if (minDist === distLeft) {
      p.x = left;
      p.vx = -Math.abs(p.vx);
    } else if (minDist === distRight) {
      p.x = right;
      p.vx = Math.abs(p.vx);
    } else if (minDist === distTop) {
      p.y = top;
      p.vy = -Math.abs(p.vy);
    } else {
      p.y = bottom;
      p.vy = Math.abs(p.vy);
    }
  }

 
  function pickChosen() {
    if (!GAME_ENABLED || !particles.length) {
      chosenIndex = -1;
      return;
    }
    if (chosenIndex === -1) {
      chosenIndex = Math.floor(Math.random() * particles.length);
      // Give the newly chosen particle an initial speed boost
      particles[chosenIndex].vx *= CHOSEN_SPEED_MULTIPLIER;
      particles[chosenIndex].vy *= CHOSEN_SPEED_MULTIPLIER;
    } else if (chosenIndex >= particles.length) {
      chosenIndex = particles.length - 1;
    }
  }

  let particles = [];
  let width, height;
  let mouseX = null;
  let mouseY = null;

  function resize() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    const count = Math.max(20, Math.floor((width * height) / DENSITY));
    particles = Array.from({ length: count }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * MAX_SPEED,
      vy: (Math.random() - 0.5) * MAX_SPEED,
    }));
    pickChosen();
  }

  function step() {
    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = "rgba(160, 160, 160, 0.45)";
    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;

      if (i === chosenIndex) {
        const margin = CHOSEN_MARGIN;
        
        // Define dynamic top and bottom limits based on header/footer elements
        const topLimit = headerEl ? headerEl.getBoundingClientRect().bottom + margin : margin;
        const bottomLimit = footerEl ? footerEl.getBoundingClientRect().top - margin : height - margin;

        if (p.x < margin) {
          p.x = margin;
          p.vx = Math.abs(p.vx);
        } else if (p.x > width - margin) {
          p.x = width - margin;
          p.vx = -Math.abs(p.vx);
        }

        if (p.y < topLimit) {
          p.y = topLimit;
          p.vy = Math.abs(p.vy);
        } else if (p.y > bottomLimit) {
          p.y = bottomLimit;
          p.vy = -Math.abs(p.vy);
        }

        for (const el of obstacleEls) {
          bounceOffRect(p, el.getBoundingClientRect());
        }
      } else {
        // Normal particles wrap around
        if (p.x < 0) p.x = width;
        if (p.x > width) p.x = 0;
        if (p.y < 0) p.y = height;
        if (p.y > height) p.y = 0;
      }

      if (mouseX !== null && i !== chosenIndex) {
        const dx = p.x - mouseX;
        const dy = p.y - mouseY;
        const dist = Math.hypot(dx, dy);
        if (dist > 0 && dist < REPEL_RADIUS) {
          const force = (1 - dist / REPEL_RADIUS) * REPEL_STRENGTH;
          p.x += (dx / dist) * force;
          p.y += (dy / dist) * force;
        }
      }

      if (i !== chosenIndex) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, RADIUS, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    if (GAME_ENABLED && chosenIndex >= 0 && particles[chosenIndex]) {
      const now = performance.now();
      const dt = (now - lastFrameTime) / 1000;
      lastFrameTime = now;
      const cp = particles[chosenIndex];
      const pulse = 4 + Math.sin(now / 220) * 2;

      ctx.beginPath();
      ctx.arc(cp.x, cp.y, RADIUS + 5 + pulse, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(94, 234, 212, 0.9)";
      ctx.lineWidth = 1.5;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(cp.x, cp.y, RADIUS + 1.5, 0, Math.PI * 2);
      ctx.fillStyle = "#5eead4";
      ctx.fill();

      let inFocus = false;
      if (mouseX !== null) {
        const dist = Math.hypot(cp.x - mouseX, cp.y - mouseY);
        inFocus = dist < FOCUS_RADIUS;
      }

      if (inFocus) {
        focusTime += dt;
        if (focusTime > bestTime) {
          bestTime = focusTime;
          localStorage.setItem("particleGameBest", bestTime.toFixed(1));
        }
      } else {
        focusTime = 0;
      }

      if (hud) hud.classList.toggle("is-focused", inFocus);
      if (hudTimer) hudTimer.textContent = focusTime.toFixed(1) + "s";
      if (hudBest) hudBest.textContent = bestTime.toFixed(1) + "s";
    }

    requestAnimationFrame(step);
  }

  const prefersReducedMotion = window.matchMedia(
    "(prefers-reduced-motion: reduce)"
  ).matches;

  window.addEventListener("mousemove", (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
  });
  window.addEventListener("mouseleave", () => {
    mouseX = null;
    mouseY = null;
  });

  resize();
  window.addEventListener("resize", resize);
  if (!prefersReducedMotion) requestAnimationFrame(step);
})();
