// Matrix Falling Text Effect
const canvas = document.getElementById('matrix');
const ctx = canvas.getContext('2d');

// Set canvas size
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

const fontSize = 16;
const columns = Math.floor(canvas.width / fontSize);
const drops = Array(columns).fill(0);

const characters = "01#$%&@€¥£¢∞ΩπΦΨΔΛΘ";

function drawMatrix() {
  ctx.fillStyle = "rgba(0, 0, 0, 0.05)";   // Fading effect
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  ctx.fillStyle = "#00FF41";  // Green matrix text color
  ctx.font = `${fontSize}px monospace`;

  for (let i = 0; i < drops.length; i++) {
    const text = characters[Math.floor(Math.random() * characters.length)];
    ctx.fillText(text, i * fontSize, drops[i] * fontSize);

    if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
      drops[i] = 0;
    }
    drops[i]++;
  }
}

// Animation loop
setInterval(drawMatrix, 65);

// Resize canvas on window resize
window.addEventListener("resize", () => {
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
});
