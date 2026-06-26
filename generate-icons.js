// Run with: node generate-icons.js
// Generates simple PNG icons using Canvas API (Node.js with canvas package)
// If canvas is not available, icons can be replaced with any PNG files.

const { createCanvas } = require('canvas');
const fs = require('fs');
const path = require('path');

const sizes = [16, 48, 128];

sizes.forEach(size => {
  const canvas = createCanvas(size, size);
  const ctx = canvas.getContext('2d');

  // Background
  ctx.fillStyle = '#111827';
  ctx.beginPath();
  ctx.roundRect(0, 0, size, size, size * 0.2);
  ctx.fill();

  // Shield shape
  const cx = size / 2;
  const cy = size / 2;
  const sh = size * 0.65;
  const sw = size * 0.55;

  ctx.fillStyle = '#EF4444';
  ctx.beginPath();
  ctx.moveTo(cx, cy - sh / 2);
  ctx.lineTo(cx + sw / 2, cy - sh / 4);
  ctx.lineTo(cx + sw / 2, cy + sh / 8);
  ctx.quadraticCurveTo(cx + sw / 2, cy + sh / 2, cx, cy + sh / 2);
  ctx.quadraticCurveTo(cx - sw / 2, cy + sh / 2, cx - sw / 2, cy + sh / 8);
  ctx.lineTo(cx - sw / 2, cy - sh / 4);
  ctx.closePath();
  ctx.fill();

  // Lock symbol
  ctx.fillStyle = '#fff';
  const ls = size * 0.18;
  ctx.fillRect(cx - ls / 2, cy, ls, ls * 0.9);

  ctx.strokeStyle = '#fff';
  ctx.lineWidth = size * 0.07;
  ctx.beginPath();
  ctx.arc(cx, cy, ls * 0.45, Math.PI, 0);
  ctx.stroke();

  const buffer = canvas.toBuffer('image/png');
  const outPath = path.join(__dirname, 'icons', `icon${size}.png`);
  fs.writeFileSync(outPath, buffer);
  console.log(`Generated ${outPath}`);
});
