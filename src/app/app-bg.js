// ════════════════════════════════════════════════════════════════════════════
// app-bg.js — Subtle per-theme animated background for the landing surface.
//
// A single <canvas id="bg-canvas"> is injected as the first child of <body>,
// fixed to the viewport at z-index:-1 so body's own background paints beneath
// it and every opaque chrome surface (toolbar, sidebar, loaded viewer panes)
// paints above it. The canvas is hidden entirely via CSS when:
//   • a file is loaded     →  body:has(#drop-zone.has-document)
//   • theme-midnight       →  OLED pure-black stays pure-black
//   • prefers-reduced-motion
//
// Five engines, one picked per theme:
//   moire        — light baseline: two families of very thin parallel
//                  lines at different slow-rotating angles. Where they
//                  cross they produce a moiré interference pattern that
//                  drifts continuously as the two angles diverge.
//                  Non-interactive.
//   starfield    — dark baseline: three depth layers of tiny stars
//                  drifting horizontally at different speeds (parallax).
//                  Each star twinkles on its own phase; once every
//                  15-40 s a single shooting-star streak crosses the
//                  viewport diagonally and fades. Non-interactive.
//   cuteKitties  — mocha: ~14 floating kitten silhouettes with gentle
//                  upward drift; cursor acts as a breeze that pushes
//                  nearby shapes away.
//   cuteHearts   — latte: same physics, simple hearts instead.
//   penrose      — solarized: aperiodic P3 rhombic tiling (thick + thin
//                  golden-ratio rhombs) built by recursive subdivision from
//                  a ring of thick rhombs. Tiling is static; per-tile
//                  fill alpha breathes on independent phases.
//                  Alpha is intentionally whisper-low.
//
// The engine-per-theme map treats "midnight" as null (no canvas painted) and
// any theme not in the map falls through to the `moire` baseline.
//
// Frame-rate policy: the three ambient engines (`moire`, `starfield`,
// `penrose`) are throttled to ~24 fps via a timestamp gate inside the RAF
// loop — the motion is slow enough that 60 fps draws are wasted work and a
// measurable CPU drain. The physics engines (`cuteHearts`, `cuteKitties`)
// keep 60 fps so cursor-breeze response stays crisp.
//
// No eval, no `new Function`, no network, no new vendor deps, no new
// localStorage keys. Honours `prefers-reduced-motion` dynamically and pauses
// the animation loop when the tab is hidden (`visibilitychange`).
//
// Wiring:
//   • app-core.js::init() calls  window.BgCanvas.init()  last-ish.
//   • app-ui.js::_setTheme()  calls  window.BgCanvas.setTheme(id)  after
//     applying the body class.  First-boot: BgCanvas.init() reads whatever
//     theme class is already on <body> (set by the FOUC-prevention script in
//     build.py) so the correct engine spins up on the first frame.
//
// Exposes `window.BgCanvas = { init, setTheme }`.
// ════════════════════════════════════════════════════════════════════════════

(function () {
  'use strict';

  // Per-theme engine picker. Midnight intentionally maps to null — the canvas
  // stays present but drawn-empty so the CSS rule can also flip display:none
  // for belt-and-suspenders. Anything not listed here falls through to the
  // `moire` baseline at call-time.
  const THEME_ENGINES = {
    light:     'moire',
    dark:      'starfield',
    mocha:     'cuteKitties',
    latte:     'cuteHearts',
    solarized: 'penrose',
    midnight:  null,
  };

  // Hard-coded RGB tuples per theme. Kept here (not read from computed CSS
  // vars at render time) so the animation stays glitch-free across a theme
  // switch — the engine rebuilds its palette on setTheme(), never mid-loop.
  const PALETTES = {
    // Moiré line-stroke colour for the light baseline — a soft blue that
    // reads as a subtle grain against paper. Two-tone would fight the
    // airy feel we want on that theme.
    light: { moire: [26, 115, 232] },
    // Starfield palette for the dark baseline. Two star tints (cool white
    // and a faint accent cyan) plus a streak colour for the occasional
    // shooting star. Per-frame per-star colour selection is deterministic
    // — each star picks its tint at spawn, not mid-render — so alpha /
    // twinkle variation doesn't accidentally cross-mix hues.
    dark:  {
      starWhite: [230, 240, 255],
      starCyan:  [120, 200, 255],
      streak:    [200, 230, 255],
    },
    mocha: { cute: [[203, 166, 247], [245, 194, 231], [180, 190, 254], [249, 226, 175]] },
    latte: { cute: [[136, 57, 239], [234, 118, 203], [114, 135, 253], [223, 142, 29]]  },
    // Penrose P3 rhomb fills / strokes — thick (fat) rhombs in Solarized
    // yellow, thin (skinny) rhombs in Solarized cyan, so the aperiodic
    // tiling is legible as two interleaved tile species.
    solarized: {
      penroseThick: [181, 137, 0],   // Solarized yellow — fat rhombs
      penroseThin:  [42, 161, 152],  // Solarized cyan   — skinny rhombs
    },
  };


  let _canvas = null;
  let _ctx = null;
  let _theme = null;
  let _engineId = null;
  let _raf = null;
  let _dpr = 1;
  let _w = 0, _h = 0;
  // Mouse: target is raw event position, _mouseX/Y is lerped for silky feel.
  let _mouseTX = 0, _mouseTY = 0;
  let _mouseX = 0,  _mouseY = 0;
  let _hasMouse = false;
  let _state = null;

  // ── Prefs / shims ─────────────────────────────────────────────────────
  const _reducedMotion = () => {
    try {
      return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
    } catch (_) { return false; }
  };

  // ── Canvas lifecycle ──────────────────────────────────────────────────
  function _ensureCanvas() {
    if (_canvas) return _canvas;
    _canvas = document.createElement('canvas');
    _canvas.id = 'bg-canvas';
    _canvas.setAttribute('aria-hidden', 'true');
    // Insert as the first body child so document order matches the CSS
    // stacking intent: body's own background paints first, then the canvas
    // at z-index:-1, then every in-flow chrome element on top.
    if (document.body.firstChild) {
      document.body.insertBefore(_canvas, document.body.firstChild);
    } else {
      document.body.appendChild(_canvas);
    }
    _ctx = _canvas.getContext('2d');
    return _canvas;
  }

  function _resize() {
    if (!_canvas) return;
    // Cap devicePixelRatio so 4K displays don't torch the GPU on what is
    // supposed to be an ambient effect. The geometric-stroke engines
    // (moire / starfield / penrose) keep 1.5× — thin lines at 1.0× on a
    // HiDPI display look noticeably aliased. Physics engines (cute*) also
    // stay at 1.5× so heart / kitty silhouettes keep crisp edges.
    const dprCap = 1.5;
    _dpr = Math.min(window.devicePixelRatio || 1, dprCap);
    _w = window.innerWidth;
    _h = window.innerHeight;
    _canvas.width  = Math.round(_w * _dpr);
    _canvas.height = Math.round(_h * _dpr);
    _canvas.style.width  = _w + 'px';
    _canvas.style.height = _h + 'px';
    _ctx.setTransform(_dpr, 0, 0, _dpr, 0, 0);
    if (_state && _state.onResize) _state.onResize(_w, _h);
  }


  function _onMouseMove(e) {
    _mouseTX = e.clientX;
    _mouseTY = e.clientY;
    _hasMouse = true;
  }

  // Ambient engines draw at this cadence (~24 fps) instead of 60 — the
  // motion is slow enough that the missing frames are invisible but the CPU
  // saving is large (≈60% fewer draws). Physics engines ignore this gate.
  const _AMBIENT_FRAME_MS = 1000 / 24;

  function _loop(t) {
    if (!_state) { _raf = null; return; }
    // Lerp the smoothed cursor position toward the raw target — produces a
    // silky response with no single-frame jitter regardless of the browser's
    // mousemove rate. Only meaningful for engines that actually read the
    // cursor; ambient engines leave it alone.
    if (_state.usesCursor) {
      _mouseX += (_mouseTX - _mouseX) * 0.08;
      _mouseY += (_mouseTY - _mouseY) * 0.08;
    }
    // Frame-rate gate for ambient engines.
    if (_state.throttle) {
      const last = _state.lastDraw || 0;
      if (t - last < _AMBIENT_FRAME_MS) { _raf = requestAnimationFrame(_loop); return; }
      _state.lastDraw = t;
    }
    const dt = Math.min(0.05, ((t - (_state.lastT || t)) / 1000));
    _state.lastT = t;
    _state.draw(t, dt);
    _raf = requestAnimationFrame(_loop);
  }


  function _stop() {
    if (_raf) { cancelAnimationFrame(_raf); _raf = null; }
  }

  function _start() {
    _stop();
    if (_state) _raf = requestAnimationFrame(_loop);
  }

  // ──────────────────────────────────────────────────────────────────────
  // Engine: moire  (light baseline)
  // ──────────────────────────────────────────────────────────────────────
  // Two families of thin parallel lines painted on top of each other, each
  // family at its own independently, very-slowly rotating angle. Where the
  // two line-fields overlap they produce a drifting moiré interference
  // pattern — a classic, visually-interesting emergent effect from the
  // simplest possible geometry.
  //
  // Motion model: each family's angle advances as `baseAngle + t * ω` with
  // ω ~= a few µrad/ms so one full 180°-cycle takes several minutes. The
  // interference fringes migrate across the viewport continuously without
  // any one line visibly moving fast. Line spacing is fixed; to guarantee
  // the rotating lines always cover the canvas we extend each line to the
  // viewport diagonal.
  //
  // Non-interactive; throttled at 24 fps like the other ambient engines.
  function _initMoire() {
    const pal = (PALETTES[_theme] && PALETTES[_theme].moire)
      || PALETTES.light.moire;
    const isDark = document.body.classList.contains('dark');
    // Whisper-low alpha — individual lines should be barely visible; the
    // moiré fringes come through as an emergent bloom where the two
    // families overlap, not from heavy-handed strokes.
    const lineAlpha = isDark ? 0.05 : 0.06;

    // Line spacing in CSS pixels. Smaller spacing produces finer fringes
    // that drift faster as angles diverge; 14 px gives a calm, breath-
    // paced interference.
    const SPACING = 14;
    // Angular velocities (radians / millisecond). Keeping the two near
    // each other but unequal is what produces slowly-drifting fringes
    // rather than a static grid.
    const W_A = 0.0000180;
    const W_B = 0.0000135;
    // Base offsets — randomised once so every page load looks slightly
    // different without any per-frame randomness leaking in.
    const baseA = Math.random() * Math.PI;
    const baseB = Math.random() * Math.PI;

    const strokeStyle = `rgba(${pal[0]},${pal[1]},${pal[2]},${lineAlpha})`;

    // Draw one family of parallel lines at `angle`, spaced `SPACING` px
    // apart, long enough to cover the viewport at any rotation.
    function drawFamily(ctx, angle) {
      const cx = _w * 0.5, cy = _h * 0.5;
      // Half-diagonal plus a little slop — lines of this half-length
      // through the centre, rotated by `angle`, always exit the canvas.
      const L = Math.hypot(_w, _h) * 0.5 + SPACING;
      // Unit vector along the line direction, and its perpendicular
      // (which is the axis along which we step by SPACING).
      const ux = Math.cos(angle),   uy = Math.sin(angle);
      const nx = -uy,                ny = ux;
      // How many lines we need on either side of centre to cover the
      // viewport given this rotation.
      const maxOffset = Math.hypot(_w, _h) * 0.5 + SPACING;
      const count = Math.ceil(maxOffset / SPACING);
      ctx.beginPath();
      for (let k = -count; k <= count; k++) {
        const off = k * SPACING;
        // Midpoint of line k.
        const mx = cx + nx * off;
        const my = cy + ny * off;
        ctx.moveTo(mx - ux * L, my - uy * L);
        ctx.lineTo(mx + ux * L, my + uy * L);
      }
      ctx.stroke();
    }

    return {
      throttle: true,
      usesCursor: false,
      draw(t) {
        const ctx = _ctx;
        ctx.clearRect(0, 0, _w, _h);
        ctx.strokeStyle = strokeStyle;
        ctx.lineWidth = 1;
        // Family A.
        drawFamily(ctx, baseA + t * W_A);
        // Family B — slightly different angular velocity produces the
        // slow fringe migration.
        drawFamily(ctx, baseB + t * W_B);
      },
      onResize() { /* no cached geometry — lines are computed per frame */ },
    };
  }

  // ──────────────────────────────────────────────────────────────────────
  // Engine: starfield  (dark baseline)
  // ──────────────────────────────────────────────────────────────────────
  // Three depth layers of tiny stars drifting horizontally at different
  // speeds. The speed ratio between layers is what sells the parallax —
  // foreground stars visibly overtake the background ones, giving the
  // landing surface a sense of vertical depth without any actual
  // perspective projection.
  //
  // Motion model:
  //   Each star is just { x, y, r, tint, twinkleSpeed, phase, layer }.
  //   Per frame:  x += LAYER_VX[layer] * dt.
  //   Alpha      = baseAlphaPerLayer * (0.55 + 0.45 * sin(t·speed + phase)).
  //   When a star exits the right edge it's re-inserted at x = -r with
  //   a fresh y / tint / phase so the flow stays endless.
  //
  // Density:
  //   Chosen per layer and scaled by sqrt(viewport area) on resize so a
  //   1080p display and a 4K display read the same visual density. Star
  //   counts are intentionally modest (≤ ~260 total) — the twinkling does
  //   most of the work, not volume.
  //
  // Shooting stars:
  //   At most one in-flight at a time. When idle, a random "next-fire"
  //   timestamp is scheduled 15-40 s out. At fire-time a single streak
  //   is spawned from one random edge with a velocity crossing the
  //   viewport in ~900 ms and a tail that fades to zero. Once it exits
  //   or times out it's marked idle and a new fire-time is picked.
  //   Kept serene, never stacking multiple streaks.
  //
  // Non-interactive; throttled at 24 fps via the shared ambient gate.
  function _initStarfield() {
    const pal = PALETTES.dark;
    const WHITE_RGB  = pal.starWhite;
    const CYAN_RGB   = pal.starCyan;
    const STREAK_RGB = pal.streak;

    // Horizontal drift speeds per layer, in CSS px per second. Ratio
    // ≈ 1 : 2.5 : 5.5 gives a clear parallax read without the foreground
    // stars shooting past too fast to be called "ambient".
    const LAYER_VX = [4, 10, 22];
    // Base alpha per layer — far stars dim, near stars bright.
    const LAYER_ALPHA = [0.35, 0.55, 0.85];
    // Radius range per layer (CSS px).
    const LAYER_R_MIN = [0.5, 0.8, 1.2];
    const LAYER_R_MAX = [0.9, 1.4, 2.0];
    // Density target: stars per 10,000 CSS px² of viewport area.
    // Tuned so a 1440×900 viewport ends up with ~150/80/30 stars (~260 total).
    const LAYER_DENSITY = [0.00120, 0.00062, 0.00024];

    // Twinkle speed (radians / ms). Randomised per star from this range
    // so individual stars read as independently alive.
    const TWINKLE_MIN = 0.0012;
    const TWINKLE_MAX = 0.0030;

    // Probability (per star spawn) that it's tinted cyan instead of
    // white. Intentionally low so the field reads as a cool-white sky
    // with just a handful of accent stars.
    const CYAN_P = 0.18;

    let stars = []; // { x, y, r, layer, tint: 0|1, twinkleSpeed, phase }

    // Spawn one star. If `entering` is true the star is inserted at the
    // left edge (for when a star wraps off the right); otherwise anywhere
    // in the viewport (initial flock).
    function spawnStar(layer, entering) {
      const rMin = LAYER_R_MIN[layer];
      const rMax = LAYER_R_MAX[layer];
      const r = rMin + Math.random() * (rMax - rMin);
      return {
        x: entering ? -r : Math.random() * _w,
        y: Math.random() * _h,
        r,
        layer,
        tint: (Math.random() < CYAN_P) ? 1 : 0,
        twinkleSpeed: TWINKLE_MIN + Math.random() * (TWINKLE_MAX - TWINKLE_MIN),
        phase: Math.random() * Math.PI * 2,
      };
    }

    function rebuild() {
      stars = [];
      const area = _w * _h;
      for (let layer = 0; layer < 3; layer++) {
        const count = Math.max(4, Math.round(area * LAYER_DENSITY[layer] / 100));
        for (let i = 0; i < count; i++) stars.push(spawnStar(layer, false));
      }
    }
    rebuild();

    // Shooting-star state machine.
    // shooter === null      → idle, waiting for `nextFireAt`
    // shooter !== null      → in flight with { x, y, vx, vy, life, maxLife }
    let shooter = null;
    let nextFireAt = 0;
    function scheduleNextFire(now) {
      // 15-40 s between streaks. First schedule happens on the first
      // draw call because we don't know `t` until then.
      nextFireAt = now + 15000 + Math.random() * 25000;
    }
    function spawnShooter() {
      // Pick a starting edge + a roughly-downward / inward trajectory
      // so the streak never just grazes the viewport corner.
      const fromLeft = Math.random() < 0.5;
      const startX = fromLeft ? -40 : _w + 40;
      const startY = Math.random() * _h * 0.6; // favour upper area
      // Cross the viewport in ~900 ms — px/sec.
      const crossMs = 700 + Math.random() * 500;
      const dx = fromLeft ? (_w + 80) : -(_w + 80);
      const dy = (80 + Math.random() * 220);
      const vx = dx / (crossMs / 1000);
      const vy = dy / (crossMs / 1000);
      shooter = {
        x: startX, y: startY,
        vx, vy,
        life: 0,
        maxLife: crossMs,
      };
    }

    return {
      throttle: true,
      usesCursor: false,
      draw(t, dt) {
        const ctx = _ctx;
        ctx.clearRect(0, 0, _w, _h);

        // ── 1. Advance + draw background stars, layer by layer so each
        //       layer's constant alpha minimises fillStyle churn.
        for (let layer = 0; layer < 3; layer++) {
          const vx = LAYER_VX[layer];
          const baseA = LAYER_ALPHA[layer];
          for (let i = 0; i < stars.length; i++) {
            const s = stars[i];
            if (s.layer !== layer) continue;
            s.x += vx * dt;
            if (s.x - s.r > _w) {
              // Wrap: re-spawn at the left with fresh attributes so a
              // looped viewport never shows an obvious seam.
              stars[i] = spawnStar(layer, true);
              continue;
            }
            const tw = 0.55 + 0.45 * Math.sin(t * s.twinkleSpeed + s.phase);
            const a = baseA * tw;
            const rgb = (s.tint === 1) ? CYAN_RGB : WHITE_RGB;
            ctx.fillStyle = `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${a.toFixed(3)})`;
            ctx.beginPath();
            ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
            ctx.fill();
          }
        }

        // ── 2. Shooting-star state machine.
        if (!shooter) {
          if (nextFireAt === 0) scheduleNextFire(t);
          if (t >= nextFireAt) spawnShooter();
        } else {
          shooter.life += dt * 1000;
          shooter.x += shooter.vx * dt;
          shooter.y += shooter.vy * dt;
          // Progress 0→1; fade in the first 15%, hold, fade out the last 25%.
          const p = shooter.life / shooter.maxLife;
          let headAlpha;
          if (p < 0.15)       headAlpha = p / 0.15;
          else if (p > 0.75)  headAlpha = Math.max(0, (1 - p) / 0.25);
          else                headAlpha = 1;
          headAlpha *= 0.9;

          // Tail direction = opposite of velocity, scaled by a fraction
          // of the per-second speed so the streak keeps a consistent
          // visual length regardless of how fast it's crossing.
          const speed = Math.hypot(shooter.vx, shooter.vy);
          const tailLen = Math.min(140, speed * 0.12);
          const ux = -shooter.vx / speed;
          const uy = -shooter.vy / speed;
          const tailX = shooter.x + ux * tailLen;
          const tailY = shooter.y + uy * tailLen;

          // Stroke the tail as a gradient from head (bright) to tail (0).
          const grad = ctx.createLinearGradient(shooter.x, shooter.y, tailX, tailY);
          grad.addColorStop(0,
            `rgba(${STREAK_RGB[0]},${STREAK_RGB[1]},${STREAK_RGB[2]},${headAlpha.toFixed(3)})`);
          grad.addColorStop(1,
            `rgba(${STREAK_RGB[0]},${STREAK_RGB[1]},${STREAK_RGB[2]},0)`);
          ctx.strokeStyle = grad;
          ctx.lineWidth = 1.6;
          ctx.lineCap = 'round';
          ctx.beginPath();
          ctx.moveTo(shooter.x, shooter.y);
          ctx.lineTo(tailX, tailY);
          ctx.stroke();

          // Bright head dot on top.
          ctx.fillStyle =
            `rgba(${STREAK_RGB[0]},${STREAK_RGB[1]},${STREAK_RGB[2]},${headAlpha.toFixed(3)})`;
          ctx.beginPath();
          ctx.arc(shooter.x, shooter.y, 1.8, 0, Math.PI * 2);
          ctx.fill();

          // Retire when the streak has left the viewport or timed out.
          if (p >= 1 ||
              shooter.x < -200 || shooter.x > _w + 200 ||
              shooter.y < -200 || shooter.y > _h + 200) {
            shooter = null;
            scheduleNextFire(t);
          }
        }
      },
      onResize() { rebuild(); },
    };
  }

  // Kept around in case anyone wants the old dark-baseline engines back.
  // Neither is wired into THEME_ENGINES — the `dark` entry is `starfield`.
  // Safe to delete if/when the new engine has stuck.
  function _initFlowField() {
    const pal = PALETTES.dark;
    const GRID_RGB  = pal.flowGrid;   // grid dots
    const ARROW_RGB = pal.flowArrow;  // flow arrows

    // Alphas are tuned conservatively — the dark theme body already sits
    // on near-black, so even a subtle stroke reads on screen. The grid is
    // quieter than the arrows so the flow pattern owns the eye.
    const GRID_ALPHA   = 0.08;
    const ARROW_BASE_A = 0.22;

    // Cell pitch (CSS px). Same order of magnitude as the old Truchet
    // engine so the landing surface keeps its familiar sense of scale.
    const TILE = 42;
    // Arrow shaft length, head half-width, head length — measured from
    // the arrow's *tail* at one end to its tip at the other. Keeping the
    // arrow < cell size prevents neighbours from visually fighting.
    const ARROW_LEN  = TILE * 0.62;
    const HEAD_LEN   = TILE * 0.22;
    const HEAD_HALFW = TILE * 0.14;

    // Low-frequency sine basis used to build the vector field. Each row
    // is [kx, ky, omega, phi, amp]. Spatial frequencies are in radians
    // per CSS pixel; ω is radians / ms. The four rows sum to an angle
    // that walks smoothly over space and time, never repeating on any
    // sub-minute scale.
    const BASIS = [
      [0.0038,  0.0022, 0.000180, 0.0, 1.00],
      [0.0015, -0.0042, 0.000140, 1.7, 0.80],
      [0.0070,  0.0064, 0.000110, 3.1, 0.55],
      [-0.0052, 0.0028, 0.000095, 4.5, 0.45],
    ];

    let cols = 0, rows = 0;
    // Pre-compute cell centres once per resize.
    let cellX = null, cellY = null;
    function rebuild() {
      cols = Math.ceil(_w / TILE) + 1;
      rows = Math.ceil(_h / TILE) + 1;
      cellX = new Float32Array(cols);
      cellY = new Float32Array(rows);
      const ox = -TILE * 0.5;
      const oy = -TILE * 0.5;
      for (let rx = 0; rx < cols; rx++) cellX[rx] = ox + rx * TILE + TILE * 0.5;
      for (let ry = 0; ry < rows; ry++) cellY[ry] = oy + ry * TILE + TILE * 0.5;
    }
    rebuild();

    // Evaluate the field angle at (x, y) and time t.
    function angleAt(x, y, t) {
      let s = 0;
      for (let i = 0; i < BASIS.length; i++) {
        const b = BASIS[i];
        s += b[4] * Math.sin(b[0] * x + b[1] * y + b[2] * t + b[3]);
      }
      // Multiply by π so s ≈ [-πA, +πA] — keeps the angle range wide
      // without ever being dominated by a single frequency.
      return s * Math.PI;
    }

    const gridStyle  = `rgba(${GRID_RGB[0]},${GRID_RGB[1]},${GRID_RGB[2]},${GRID_ALPHA})`;

    return {
      throttle: true,
      usesCursor: false,
      draw(t) {
        const ctx = _ctx;
        ctx.clearRect(0, 0, _w, _h);

        // ── 1. Paint the substrate grid as a single thin-line path.
        ctx.strokeStyle = gridStyle;
        ctx.lineWidth = 1;
        ctx.beginPath();
        // Vertical grid lines.
        for (let rx = 0; rx < cols; rx++) {
          const x = cellX[rx] - TILE * 0.5;
          ctx.moveTo(x, 0);
          ctx.lineTo(x, _h);
        }
        // Horizontal grid lines.
        for (let ry = 0; ry < rows; ry++) {
          const y = cellY[ry] - TILE * 0.5;
          ctx.moveTo(0, y);
          ctx.lineTo(_w, y);
        }
        ctx.stroke();

        // ── 2. Paint one arrow per cell along the local flow direction.
        //       All arrows share a single path + stroke so per-frame cost
        //       stays near one Canvas draw call.
        ctx.lineCap = 'round';
        ctx.lineJoin = 'round';
        ctx.lineWidth = 1.4;
        // Stroke colour is constant; per-cell variation comes from global
        // alpha via a second pass if needed. For simplicity we pick one
        // mid alpha and let the whole flow field read as one hue — the
        // breathing effect is carried by the sine basis varying angles.
        ctx.strokeStyle =
          `rgba(${ARROW_RGB[0]},${ARROW_RGB[1]},${ARROW_RGB[2]},${ARROW_BASE_A})`;
        ctx.beginPath();
        const halfLen = ARROW_LEN * 0.5;
        for (let ry = 0; ry < rows; ry++) {
          const cy = cellY[ry];
          for (let rx = 0; rx < cols; rx++) {
            const cx = cellX[rx];
            const th = angleAt(cx, cy, t);
            const cos = Math.cos(th), sin = Math.sin(th);
            // Shaft: tail (cx - cos·halfLen) → tip (cx + cos·halfLen).
            const tailX = cx - cos * halfLen;
            const tailY = cy - sin * halfLen;
            const tipX  = cx + cos * halfLen;
            const tipY  = cy + sin * halfLen;
            ctx.moveTo(tailX, tailY);
            ctx.lineTo(tipX, tipY);
            // Arrow head: two short strokes flaring back from the tip.
            // Perpendicular vector = (-sin, cos).
            const bx = tipX - cos * HEAD_LEN;
            const by = tipY - sin * HEAD_LEN;
            ctx.moveTo(tipX, tipY);
            ctx.lineTo(bx - sin * HEAD_HALFW, by + cos * HEAD_HALFW);
            ctx.moveTo(tipX, tipY);
            ctx.lineTo(bx + sin * HEAD_HALFW, by - cos * HEAD_HALFW);
          }
        }
        ctx.stroke();
      },
      onResize() { rebuild(); },
    };
  }

  // Kept around in case anyone wants the original dark baseline back.
  // Not wired into THEME_ENGINES — the `truchet` entry was swapped to
  // `flowField` above. Safe to delete if/when the new engine has stuck.
  function _initTruchet() {
    const pal = (PALETTES[_theme] && PALETTES[_theme].truchet)
      || PALETTES.dark.truchet;
    const isDark = document.body.classList.contains('dark');
    // Alphas are ×10 lower than what you'd naïvely pick for a "subtle"
    // background — the user explicitly wants the curves to sit at the
    // threshold of perception on the Dark theme. Any higher and the
    // tile-flip events start to draw the eye away from loaded content
    // nearby. Any lower and the pattern disappears on dim displays.
    const edgeAlpha = isDark ? 0.018 : 0.014;

    // Target tile size — big enough that a typical viewport holds ~8-14
    // tiles per axis, small enough that curves read as flowing lines.
    const TILE = 86;
    const strokeStyle = `rgba(${pal[0]},${pal[1]},${pal[2]},${edgeAlpha})`;

    let cols = 0, rows = 0;
    let tiles = null; // { orient: 0|1, flipT: 0..1, target: 0|1 }

    function rebuild() {
      cols = Math.ceil(_w / TILE) + 1;
      rows = Math.ceil(_h / TILE) + 1;
      tiles = new Array(cols * rows);
      for (let i = 0; i < tiles.length; i++) {
        const o = (Math.random() < 0.5) ? 0 : 1;
        tiles[i] = { orient: o, target: o, flipT: 0 };
      }
    }
    rebuild();

    // Flip scheduler — one tile begins a flip every ~2.5 s on average.
    // `flipT` walks 0 → 1 over FLIP_DURATION when `target !== orient`;
    // on completion we snap `orient = target` and reset flipT.
    const FLIP_INTERVAL_MS = 2500;
    const FLIP_DURATION_MS = 1100;
    let nextFlipAt = 0;

    // Pre-stroke each of the two arcs in path space so the inner loop
    // just issues rotate/translate and a single stroke per tile.
    const R = TILE * 0.5;
    const drawTile = (ctx, cx, cy, orient, flipT) => {
      // Rotation (radians) for the in-flight flip — 0 at rest, ±π/2 mid.
      // Using π/2 makes the "flipped" quarter-arc pair land exactly on the
      // other orientation, so flipT=1 is indistinguishable from a static
      // tile of the other orient.
      const dir = (orient === 0) ? 1 : -1;
      const rot = dir * flipT * Math.PI * 0.5;
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(rot);
      // Draw two quarter-arcs according to the *current* (pre-flip) orient.
      ctx.beginPath();
      if (orient === 0) {
        // Arc in top-left corner: centred at (-R, -R), radius R,
        // sweep 0 → π/2.
        ctx.arc(-R, -R, R, 0, Math.PI * 0.5);
        // Arc in bottom-right corner: centred at (R, R), radius R,
        // sweep π → 3π/2.
        ctx.moveTo(R, 0);
        ctx.arc(R, R, R, Math.PI, Math.PI * 1.5);
      } else {
        // Arc in top-right corner: centred at (R, -R), radius R, sweep π/2 → π.
        ctx.arc(R, -R, R, Math.PI * 0.5, Math.PI);
        // Arc in bottom-left corner: centred at (-R, R), radius R, sweep 3π/2 → 2π.
        ctx.moveTo(0, R);
        ctx.arc(-R, R, R, Math.PI * 1.5, Math.PI * 2);
      }
      ctx.stroke();
      ctx.restore();
    };

    return {
      throttle: true,
      usesCursor: false,
      draw(t, dt) {
        const ctx = _ctx;
        ctx.clearRect(0, 0, _w, _h);
        ctx.strokeStyle = strokeStyle;
        ctx.lineWidth = 1.3;
        ctx.lineCap = 'round';
        // Kick off a new flip if it's time and we don't already have too
        // many in flight (cap keeps the scene from getting visually noisy).
        const inFlightCap = 2;
        let inFlight = 0;
        for (const tile of tiles) if (tile.orient !== tile.target) inFlight++;
        if (t >= nextFlipAt && inFlight < inFlightCap) {
          const idx = (Math.random() * tiles.length) | 0;
          const tile = tiles[idx];
          // Only schedule a flip for a tile currently at rest.
          if (tile.orient === tile.target) {
            tile.target = 1 - tile.orient;
            tile.flipT = 0;
          }
          nextFlipAt = t + FLIP_INTERVAL_MS * (0.7 + Math.random() * 0.6);
        }
        // Advance any in-flight flips.
        for (const tile of tiles) {
          if (tile.orient === tile.target) continue;
          tile.flipT += (dt * 1000) / FLIP_DURATION_MS;
          if (tile.flipT >= 1) {
            tile.orient = tile.target;
            tile.flipT = 0;
          }
        }
        // Origin-offset the grid by a fractional tile so there's no
        // single-pixel seam against the viewport edge on first paint.
        const ox = -TILE * 0.5;
        const oy = -TILE * 0.5;
        for (let ry = 0; ry < rows; ry++) {
          for (let rx = 0; rx < cols; rx++) {
            const tile = tiles[ry * cols + rx];
            const cx = ox + rx * TILE + TILE * 0.5;
            const cy = oy + ry * TILE + TILE * 0.5;
            // Smoothstep the flip for a gentler ease-in/out.
            const smooth = tile.flipT * tile.flipT * (3 - 2 * tile.flipT);
            drawTile(ctx, cx, cy, tile.orient, smooth);
          }
        }
      },
      onResize() { rebuild(); },
    };
  }

  // ──────────────────────────────────────────────────────────────────────
  // Engine: penrose  (solarized)
  // ──────────────────────────────────────────────────────────────────────
  // Aperiodic Penrose P3 rhombic tiling. Built by recursive subdivision
  // from a ring of "fat" rhomb triangles around the centre: each fat
  // triangle splits into one fat + one thin sub-triangle, each thin
  // triangle splits into one fat + one thin, and after ~5 levels we have
  // a few hundred tiles covering a disc. We pair adjacent triangles back
  // into their parent rhombs for drawing.
  //
  // Motion model: the tiling is static in position (no rotation — the
  // slow global spin was removed because on long viewing sessions it
  // read as ambient motion sickness). Each rhomb breathes its fill alpha
  // on an independent phase so different patches of the tiling visibly
  // glow in and out — that alone is enough visual life for the theme.
  // No cursor interaction.
  //
  // The geometry is computed once per resize (on a disc sized to the
  // viewport diagonal) and cached — the per-frame cost is one rotate +
  // one fill+stroke per visible rhomb.
  function _initPenrose() {
    const pal = PALETTES.solarized;
    const isDark = document.body.classList.contains('dark');
    // Alphas are ×10 lower than the "obvious" subtle tuning — the Penrose
    // tiling is a lot of geometry on screen at once, and at readable alpha
    // it pulls focus from every other chrome surface. At this level the
    // rhombs read as a watermark and only resolve into an aperiodic tiling
    // when the user deliberately looks for it.
    //
    // Note: floors bumped (0.012 → 0.018, 0.022 → 0.030) and the breathing
    // swing tightened (see `breath` below: floor 0.4 → 0.55) so the tiling
    // never slips into a "ghosted / fading" trough — older tuning had a
    // min visible level of ~0.0048 which made it look like the pattern
    // was dying out over time. New minimum visible level is ~0.0099,
    // roughly 2× brighter at the quietest phase.
    const baseAlpha = isDark ? 0.018 : 0.015;
    const strokeAlpha = isDark ? 0.030 : 0.026;

    const PHI = (1 + Math.sqrt(5)) / 2;

    let rhombs = []; // { kind: 0|1, pts: [p0, p1, p2, p3], phase, speed }

    // Build the base ring of 10 fat triangles (each a 36-36-108 triangle,
    // pairs of which form a fat rhomb).
    // Representation during subdivision: a triangle as [kind, A, B, C]
    // where kind ∈ {0: fat, 1: thin}. The *rhomb* is formed by two
    // triangles sharing their A-C edge.
    function subdivide(triangles) {
      const next = [];
      for (const [kind, A, B, C] of triangles) {
        if (kind === 0) {
          // Fat triangle: split into one fat + one thin sub-triangle.
          const P = [
            A[0] + (B[0] - A[0]) / PHI,
            A[1] + (B[1] - A[1]) / PHI,
          ];
          next.push([0, C, P, B]);
          next.push([1, P, C, A]);
        } else {
          // Thin triangle: split into one thin + one fat sub-triangle.
          const Q = [
            B[0] + (A[0] - B[0]) / PHI,
            B[1] + (A[1] - B[1]) / PHI,
          ];
          const R = [
            B[0] + (C[0] - B[0]) / PHI,
            B[1] + (C[1] - B[1]) / PHI,
          ];
          next.push([1, R, C, A]);
          next.push([1, Q, R, B]);
          next.push([0, R, Q, A]);
        }
      }
      return next;
    }

    function rebuild() {
      // Disc radius — large enough that the tiling always reaches the
      // viewport corners even with the centre sitting at (_w/2, _h/2).
      const R = Math.hypot(_w, _h) * 0.62;
      // Seed: 10 thin triangles around the centre (classic "sun" start).
      // Thin-triangle seed → yields a nicely balanced kite-and-dart / P3
      // mix after ~5 subdivisions.
      let tris = [];
      for (let i = 0; i < 10; i++) {
        const a1 = ((2 * i) * Math.PI) / 10 - Math.PI / 10;
        const a2 = ((2 * (i + 1)) * Math.PI) / 10 - Math.PI / 10;
        const B = [R * Math.cos(a1), R * Math.sin(a1)];
        const C = [R * Math.cos(a2), R * Math.sin(a2)];
        // Flip every other triangle so shared edges line up correctly.
        if (i % 2 === 0) tris.push([0, [0, 0], B, C]);
        else             tris.push([0, [0, 0], C, B]);
      }
      // ~5 subdivisions gives ≈ 400-700 rhombs, plenty of visual density
      // without making the per-frame draw expensive.
      const LEVELS = 5;
      for (let l = 0; l < LEVELS; l++) tris = subdivide(tris);

      // Pair each triangle with its partner across the shared A-C edge
      // to get rhombs. Build a map keyed by the midpoint of the A-C
      // edge — colliding triangles share that midpoint.
      const midKey = (p, q) => {
        const mx = ((p[0] + q[0]) * 0.5);
        const my = ((p[1] + q[1]) * 0.5);
        return Math.round(mx * 100) + ',' + Math.round(my * 100);
      };
      const byMid = new Map();
      for (const tri of tris) {
        const [, A, , C] = tri;
        const k = midKey(A, C);
        if (byMid.has(k)) byMid.get(k).push(tri);
        else byMid.set(k, [tri]);
      }
      rhombs = [];
      for (const pair of byMid.values()) {
        if (pair.length !== 2) continue; // edge-of-disc orphan
        const [t1, t2] = pair;
        // A rhomb's 4 vertices: A, B₁, C, B₂ where B₁ / B₂ are the two
        // "far" corners of the two triangles (they sit on opposite sides
        // of the shared A-C edge).
        const A = t1[1], C = t1[3];
        const B1 = t1[2];
        const B2 = t2[2];
        rhombs.push({
          kind: t1[0],      // 0 = fat rhomb (yellow), 1 = thin (cyan)
          pts: [A, B1, C, B2],
          // Independent slow breathing phase per rhomb.
          phase: Math.random() * Math.PI * 2,
          speed: 0.0004 + Math.random() * 0.0006,
        });
      }
    }
    rebuild();

    return {
      throttle: true,
      usesCursor: false,
      draw(t) {
        const ctx = _ctx;
        ctx.clearRect(0, 0, _w, _h);
        const cx = _w * 0.5, cy = _h * 0.5;
        // Static tiling — no global rotation. Visual life comes entirely
        // from per-rhomb alpha breathing below. cosR / sinR retained as
        // identity so the vertex transform below stays a single code path
        // (cheaper than branching on a rotate flag per vertex).
        const cosR = 1, sinR = 0;
        for (const r of rhombs) {
          // Per-rhomb breathing: fill alpha cycles between 55% and 100%
          // of baseAlpha (floor raised from 40% so no rhomb ever slips
          // into perceptual invisibility — keeps the tiling from looking
          // like it's fading out over time).
          const breath = 0.55 + 0.45 * (0.5 + 0.5 * Math.sin(t * r.speed + r.phase));
          const fillRgb = (r.kind === 0) ? pal.penroseThick : pal.penroseThin;
          ctx.fillStyle =
            `rgba(${fillRgb[0]},${fillRgb[1]},${fillRgb[2]},${baseAlpha * breath})`;
          ctx.strokeStyle =
            `rgba(${fillRgb[0]},${fillRgb[1]},${fillRgb[2]},${strokeAlpha})`;
          ctx.lineWidth = 0.8;
          ctx.beginPath();
          for (let k = 0; k < 4; k++) {
            const p = r.pts[k];
            // Rotate + translate into screen space.
            const rx = p[0] * cosR - p[1] * sinR + cx;
            const ry = p[0] * sinR + p[1] * cosR + cy;
            if (k === 0) ctx.moveTo(rx, ry);
            else ctx.lineTo(rx, ry);
          }
          ctx.closePath();
          ctx.fill();
          ctx.stroke();
        }
      },
      onResize() { rebuild(); },
    };
  }



  // ──────────────────────────────────────────────────────────────────────
  // Engine: cute  (hearts for mocha, kitties for latte)
  // ──────────────────────────────────────────────────────────────────────
  function _initCute(variant) {
    const pal = (PALETTES[_theme] && PALETTES[_theme].cute) || PALETTES.mocha.cute;
    const isDark = document.body.classList.contains('dark');
    const baseAlpha = isDark ? 0.13 : 0.11;
    const count = 14;
    const shapes = [];
    for (let i = 0; i < count; i++) shapes.push(_spawnCute(pal, baseAlpha, true));

    const draw = (variant === 'kitties') ? _drawKitty : _drawHeart;

    return {
      draw(t, dt) {
        const ctx = _ctx;
        ctx.clearRect(0, 0, _w, _h);
        for (const s of shapes) {
          // Physics
          s.x += s.vx * dt;
          s.y += s.vy * dt;
          s.rot += s.rotSpeed * dt;
          // Light drag so cursor breeze decays
          s.vx *= (1 - 0.8 * dt);
          s.vy += (s.vyBase - s.vy) * 0.5 * dt; // pull back toward drift velocity
          // Cursor breeze — push away when within ~140 px.
          if (_hasMouse) {
            const dx = s.x - _mouseX, dy = s.y - _mouseY;
            const d2 = dx * dx + dy * dy;
            if (d2 < 140 * 140 && d2 > 1) {
              const d = Math.sqrt(d2);
              const f = (1 - d / 140) * 260;
              s.vx += (dx / d) * f * dt;
              s.vy += (dy / d) * f * dt;
            }
          }
          // Clamp max speed so a long cursor hover can't catapult a shape.
          const maxV = 120;
          const v2 = s.vx * s.vx + s.vy * s.vy;
          if (v2 > maxV * maxV) {
            const v = Math.sqrt(v2);
            s.vx = (s.vx / v) * maxV;
            s.vy = (s.vy / v) * maxV;
          }
          // Wrap / respawn when the shape drifts fully off the top.
          if (s.y < -s.size * 2) {
            const n = _spawnCute(pal, baseAlpha, false);
            Object.assign(s, n);
          }
          if (s.x < -s.size * 2) s.x = _w + s.size;
          else if (s.x > _w + s.size * 2) s.x = -s.size;
          if (s.y > _h + s.size * 2) s.y = -s.size;
          const [r, g, b] = s.color;
          draw(ctx, s.x, s.y, s.size, s.rot, `rgba(${r},${g},${b},${s.a})`);
        }
      },
      onResize() {
        // Deliberately no-op — existing shapes drift naturally into the new
        // viewport; spawning a fresh flock on every resize would look jumpy.
      },
    };
  }

  // Initial flock can start anywhere on screen; respawns enter from below.
  function _spawnCute(pal, baseAlpha, initial) {
    const size = 14 + Math.random() * 18;
    const vyBase = -8 - Math.random() * 12;
    return {
      x: Math.random() * _w,
      y: initial ? Math.random() * _h : _h + size + Math.random() * 60,
      vx: (Math.random() - 0.5) * 6,
      vy: vyBase,
      vyBase,
      size,
      rot: Math.random() * Math.PI * 2,
      rotSpeed: (Math.random() - 0.5) * 0.25,
      color: pal[(Math.random() * pal.length) | 0],
      a: baseAlpha * (0.6 + Math.random() * 0.6),
    };
  }

  function _drawHeart(ctx, x, y, size, rot, rgba) {
    ctx.save();
    ctx.translate(x, y);
    ctx.rotate(rot);
    ctx.scale(size / 30, size / 30);
    ctx.fillStyle = rgba;
    ctx.beginPath();
    // Classic two-bezier heart, roughly 30 × 28 centred at origin.
    ctx.moveTo(0, 8);
    ctx.bezierCurveTo(0, 3, -6, -10, -14, -4);
    ctx.bezierCurveTo(-22, 2, -14, 12, 0, 22);
    ctx.bezierCurveTo(14, 12, 22, 2, 14, -4);
    ctx.bezierCurveTo(6, -10, 0, 3, 0, 8);
    ctx.closePath();
    ctx.fill();
    ctx.restore();
  }

  function _drawKitty(ctx, x, y, size, rot, rgba) {
    ctx.save();
    ctx.translate(x, y);
    ctx.rotate(rot);
    ctx.scale(size / 30, size / 30);
    ctx.fillStyle = rgba;
    // Head
    ctx.beginPath();
    ctx.arc(0, 2, 12, 0, Math.PI * 2);
    ctx.fill();
    // Ears (two triangles)
    ctx.beginPath();
    ctx.moveTo(-11, -4); ctx.lineTo(-6, -16); ctx.lineTo(-2, -8); ctx.closePath();
    ctx.moveTo(11, -4);  ctx.lineTo(6, -16);  ctx.lineTo(2, -8);  ctx.closePath();
    ctx.fill();
    // Knock out eyes + whiskers for a silhouette with just enough detail.
    ctx.globalCompositeOperation = 'destination-out';
    ctx.beginPath();
    ctx.arc(-4, 0, 1.6, 0, Math.PI * 2);
    ctx.arc(4, 0, 1.6, 0, Math.PI * 2);
    ctx.fill();
    ctx.lineWidth = 0.9;
    ctx.strokeStyle = '#000';
    ctx.beginPath();
    ctx.moveTo(-12, 5); ctx.lineTo(-4, 5);
    ctx.moveTo(-12, 8); ctx.lineTo(-4, 7);
    ctx.moveTo(12, 5);  ctx.lineTo(4, 5);
    ctx.moveTo(12, 8);  ctx.lineTo(4, 7);
    ctx.stroke();
    ctx.globalCompositeOperation = 'source-over';
    ctx.restore();
  }

  // ── Public API ────────────────────────────────────────────────────────
  function init() {
    _ensureCanvas();
    _resize();
    window.addEventListener('resize', _resize, { passive: true });
    window.addEventListener('mousemove', _onMouseMove, { passive: true });
    // Pause the RAF loop when the tab isn't visible — saves battery and
    // avoids the first post-wake frame integrating a huge dt (we clamp it
    // to 50 ms anyway, but this is cleaner).
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) _stop();
      else if (_state) _start();
    });
    // React to live prefers-reduced-motion toggles (macOS Accessibility, etc.)
    try {
      const m = window.matchMedia('(prefers-reduced-motion: reduce)');
      const onChange = () => { if (_theme) setTheme(_theme); };
      if (m.addEventListener) m.addEventListener('change', onChange);
      else if (m.addListener) m.addListener(onChange);
    } catch (_) { /* matchMedia unavailable */ }
    // First-boot bootstrap: adopt whatever theme the FOUC-prevention script
    // in build.py already applied to <body>. `_setTheme()` in app-ui.js will
    // call us again on user theme changes.
    const cls = Array.from(document.body.classList).find(c => c.indexOf('theme-') === 0);
    if (cls) setTheme(cls.slice(6));
  }

  function setTheme(themeId) {
    _theme = themeId;
    _stop();
    _state = null;
    _engineId = null;
    if (!_canvas) _ensureCanvas();
    if (_ctx) _ctx.clearRect(0, 0, _w, _h);
    if (_reducedMotion()) return;
    const engineId = THEME_ENGINES.hasOwnProperty(themeId) ? THEME_ENGINES[themeId] : 'moire';
    if (!engineId) return; // e.g. midnight — canvas stays cleared
    _engineId = engineId;
    if (engineId === 'moire')            _state = _initMoire();
    else if (engineId === 'starfield')   _state = _initStarfield();
    else if (engineId === 'flowField')   _state = _initFlowField();
    else if (engineId === 'truchet')     _state = _initTruchet();
    else if (engineId === 'penrose')     _state = _initPenrose();
    else if (engineId === 'cuteHearts')  _state = _initCute('hearts');
    else if (engineId === 'cuteKitties') _state = _initCute('kitties');
    if (_state) {
      // Seed the smoothed cursor at the centre so the first frame doesn't
      // lurch from (0,0) to the real pointer position.
      _mouseTX = _w * 0.5;
      _mouseTY = _h * 0.5;
      _mouseX = _mouseTX;
      _mouseY = _mouseTY;
      _start();
    }
  }

  window.BgCanvas = { init, setTheme };
})();
