// ============ YJ-Phonics Bubble Shooter Game ============
// CVC 단어 버블 슈터 - 별도 JS 파일

// ============ CVC WORD DATA ============
const CVC_WORDS = {
  a: ["cat","bat","hat","mat","rat","sat","fat","pat","van","can","man","fan","pan","ran","tan","bag","tag","rag","nag","gap","map","cap","tap","nap","zap","ram","jam","ham","dam","bad","dad","had","sad","mad","pad","lab","cab","tab","jab"],
  e: ["bed","red","fed","led","wed","hen","pen","ten","men","den","bet","get","jet","let","met","net","pet","set","wet","vet","peg","leg","beg","keg"],
  i: ["pig","big","dig","fig","wig","jig","rig","pin","bin","tin","fin","win","sit","bit","fit","hit","kit","lit","pit","wit","zip","tip","lip","hip","dip","rip","sip","nip","mix","fix","six","kid","did","hid","lid","rid"],
  o: ["hot","got","not","dot","lot","pot","rot","cot","dog","log","fog","hog","jog","bog","hop","mop","top","pop","cop","mob","job","rob","sob","cob","nod","rod","cod","pod"],
  u: ["cup","pup","bus","gum","hug","bug","dug","jug","mug","rug","tug","bud","mud","cut","gut","hut","nut","rut","but","put","sun","run","fun","gun","bun","nun","pun","pub","rub","sub","tub","cub"]
};
const VOWELS = ['a','e','i','o','u'];
const VOWEL_COLORS = {
  a: ['#ff6b6b','#ee5a24'],
  e: ['#48dbfb','#0abde3'],
  i: ['#feca57','#ff9f43'],
  o: ['#55efc4','#00b894'],
  u: ['#a29bfe','#6c5ce7']
};

const DIFFICULTY = {
  easy:   { questions: 10, lives: 5, fallMin: 40, fallMax: 60, choices: 3, spawnInterval: 0.6, label: 'Easy' },
  normal: { questions: 15, lives: 3, fallMin: 60, fallMax: 100, choices: 5, spawnInterval: 0.45, label: 'Normal' },
  hard:   { questions: 20, lives: 2, fallMin: 90, fallMax: 140, choices: 6, spawnInterval: 0.35, label: 'Hard' }
};

const DAILY_LIMIT = 3;

// ============ UTILITY ============
function shuffleArr(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function getWordVowel(word) {
  for (const v of VOWELS) {
    if (CVC_WORDS[v].includes(word)) return v;
  }
  return 'a';
}

// ============ BUBBLE CLASS ============
class Bubble {
  constructor(word, x, y, vowel, fallMin, fallMax, R) {
    this.word = word;
    this.x = x; this.y = y;
    this.r = R;
    this.vowel = vowel;
    this.colors = VOWEL_COLORS[vowel] || ['#ccc','#999'];
    this.baseX = x;
    this.wobblePhase = Math.random() * Math.PI * 2;
    this.wobbleSpeed = 1.2 + Math.random() * 1.0;
    this.wobbleAmp = 15 + Math.random() * 25;
    this.fallSpeed = fallMin + Math.random() * (fallMax - fallMin);
    this.sway = (Math.random() - 0.5) * 20;
    this.alpha = 0; this.scale = 0.2;
    this.alive = true; this.popping = false; this.popPhase = 0;
    this.dx = x; this.dy = y;
    this.rotation = (Math.random() - 0.5) * 0.3;
    this.rotSpeed = (Math.random() - 0.5) * 0.5;
  }

  update(dt, W) {
    if (this.popping) {
      this.popPhase += dt * 5;
      this.scale = 1 + this.popPhase * 0.6;
      this.alpha = Math.max(0, 1 - this.popPhase);
      if (this.alpha <= 0) this.alive = false;
      return;
    }
    this.alpha = Math.min(1, this.alpha + dt * 4);
    this.scale = Math.min(1, this.scale + dt * 4);
    this.wobblePhase += this.wobbleSpeed * dt;
    this.baseX += this.sway * dt;
    this.dx = this.baseX + Math.sin(this.wobblePhase) * this.wobbleAmp;
    this.y += this.fallSpeed * dt;
    this.dy = this.y;
    this.rotation += this.rotSpeed * dt;
    if (this.dx - this.r < 0) { this.baseX += 2; this.sway = Math.abs(this.sway); }
    if (this.dx + this.r > W) { this.baseX -= 2; this.sway = -Math.abs(this.sway); }
  }

  draw(c) {
    if (!this.alive) return;
    c.save();
    c.globalAlpha = this.alpha;
    c.translate(this.dx, this.dy);
    c.rotate(this.rotation);
    c.scale(this.scale, this.scale);

    // Outer glow
    const g = c.createRadialGradient(0, 0, this.r * 0.2, 0, 0, this.r * 1.6);
    g.addColorStop(0, this.colors[0] + '30');
    g.addColorStop(1, 'transparent');
    c.fillStyle = g;
    c.beginPath(); c.arc(0, 0, this.r * 1.6, 0, Math.PI * 2); c.fill();

    // Main body
    const gr = c.createRadialGradient(-this.r * 0.3, -this.r * 0.3, this.r * 0.1, 0, 0, this.r);
    gr.addColorStop(0, this.colors[0]);
    gr.addColorStop(0.6, this.colors[1]);
    gr.addColorStop(1, this.colors[1] + 'aa');
    c.fillStyle = gr;
    c.beginPath(); c.arc(0, 0, this.r, 0, Math.PI * 2); c.fill();

    // Rim
    c.strokeStyle = 'rgba(255,255,255,0.15)';
    c.lineWidth = 2;
    c.beginPath(); c.arc(0, 0, this.r - 1, 0, Math.PI * 2); c.stroke();

    // Shine
    c.fillStyle = 'rgba(255,255,255,0.3)';
    c.beginPath();
    c.ellipse(-this.r * 0.25, -this.r * 0.3, this.r * 0.3, this.r * 0.18, -0.5, 0, Math.PI * 2);
    c.fill();

    // Word text
    c.fillStyle = 'white';
    c.font = `700 ${this.r * 0.62}px 'Segoe UI', sans-serif`;
    c.textAlign = 'center'; c.textBaseline = 'middle';
    c.shadowColor = 'rgba(0,0,0,0.5)'; c.shadowBlur = 4;
    c.fillText(this.word, 0, 2);
    c.shadowBlur = 0;

    c.restore();
  }

  pop(particles) {
    this.popping = true;
    for (let i = 0; i < 14; i++) {
      const a = (Math.PI * 2 * i) / 14, s = 100 + Math.random() * 150;
      particles.push({
        x: this.dx, y: this.dy,
        vx: Math.cos(a) * s, vy: Math.sin(a) * s,
        radius: 3 + Math.random() * 6,
        color: this.colors[Math.floor(Math.random() * 2)],
        life: 1, decay: 1.5 + Math.random()
      });
    }
  }

  contains(px, py) {
    const dx = this.dx - px, dy = this.dy - py;
    return Math.sqrt(dx * dx + dy * dy) < this.r * 1.1;
  }

  fellOff(H) { return this.y > H + this.r * 2; }
}


// ============ BUBBLE GAME CLASS ============
class BubbleGame {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    this.ctx = this.canvas.getContext('2d');
    this.W = 0; this.H = 0; this.BUBBLE_R = 30;
    this.gameState = 'menu'; // menu, playing, result
    this.difficulty = 'normal';
    this.animId = null;
    this.lastTime = 0;
    this.bound = false;

    // Game state
    this.score = 0; this.lives = 3; this.comboCount = 0; this.maxCombo = 0;
    this.currentQuestion = 0; this.totalQuestions = 15;
    this.questionSets = [];
    this.currentSet = null;
    this.bubbles = []; this.projectile = null; this.particles = [];
    this.cannonAngle = -Math.PI / 2;
    this.canShoot = true;
    this.correctCount = 0; this.wrongCount = 0; this.missedCount = 0;
    this.vowelCorrect = {a:0,e:0,i:0,o:0,u:0};
    this.spawnTimer = 0; this.nextSpawnIdx = 0; this.allSpawned = false;
    this.wrongWords = [];
    this.pointerDown = false;

    // Background stars
    this.stars = Array.from({ length: 50 }, () => ({
      x: Math.random(), y: Math.random() * 0.65, r: 0.5 + Math.random() * 1.5,
      tw: Math.random() * Math.PI * 2, sp: 0.5 + Math.random() * 1.5
    }));

    this._resize = this.resize.bind(this);
    this._loop = this.gameLoop.bind(this);
  }

  resize() {
    const wrap = this.canvas.parentElement;
    if (!wrap) return;
    const dpr = window.devicePixelRatio || 1;
    this.W = wrap.clientWidth;
    this.H = wrap.clientHeight;
    this.canvas.width = this.W * dpr;
    this.canvas.height = this.H * dpr;
    this.canvas.style.width = this.W + 'px';
    this.canvas.style.height = this.H + 'px';
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.BUBBLE_R = Math.max(28, Math.min(this.W, this.H) * 0.06);
  }

  bindEvents() {
    if (this.bound) return;
    this.bound = true;
    window.addEventListener('resize', this._resize);

    this.canvas.addEventListener('pointerdown', (e) => {
      if (this.gameState !== 'playing') return;
      this.pointerDown = true;
      this._updateAngle(e.clientX, e.clientY);
    });
    this.canvas.addEventListener('pointermove', (e) => {
      if (this.pointerDown) this._updateAngle(e.clientX, e.clientY);
    });
    this.canvas.addEventListener('pointerup', () => {
      if (this.pointerDown) { this.pointerDown = false; this.shoot(); }
    });
    this._keyHandler = (e) => {
      if (this.gameState !== 'playing') return;
      if (e.code === 'ArrowLeft') this.cannonAngle -= 0.08;
      if (e.code === 'ArrowRight') this.cannonAngle += 0.08;
      if (e.code === 'Space') { e.preventDefault(); this.shoot(); }
    };
    document.addEventListener('keydown', this._keyHandler);
  }

  unbindEvents() {
    if (!this.bound) return;
    this.bound = false;
    window.removeEventListener('resize', this._resize);
    document.removeEventListener('keydown', this._keyHandler);
  }

  _updateAngle(px, py) {
    const rect = this.canvas.getBoundingClientRect();
    const cx = px - rect.left;
    const cy = py - rect.top;
    const base = this._getBase();
    this.cannonAngle = Math.atan2(cy - base.y, cx - base.x);
    if (this.cannonAngle > 0) this.cannonAngle = cx < base.x ? Math.PI - 0.1 : -0.1;
  }

  _getBase() { return { x: this.W / 2, y: this.H - 55 }; }

  // ===== Daily Limit =====
  getTodayKey() {
    const d = new Date();
    return `bubble_plays_${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
  }

  getPlaysToday() {
    return parseInt(localStorage.getItem(this.getTodayKey()) || '0', 10);
  }

  incrementPlays() {
    const k = this.getTodayKey();
    localStorage.setItem(k, String(this.getPlaysToday() + 1));
  }

  getRemainingPlays() {
    return Math.max(0, DAILY_LIMIT - this.getPlaysToday());
  }

  // ===== Menu =====
  showMenu() {
    this.gameState = 'menu';
    this.stopLoop();
    this.resize();
    this.bindEvents();

    // Draw dark background
    this.ctx.clearRect(0, 0, this.W, this.H);
    const grd = this.ctx.createLinearGradient(0, 0, 0, this.H);
    grd.addColorStop(0, '#0a1628'); grd.addColorStop(1, '#1a2a4a');
    this.ctx.fillStyle = grd;
    this.ctx.fillRect(0, 0, this.W, this.H);

    const remaining = this.getRemainingPlays();
    const playsEl = document.getElementById('bubblePlaysLeft');
    if (playsEl) {
      if (remaining > 0) {
        playsEl.innerHTML = `<span style="color:#ffd166;font-size:15px">오늘 남은 횟수: <b>${remaining}/${DAILY_LIMIT}</b></span>`;
      } else {
        playsEl.innerHTML = `<span style="color:#ef476f;font-size:15px">오늘은 다 했어요! 내일 다시 해봐요 ^^</span>`;
      }
    }

    // Show/hide difficulty buttons based on remaining plays
    const btns = document.querySelectorAll('.difficulty-btns .diff-btn');
    btns.forEach(b => {
      b.disabled = remaining <= 0;
      b.style.opacity = remaining > 0 ? '1' : '0.4';
    });

    document.getElementById('bubbleMenuOverlay').style.display = '';
    document.getElementById('bubbleResultOverlay').style.display = 'none';
    document.getElementById('bubbleHud').style.display = 'none';
    document.getElementById('bubbleTargetBar').style.display = 'none';
  }

  // ===== Start Game =====
  start(diff) {
    if (this.getRemainingPlays() <= 0) return;

    this.difficulty = diff;
    const cfg = DIFFICULTY[diff];
    this.totalQuestions = cfg.questions;
    this.lives = cfg.lives;

    this.score = 0; this.comboCount = 0; this.maxCombo = 0;
    this.currentQuestion = 0; this.correctCount = 0; this.wrongCount = 0; this.missedCount = 0;
    this.vowelCorrect = {a:0,e:0,i:0,o:0,u:0};
    this.wrongWords = [];
    this.bubbles = []; this.projectile = null; this.particles = [];
    this.cannonAngle = -Math.PI / 2;
    this.canShoot = true;

    this.questionSets = this._generateQuestions(cfg.questions, cfg.choices);
    this.gameState = 'playing';

    document.getElementById('bubbleMenuOverlay').style.display = 'none';
    document.getElementById('bubbleResultOverlay').style.display = 'none';
    document.getElementById('bubbleHud').style.display = 'flex';

    this._updateHUD();
    this._nextQuestion();
    this.startLoop();
  }

  // ===== Question Generation =====
  _generateQuestions(count, numChoices) {
    const sets = [];
    for (let i = 0; i < count; i++) {
      const vowel = VOWELS[i % 5];
      const words = CVC_WORDS[vowel];
      const target = words[Math.floor(Math.random() * words.length)];
      const distractors = [];
      const otherVowels = shuffleArr(VOWELS.filter(v => v !== vowel));
      for (const ov of otherVowels) {
        const ow = CVC_WORDS[ov];
        const pick = ow[Math.floor(Math.random() * ow.length)];
        if (!distractors.includes(pick) && pick !== target) distractors.push(pick);
        if (distractors.length >= numChoices - 1) break;
      }
      while (distractors.length < numChoices - 1) {
        const rv = VOWELS[Math.floor(Math.random() * 5)];
        const rw = CVC_WORDS[rv][Math.floor(Math.random() * CVC_WORDS[rv].length)];
        if (rw !== target && !distractors.includes(rw)) distractors.push(rw);
      }
      sets.push({ target, vowel, choices: shuffleArr([target, ...distractors]) });
    }
    return shuffleArr(sets);
  }

  _nextQuestion() {
    if (this.currentQuestion >= this.totalQuestions || this.lives <= 0) {
      this._endGame();
      return;
    }
    this.currentSet = this.questionSets[this.currentQuestion];
    this.bubbles = [];
    this.projectile = null;
    this.canShoot = true;
    this.spawnTimer = 0;
    this.nextSpawnIdx = 0;
    this.allSpawned = false;

    const tb = document.getElementById('bubbleTargetBar');
    tb.style.display = 'flex';
    document.getElementById('bubbleTargetWord').textContent = this.currentSet.target.toUpperCase();
    document.getElementById('bubbleQCount').textContent = `${this.currentQuestion + 1}/${this.totalQuestions}`;
    this._updateHUD();

    setTimeout(() => this._speakWord(this.currentSet.target), 400);
  }

  // ===== Spawn =====
  _spawnBubble() {
    if (this.allSpawned || !this.currentSet) return;
    if (this.nextSpawnIdx >= this.currentSet.choices.length) {
      this.allSpawned = true;
      return;
    }
    const word = this.currentSet.choices[this.nextSpawnIdx];
    const vowel = getWordVowel(word);
    const cfg = DIFFICULTY[this.difficulty];
    const margin = this.BUBBLE_R + 20;
    const x = margin + Math.random() * (this.W - margin * 2);
    const y = -this.BUBBLE_R - Math.random() * 40;
    this.bubbles.push(new Bubble(word, x, y, vowel, cfg.fallMin, cfg.fallMax, this.BUBBLE_R));
    this.nextSpawnIdx++;
  }

  // ===== Shoot =====
  shoot() {
    if (!this.canShoot || this.projectile || this.gameState !== 'playing') return;
    const b = this._getBase();
    this.projectile = {
      x: b.x + Math.cos(this.cannonAngle) * 46,
      y: b.y + Math.sin(this.cannonAngle) * 46,
      vx: Math.cos(this.cannonAngle) * 700,
      vy: Math.sin(this.cannonAngle) * 700
    };
  }

  // ===== Hit =====
  _handleHit(bubble) {
    this.canShoot = false;
    this.projectile = null;

    if (bubble.word === this.currentSet.target) {
      this.comboCount++;
      if (this.comboCount > this.maxCombo) this.maxCombo = this.comboCount;
      const comboBonus = Math.min(this.comboCount, 5) * 20;
      this.score += 100 + comboBonus;
      this.correctCount++;
      this.vowelCorrect[this.currentSet.vowel]++;
      bubble.pop(this.particles);
      const txt = this.comboCount >= 3 ? `x${this.comboCount} COMBO!` : 'GREAT!';
      this._showFeedback(true, txt);
      this.currentQuestion++;
      setTimeout(() => this._nextQuestion(), 900);
    } else {
      this.lives--;
      this.wrongCount++;
      this.comboCount = 0;
      if (!this.wrongWords.includes(this.currentSet.target)) {
        this.wrongWords.push(this.currentSet.target);
      }
      bubble.pop(this.particles);
      this._showFeedback(false, bubble.word + ' ≠ ' + this.currentSet.target);
      setTimeout(() => {
        if (this.lives <= 0) this._endGame();
        else { this.canShoot = true; this._speakWord(this.currentSet.target); }
      }, 800);
    }
    this._updateHUD();
  }

  _handleMiss() {
    this.lives--;
    this.missedCount++;
    this.comboCount = 0;
    if (!this.wrongWords.includes(this.currentSet.target)) {
      this.wrongWords.push(this.currentSet.target);
    }
    this._showFeedback(false, 'Too slow!');
    this._updateHUD();
    setTimeout(() => {
      if (this.lives <= 0) this._endGame();
      else { this.currentQuestion++; this._nextQuestion(); }
    }, 800);
  }

  // ===== End Game =====
  async _endGame() {
    this.gameState = 'result';
    this.stopLoop();
    this.incrementPlays();

    document.getElementById('bubbleHud').style.display = 'none';
    document.getElementById('bubbleTargetBar').style.display = 'none';

    document.getElementById('bubbleResultScore').textContent = this.score;

    // Vowel stats
    const vs = document.getElementById('bubbleVowelStats');
    vs.innerHTML = VOWELS.map(v =>
      `<div class="vowel-stat"><div class="letter" style="color:${VOWEL_COLORS[v][0]}">${v}</div><div class="count">${this.vowelCorrect[v]}/${Math.ceil(this.totalQuestions/5)}</div></div>`
    ).join('');

    document.getElementById('bubbleResultDetail').innerHTML =
      `<div>Correct: ${this.correctCount} | Wrong: ${this.wrongCount} | Missed: ${this.missedCount}</div>` +
      `<div>Max Combo: ${this.maxCombo}x | Difficulty: ${DIFFICULTY[this.difficulty].label}</div>`;

    // Wrong words review
    const wr = document.getElementById('bubbleWrongReview');
    if (this.wrongWords.length > 0) {
      wr.innerHTML = '<div style="color:#ef476f;font-weight:700;margin-bottom:8px">틀린 단어 복습:</div>' +
        this.wrongWords.map(w =>
          `<div class="wrong-word-row">
            <button class="bubble-listen-btn" onclick="bubbleGame._speakWord('${w}')">&#128264;</button>
            <span style="font-size:18px;font-weight:700;color:#ffd166">${w}</span>
          </div>`
        ).join('');
    } else {
      wr.innerHTML = '<div style="color:#06d6a0;font-weight:700">Perfect! 틀린 단어가 없어요!</div>';
    }

    document.getElementById('bubbleResultOverlay').style.display = '';

    // Save progress
    try {
      const label = '버블게임 ' + DIFFICULTY[this.difficulty].label;
      await fetch('/api/progress', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({
          activity: label,
          word: this.wrongWords.join(','),
          correct: this.correctCount,
          total: this.totalQuestions,
          score: this.score
        })
      });
    } catch(e) {}
  }

  // ===== TTS =====
  _speakWord(word) {
    const audio = new Audio('/api/tts?text=' + encodeURIComponent(word));
    audio.play().catch(() => {
      try {
        if ('speechSynthesis' in window) {
          window.speechSynthesis.cancel();
          const u = new SpeechSynthesisUtterance(word);
          u.lang = 'en-US'; u.rate = 0.82; u.pitch = 1.1;
          window.speechSynthesis.speak(u);
        }
      } catch(e) {}
    });
  }

  speakCurrent() {
    if (this.currentSet) this._speakWord(this.currentSet.target);
  }

  // ===== Feedback =====
  _showFeedback(ok, text) {
    const el = document.getElementById('bubbleFeedback');
    if (!el) return;
    const t = el.querySelector('.bubble-feedback-text');
    t.textContent = (ok ? '⭐ ' : '❌ ') + text;
    t.className = 'bubble-feedback-text ' + (ok ? 'correct' : 'wrong');
    el.classList.add('show');
    setTimeout(() => el.classList.remove('show'), 700);
  }

  // ===== HUD =====
  _updateHUD() {
    document.getElementById('bubbleScore').textContent = this.score;
    document.getElementById('bubbleLives').textContent = '❤️'.repeat(Math.max(0, this.lives));
    const cd = document.getElementById('bubbleCombo');
    if (this.comboCount >= 2) {
      cd.style.opacity = '1';
      document.getElementById('bubbleComboVal').textContent = this.comboCount;
    } else {
      cd.style.opacity = '0';
    }
  }

  // ===== Drawing =====
  _drawBG(time) {
    const c = this.ctx;
    c.fillStyle = 'rgba(10,22,40,0.15)';
    c.fillRect(0, 0, this.W, this.H);
    for (const s of this.stars) {
      const a = 0.3 + 0.7 * Math.abs(Math.sin(s.tw + time * s.sp));
      c.save(); c.globalAlpha = a; c.fillStyle = '#fff';
      c.beginPath(); c.arc(s.x * this.W, s.y * this.H, s.r, 0, Math.PI * 2); c.fill();
      c.restore();
    }
    // Danger zone
    c.save(); c.globalAlpha = 0.12;
    c.strokeStyle = '#ef476f'; c.lineWidth = 1; c.setLineDash([10, 8]);
    c.beginPath(); c.moveTo(0, this.H - 110); c.lineTo(this.W, this.H - 110); c.stroke();
    c.setLineDash([]); c.restore();
    // Waves
    c.save(); c.globalAlpha = 0.06;
    for (let i = 0; i < 3; i++) {
      c.strokeStyle = '#48dbfb'; c.lineWidth = 1; c.beginPath();
      for (let x = 0; x <= this.W; x += 5) {
        const y = this.H - 80 - i * 15 + Math.sin(x * 0.025 + time * 2 + i) * 6;
        x === 0 ? c.moveTo(x, y) : c.lineTo(x, y);
      }
      c.stroke();
    }
    c.restore();
  }

  _drawCannon() {
    const c = this.ctx, b = this._getBase(), CL = 46, CW = 16;
    c.save(); c.translate(b.x, b.y); c.rotate(this.cannonAngle + Math.PI / 2);
    const bg = c.createLinearGradient(-CW/2, 0, CW/2, 0);
    bg.addColorStop(0, '#ff8855'); bg.addColorStop(0.5, '#ffaa77'); bg.addColorStop(1, '#ff6b35');
    c.fillStyle = bg;
    c.beginPath(); c.roundRect(-CW/2, -CL, CW, CL, [5,5,0,0]); c.fill();
    c.fillStyle = '#ffd166';
    c.beginPath(); c.roundRect(-CW/2-3, -CL-3, CW+6, 8, 3); c.fill();
    c.restore();
    const gg = c.createRadialGradient(b.x, b.y, 4, b.x, b.y, 24);
    gg.addColorStop(0, '#ffaa77'); gg.addColorStop(1, '#ff6b35');
    c.fillStyle = gg; c.beginPath(); c.arc(b.x, b.y, 22, 0, Math.PI * 2); c.fill();
    c.fillStyle = '#ffd166'; c.beginPath(); c.arc(b.x, b.y, 7, 0, Math.PI * 2); c.fill();
  }

  _drawAim() {
    if (!this.canShoot || this.projectile) return;
    const c = this.ctx, b = this._getBase();
    c.save(); c.setLineDash([6, 6]); c.strokeStyle = 'rgba(255,209,102,0.2)'; c.lineWidth = 2;
    c.beginPath(); c.moveTo(b.x, b.y);
    c.lineTo(b.x + Math.cos(this.cannonAngle) * 180, b.y + Math.sin(this.cannonAngle) * 180);
    c.stroke(); c.setLineDash([]); c.restore();
  }

  _drawProjectile() {
    if (!this.projectile) return;
    const c = this.ctx, p = this.projectile;
    c.save(); c.fillStyle = '#ffd166'; c.shadowColor = '#ffd166'; c.shadowBlur = 14;
    c.beginPath(); c.arc(p.x, p.y, 7, 0, Math.PI * 2); c.fill();
    c.globalAlpha = 0.25;
    c.beginPath(); c.arc(p.x - p.vx * 0.015, p.y - p.vy * 0.015, 5, 0, Math.PI * 2); c.fill();
    c.restore();
  }

  _updateParticles(dt) {
    for (let i = this.particles.length - 1; i >= 0; i--) {
      const p = this.particles[i];
      p.x += p.vx * dt; p.y += p.vy * dt; p.vy += 250 * dt; p.life -= p.decay * dt;
      if (p.life <= 0) this.particles.splice(i, 1);
    }
  }

  _drawParticles() {
    const c = this.ctx;
    for (const p of this.particles) {
      c.save(); c.globalAlpha = p.life; c.fillStyle = p.color;
      c.beginPath(); c.arc(p.x, p.y, p.radius * p.life, 0, Math.PI * 2); c.fill();
      c.restore();
    }
  }

  // ===== Game Loop =====
  startLoop() {
    this.lastTime = performance.now();
    if (this.animId) cancelAnimationFrame(this.animId);
    this.animId = requestAnimationFrame(this._loop);
  }

  stopLoop() {
    if (this.animId) { cancelAnimationFrame(this.animId); this.animId = null; }
  }

  gameLoop(ts) {
    const dt = Math.min((ts - this.lastTime) / 1000, 0.05);
    this.lastTime = ts;
    const time = ts / 1000;

    this.ctx.clearRect(0, 0, this.W, this.H);
    this._drawBG(time);

    if (this.gameState === 'playing' && this.currentSet) {
      const cfg = DIFFICULTY[this.difficulty];

      // Spawn bubbles
      if (!this.allSpawned) {
        this.spawnTimer += dt;
        while (this.spawnTimer >= cfg.spawnInterval && !this.allSpawned) {
          this.spawnTimer -= cfg.spawnInterval;
          this._spawnBubble();
        }
      }

      // Update bubbles
      for (const b of this.bubbles) b.update(dt, this.W);

      // Check target fell
      let targetFell = false;
      for (const b of this.bubbles) {
        if (!b.popping && b.word === this.currentSet.target && b.fellOff(this.H)) {
          targetFell = true;
          break;
        }
      }
      if (targetFell) {
        this.canShoot = false;
        this.projectile = null;
        this.bubbles = [];
        this._handleMiss();
      }

      // Remove dead
      this.bubbles = this.bubbles.filter(b => b.alive && !b.fellOff(this.H));

      // Projectile
      if (this.projectile) {
        this.projectile.x += this.projectile.vx * dt;
        this.projectile.y += this.projectile.vy * dt;
        for (const b of this.bubbles) {
          if (!b.popping && b.contains(this.projectile.x, this.projectile.y)) {
            this._handleHit(b);
            break;
          }
        }
        if (this.projectile && (
          this.projectile.x < -20 || this.projectile.x > this.W + 20 ||
          this.projectile.y < -20 || this.projectile.y > this.H + 20
        )) {
          this.projectile = null;
          this.canShoot = true;
        }
      }

      // Draw
      for (const b of this.bubbles) b.draw(this.ctx);
      this._drawAim();
      this._drawProjectile();
      this._drawCannon();
    }

    this._updateParticles(dt);
    this._drawParticles();

    this.animId = requestAnimationFrame(this._loop);
  }

  // ===== Cleanup =====
  destroy() {
    this.stopLoop();
    this.unbindEvents();
    this.gameState = 'menu';
  }
}
