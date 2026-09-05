/* app.js — MMS 2026 Midway live demo site.
 *
 * Runs the repository's real demo scripts in the browser via Pyodide.
 * If Pyodide cannot load (dead Wi-Fi on a first visit), falls back to the
 * transcript baked at build time from the same code. The audience cannot tell
 * the difference; the status pill tells you.
 *
 * Playback pauses automatically at the beats the demos already mark:
 *   - every ">> STAGE NOTE:" line          (talk about what just happened)
 *   - before each "STAGE n/6" / "STEP n/5" (talk about what is coming)
 * Space continues. That is the whole stage-control model.
 */
(function () {
  'use strict';

  var PYODIDE_URL = 'https://cdn.jsdelivr.net/pyodide/v0.26.4/full/pyodide.js';

  var state = {
    manifest: null,
    pyodide: null,
    engine: 'loading',   // loading | live | fallback
    ready: null,         // resolves when the engine is decided
    session: null,       // which session tab is showing
    demo: null,
    variantIndex: 0,
    player: null
  };

  /* ------------------------------------------------------------------ *
   * Boot
   * ------------------------------------------------------------------ */

  document.addEventListener('DOMContentLoaded', function () {
    fetch('data/manifest.json')
      .then(function (r) { return r.json(); })
      .then(function (m) {
        state.manifest = m;
        render(m);
        bootPython(m);
        openFromUrl(m);
      })
      .catch(function (e) {
        document.getElementById('sessions').innerHTML =
          '<p class="muted">Could not load the demo manifest: ' + e + '</p>';
      });

    // Offline cache, so a dead network mid-session does not kill the demos.
    if ('serviceWorker' in navigator && location.protocol !== 'file:') {
      navigator.serviceWorker.register('sw.js').catch(function () {});
    }

    document.getElementById('run-close').addEventListener('click', closeRunner);
    document.getElementById('run-copy').addEventListener('click', copyOutput);
    document.getElementById('runner').addEventListener('click', function (e) {
      if (e.target.id === 'runner') closeRunner();
    });
    var ps = document.getElementById('opt-pause');
    try { ps.value = localStorage.getItem('mms-pause') || 'beats'; } catch (e) {}
    ps.addEventListener('change', function () {
      try { localStorage.setItem('mms-pause', ps.value); } catch (e) {}
      if (state.demo && !document.getElementById('runner').hidden &&
          document.getElementById('run-video-wrap').hidden) {
        start(state.variantIndex);          // re-run so the new granularity applies
      }
    });

    document.addEventListener('keydown', onKey);
  });

  function setEngine(kind, text, title) {
    state.engine = kind;
    var pill = document.getElementById('engine');
    pill.className = 'pill pill-' + (kind === 'live' ? 'live' : kind === 'fallback' ? 'fallback' : 'wait');
    pill.title = title || '';
    document.getElementById('engine-text').textContent = text;
  }

  function bootPython(manifest) {
    // ?mode=fallback forces the baked-transcript path, so you can rehearse the
    // dead-Wi-Fi case on purpose instead of discovering it on stage.
    if (new URLSearchParams(location.search).get('mode') === 'fallback') {
      setEngine('fallback', 'recorded output (forced)',
        'Forced with ?mode=fallback. This is what a failed Python load looks like.');
      document.getElementById('footnote').textContent =
        'Fallback forced with ?mode=fallback — playing transcripts baked from the same code at build time.';
      state.ready = Promise.resolve();
      return;
    }

    setEngine('loading', 'loading Python…', 'Downloading the Python runtime');

    state.ready = loadScript(PYODIDE_URL)
      .then(function () { return loadPyodide({ indexURL: PYODIDE_URL.replace('pyodide.js', '') }); })
      .then(function (py) {
        state.pyodide = py;
        return mountDemos(py, manifest);
      })
      .then(function () {
        setEngine('live', 'Python ready', 'Running the real demo code in this tab');
        var f = document.getElementById('footnote');
        f.textContent = 'Python ' + state.pyodide.runPython('import sys; sys.version.split()[0]') +
                        ' running in WebAssembly. ' + manifest.pyAssets.length +
                        ' demo files mounted.';
      })
      .catch(function (err) {
        console.warn('Pyodide unavailable, using baked transcripts:', err);
        setEngine('fallback', 'recorded output',
          'The Python runtime could not load, so these are transcripts baked from the same code at build time.');
        document.getElementById('footnote').textContent =
          'Python runtime unavailable — playing transcripts baked from the same code at build time.';
      });
  }

  function loadScript(src) {
    return new Promise(function (resolve, reject) {
      var s = document.createElement('script');
      s.src = src;
      s.onload = resolve;
      s.onerror = function () { reject(new Error('failed to load ' + src)); };
      document.head.appendChild(s);
    });
  }

  /* Copy the demo sources into Pyodide's virtual filesystem, preserving the
   * directory layout so the scripts' sibling imports and relative data paths
   * work with no modification. */
  function mountDemos(py, manifest) {
    py.FS.mkdirTree('/demos');
    return Promise.all(manifest.pyAssets.map(function (rel) {
      return fetch('py/' + rel).then(function (r) {
        if (!r.ok) throw new Error('missing ' + rel);
        return r.arrayBuffer();
      }).then(function (buf) {
        var full = '/demos/' + rel;
        py.FS.mkdirTree(full.slice(0, full.lastIndexOf('/')));
        py.FS.writeFile(full, new Uint8Array(buf));
      });
    }));
  }

  /* ------------------------------------------------------------------ *
   * Rendering
   * ------------------------------------------------------------------ */

  /* The two sessions are tabs, not stacked sections: one is visible at a time,
   * so what is on the projector is only ever the session being presented. */
  function render(m) {
    var nav = document.getElementById('sessionnav');
    var host = document.getElementById('sessions');
    nav.innerHTML = '';
    host.innerHTML = '';
    nav.setAttribute('role', 'tablist');

    m.sessions.forEach(function (s) {
      var b = document.createElement('button');
      b.textContent = s.title;
      b.dataset.s = s.id;
      b.id = 'tab-' + s.id;
      b.setAttribute('role', 'tab');
      b.setAttribute('aria-controls', 'sess-' + s.id);
      b.addEventListener('click', function () { showSession(s.id); });
      nav.appendChild(b);

      var demos = m.demos.filter(function (d) { return d.session === s.id; });
      var sec = document.createElement('section');
      sec.className = 'session';
      sec.id = 'sess-' + s.id;
      sec.setAttribute('role', 'tabpanel');
      sec.setAttribute('aria-labelledby', 'tab-' + s.id);
      sec.style.setProperty('--accent', s.accent);
      sec.innerHTML =
        '<div class="session-head">' +
          '<h2>' + esc(s.title) + '</h2>' +
          '<p class="sub">' + esc(s.subtitle) + '</p>' +
          '<p class="meta">' + esc(s.slot) + '  ·  ' + esc(s.presenters) + '</p>' +
          deckBar(s) +
        '</div><div class="grid"></div>';
      var grid = sec.querySelector('.grid');
      demos.forEach(function (d) { grid.appendChild(card(d, s)); });
      host.appendChild(sec);
    });

    // ?s=<session> survives a reload, so the tab you are on is the tab you
    // come back to.
    var wanted = new URLSearchParams(location.search).get('s');
    var valid = m.sessions.some(function (s) { return s.id === wanted; });
    showSession(valid ? wanted : m.sessions[0].id, true);
  }

  function showSession(id, skipUrl) {
    state.session = id;

    document.getElementById('sessionnav').querySelectorAll('button').forEach(function (b) {
      var on = b.dataset.s === id;
      b.setAttribute('aria-current', String(on));
      b.setAttribute('aria-selected', String(on));
      b.tabIndex = on ? 0 : -1;
    });

    document.getElementById('sessions').querySelectorAll('.session').forEach(function (sec) {
      sec.hidden = sec.id !== 'sess-' + id;
    });

    if (!skipUrl) {
      var p = new URLSearchParams(location.search);
      p.set('s', id);
      history.replaceState(null, '', location.pathname + '?' + p.toString());
    }
  }

  /* The session's slide deck, three ways: rendered in the browser by Office's
   * own viewer, downloaded, or handed to desktop PowerPoint via its protocol
   * handler. All three point at the committed file on GitHub rather than a
   * copy in this site, so they cannot drift from the deck in the repo. */
  function deckBar(s) {
    if (!s.deck) return '';
    return '<div class="deck">' +
      '<span class="deck-label">Slide deck</span>' +
      '<a class="btn btn-sm btn-ghost" target="_blank" rel="noopener" href="' +
        esc(s.deck.view) + '">Open in browser</a>' +
      '<a class="btn btn-sm btn-ghost" href="' + esc(s.deck.download) + '">Download</a>' +
      '<a class="btn btn-sm btn-ghost" href="' + esc(s.deck.powerpoint) +
        '" title="Opens in desktop PowerPoint. Windows with Office installed.">' +
        'Open in PowerPoint</a>' +
      '<span class="deck-file">' + esc(s.deck.file) + '</span>' +
    '</div>';
  }

  function card(d, session) {
    var el = document.createElement('article');
    el.className = 'card';
    el.style.setProperty('--accent', session.accent);

    var html =
      '<div class="slide">' + esc(d.subtitle || '') + '</div>' +
      '<h3>' + esc(d.title) + '</h3>' +
      '<p class="blurb">' + esc(d.blurb) + '</p>';

    if (d.note) html += '<div class="note">' + esc(d.note) + '</div>';

    html += '<div class="card-foot"></div>';
    el.innerHTML = html;
    var foot = el.querySelector('.card-foot');

    if (d.kind === 'run' || d.kind === 'playback') {
      var run = document.createElement('button');
      run.className = 'btn';
      run.textContent = d.kind === 'playback' ? 'Play' : 'Run';
      run.addEventListener('click', function () { openRunner(d, session); });
      foot.appendChild(run);

      if (d.variants && d.variants.length > 1) {
        var c = document.createElement('span');
        c.className = 'count';
        c.textContent = d.variants.length + ' variants';
        foot.appendChild(c);
      }

      if (d.video) {
        var vb = document.createElement('button');
        vb.className = 'btn btn-sm btn-ghost';
        vb.innerHTML = '&#9654; Recording';
        vb.title = 'Silent screen recording, ' + (d.videoLength || '');
        vb.addEventListener('click', function (e) {
          e.stopPropagation();
          openRunner(d, session, null, true);
        });
        foot.appendChild(vb);
      }
    }

    (d.links || []).forEach(function (l) {
      var a = document.createElement('a');
      a.className = 'ghost btn-sm';
      a.href = l.href; a.target = '_blank'; a.rel = 'noopener';
      a.textContent = l.label;
      foot.appendChild(a);
    });

    return el;
  }

  /* ------------------------------------------------------------------ *
   * Runner
   * ------------------------------------------------------------------ */

  /* Deep links: ?demo=<id>&v=<variantIndex>.
   * Hyperlink one of these straight from a slide and it opens the right demo,
   * on the right variant, ready to run. */
  function openFromUrl(m) {
    var params = new URLSearchParams(location.search);
    var id = params.get('demo');
    if (!id) return;
    var d = m.demos.find(function (x) { return x.id === id; });
    if (!d) return;
    var session = m.sessions.find(function (s) { return s.id === d.session; });
    showSession(d.session, true);
    var v = parseInt(params.get('v') || '', 10);
    openRunner(d, session, isNaN(v) ? null : v);
  }

  function syncUrl() {
    if (!state.demo) return;
    var p = new URLSearchParams(location.search);
    p.set('s', state.demo.session);
    p.set('demo', state.demo.id);
    if (state.demo.kind === 'run') p.set('v', String(state.variantIndex));
    else p.delete('v');
    history.replaceState(null, '', location.pathname + '?' + p.toString());
  }

  function clearUrl() {
    var p = new URLSearchParams(location.search);
    p.delete('demo'); p.delete('v');
    var q = p.toString();
    history.replaceState(null, '', location.pathname + (q ? '?' + q : ''));
  }

  function openRunner(d, session, forceVariant, startWithVideo) {
    state.demo = d;
    state.variantIndex = 0;

    document.getElementById('runner').style.setProperty('--accent', session.accent);
    document.getElementById('run-title').textContent = d.title;
    document.getElementById('run-sub').textContent = d.subtitle || '';
    document.getElementById('runner').hidden = false;

    var bar = document.getElementById('run-variants');
    bar.innerHTML = '';

    if (d.kind === 'playback') {
      var one = document.createElement('button');
      one.className = 'btn btn-sm';
      one.textContent = 'Play recording';
      one.addEventListener('click', function () { start(0); });
      bar.appendChild(one);
      start(0);
      return;
    }

    d.variants.forEach(function (v, i) {
      var b = document.createElement('button');
      // All variants look alike; aria-pressed is the only "active" signal, so
      // the selected run is unambiguous on a projector.
      b.className = 'btn btn-sm btn-ghost' + (v.highlight ? ' hot' : '');
      b.textContent = v.label;
      b.setAttribute('aria-pressed', 'false');
      b.addEventListener('click', function () { start(i); });
      bar.appendChild(b);
    });

    if (d.video) {
      var vbtn = document.createElement('button');
      vbtn.className = 'btn btn-sm btn-ghost vid';
      vbtn.innerHTML = '&#9654; Recording' + (d.videoLength ? ' · ' + d.videoLength : '');
      vbtn.setAttribute('aria-pressed', 'false');
      vbtn.addEventListener('click', function () { showVideo(d); });
      bar.appendChild(vbtn);
    }

    if (startWithVideo && d.video) { showVideo(d); return; }

    var pick = (typeof forceVariant === 'number' && forceVariant >= 0 &&
                forceVariant < d.variants.length)
      ? forceVariant
      : d.variants.findIndex(function (v) { return v.primary; });
    start(pick < 0 ? 0 : pick);
  }

  /* Swap the terminal for the recorded backup. */
  function showVideo(d) {
    if (state.player) { state.player.stop(); state.player = null; }
    runToken++;                                   // cancel any pending run

    var v = document.getElementById('run-video');
    if (v.getAttribute('src') !== d.video) v.setAttribute('src', d.video);

    document.getElementById('run-term').hidden = true;
    document.getElementById('run-video-wrap').hidden = false;
    document.getElementById('run-cmd').textContent = d.video.split('/').pop();
    document.getElementById('run-status').innerHTML =
      '<span class="a-yellow">recorded backup</span> — silent, no narration';

    document.getElementById('run-variants').querySelectorAll('button')
      .forEach(function (b) {
        b.setAttribute('aria-pressed', String(b.classList.contains('vid')));
      });

    v.play().catch(function () {});              // autoplay may be blocked; fine
  }

  function hideVideo() {
    var v = document.getElementById('run-video');
    try { v.pause(); } catch (e) {}
    document.getElementById('run-video-wrap').hidden = true;
    document.getElementById('run-term').hidden = false;
  }

  function closeRunner() {
    if (state.player) { state.player.stop(); state.player = null; }
    hideVideo();
    document.getElementById('runner').hidden = true;
    state.demo = null;
    clearUrl();
  }

  function start(index) {
    var d = state.demo;
    if (!d) return;
    state.variantIndex = index;

    hideVideo();
    var buttons = document.getElementById('run-variants').querySelectorAll('button');
    buttons.forEach(function (b, i) {
      b.setAttribute('aria-pressed', String(!b.classList.contains('vid') && i === index));
    });
    syncUrl();

    var term = document.getElementById('run-term');
    var status = document.getElementById('run-status');
    var cmdEl = document.getElementById('run-cmd');

    if (state.player) { state.player.stop(); state.player = null; }
    term.innerHTML = '';

    if (d.kind === 'playback') {
      cmdEl.textContent = 'recorded output';
      status.textContent = 'loading…';
      fetchTranscript(d.transcript).then(function (text) { play(text, 'recorded'); });
      return;
    }

    var variant = d.variants[index];
    var name = d.script.split('/').pop();
    cmdEl.textContent = 'python ' + name + (variant.args.length ? ' ' + variant.args.map(q).join(' ') : '');

    var token = ++runToken;

    status.textContent = state.engine === 'loading'
      ? 'waiting for Python…'
      : 'running…';

    // Wait for the engine to be decided. A deep link opens before Pyodide has
    // finished loading, and without this it would always fall back.
    Promise.resolve(state.ready).catch(function () {}).then(function () {
      if (token !== runToken) return;          // a different variant was clicked

      if (state.engine !== 'live') {
        return fetchTranscript(variant.transcript).then(function (text) {
          if (token === runToken) play(text, 'recorded');
        });
      }

      status.textContent = 'running…';
      return runPython(d.script, variant.args)
        .then(function (text) { if (token === runToken) play(text, 'live'); })
        .catch(function (err) {
          console.warn('run failed, falling back:', err);
          return fetchTranscript(variant.transcript).then(function (t) {
            if (token === runToken) play(t, 'recorded');
          });
        });
    });
  }

  var runToken = 0;

  function q(s) { return /[\s]/.test(s) ? '"' + s + '"' : s; }

  function fetchTranscript(key) {
    return fetch('transcripts/' + key + '.txt')
      .then(function (r) { return r.ok ? r.text() : '(transcript unavailable)'; })
      .catch(function () { return '(transcript unavailable)'; });
  }

  /* Execute one demo script inside Pyodide and return its captured stdout. */
  function runPython(scriptRel, args) {
    var py = state.pyodide;
    var code = [
      'import io, os, runpy, sys, time',
      '',
      'class _Tty(io.StringIO):',
      '    def isatty(self): return True',
      '',
      '_script = "/demos/' + scriptRel + '"',
      '_dir = _script.rsplit("/", 1)[0]',
      '_argv, _out, _path, _cwd = sys.argv, sys.stdout, list(sys.path), os.getcwd()',
      '_sleep = time.sleep',
      '_buf = _Tty()',
      'try:',
      '    os.chdir(_dir)',
      '    sys.argv = [_script] + ' + JSON.stringify(args),
      '    sys.stdout = _buf',
      '    sys.path.insert(0, _dir)',
      '    time.sleep = lambda *a, **k: None',   // pacing is the player's job here
      '    try:',
      '        runpy.run_path(_script, run_name="__main__")',
      '    except SystemExit:',
      '        pass',
      'finally:',
      '    os.chdir(_cwd)',
      '    sys.argv, sys.stdout, sys.path = _argv, _out, _path',
      '    time.sleep = _sleep',
      '    for _m in ("replay_mcp_server", "soc_triage_agent",',
      '               "hunt_service_accounts", "anomaly_to_detection"):',
      '        sys.modules.pop(_m, None)',
      '_buf.getvalue()'
    ].join('\n');

    return py.runPythonAsync(code);
  }

  /* ------------------------------------------------------------------ *
   * Player — line-by-line playback with authored pause points
   * ------------------------------------------------------------------ */

  /* Where playback stops. "beats" is the default - the moments the demos
   * themselves mark. "steps" also stops on each numbered step, tool call and
   * check result, for walking a room through line by line. */
  function pauseMode() {
    var el = document.getElementById('opt-pause');
    return el ? el.value : 'beats';
  }

  /* Pause AFTER a line the speaker should talk about. */
  function pauseAfter(plain) {
    var mode = pauseMode();
    if (mode === 'off') return false;
    if (/STAGE NOTE:/.test(plain)) return true;
    if (mode !== 'steps') return false;

    return /^\s*\[\s*(PASS|FAIL|ok|SKIP|WARN)\s*\]/i.test(plain) ||   // harness results
           /^\s*\[(yes|no)\s*\]/i.test(plain) ||                       // benign checks
           /^\s*(INJ|HUNT-INJ|LEAK|BENIGN)-\d+/.test(plain) ||          // scorecard rows
           /^\s{2,}\[tool\]/.test(plain);                              // agent tool calls
  }

  /* Pause BEFORE a line that opens a new section, so you can set it up. */
  function pauseBefore(plain) {
    var mode = pauseMode();
    if (mode === 'off') return false;

    if (/^\s*(STAGE|STEP)\s+\d+\/\d+/.test(plain) ||
        /REQUIRES HUMAN APPROVAL/.test(plain) ||
        /^\s*VERDICT:/.test(plain)) return true;
    if (mode !== 'steps') return false;

    return /^\s*\d+\.\s+[A-Z]/.test(plain) ||        // "4. Seed known bad"
           /^(HUNTER|ANALYST)\s+>/.test(plain) ||       // the human's next prompt
           /^\s*###\s/.test(plain);
  }

  /* What we actually stopped on, for the footer. "stage note" for everything
   * was misleading once step mode started pausing on results and tool calls. */
  function labelAfter(plain) {
    if (/STAGE NOTE:/.test(plain)) return 'stage note  ·  talk here';
    var t = plain.match(/^\s*\[\s*(PASS|FAIL|ok|SKIP|WARN)\s*\]\s*(.{0,52})/i);
    if (t) return t[1].toUpperCase().trim() + '  ·  ' + t[2].trim();
    var b = plain.match(/^\s*\[(yes|no)\s*\]\s*(.{0,52})/i);
    if (b) return 'benign check (' + b[1].trim() + ')  ·  ' + b[2].trim();
    var s2 = plain.match(/^\s*((?:INJ|HUNT-INJ|LEAK|BENIGN)-\d+)\s+(.{0,40})/);
    if (s2) return s2[1] + '  ·  ' + s2[2].trim();
    var tool = plain.match(/\[tool\]\s*(\w+)/);
    if (tool) return 'tool call  ·  ' + tool[1];
    return 'step';
  }

  function labelFor(plain) {
    var m = plain.match(/^\s*((?:STAGE|STEP)\s+\d+\/\d+\s+[A-Z][^\n]*)/);
    if (m) return 'next: ' + m[1].trim().slice(0, 54);
    if (/REQUIRES HUMAN APPROVAL/.test(plain)) return 'next: the approval gate';
    if (/^\s*VERDICT:/.test(plain)) return 'next: the verdict';
    return 'stage note';
  }

  function play(text, mode) {
    var term = document.getElementById('run-term');
    var status = document.getElementById('run-status');
    var animate = document.getElementById('opt-animate').checked;

    if (state.player) state.player.stop();
    term.innerHTML = '';

    var lines = text.replace(/\r\n/g, '\n').split('\n');
    var ansiState = { classes: [] };
    var i = 0;
    var stopped = false;
    var timer = null;
    var paused = false;
    // Index we have already paused *before*. Without this, resuming re-checks
    // the same line and pauses again, forever.
    var clearedAt = -1;

    function appendLine(raw) {
      var html = Ansi.toHtml(raw, ansiState);
      var node = document.createElement('span');
      node.innerHTML = html + '\n';
      term.appendChild(node);
      term.scrollTop = term.scrollHeight;
    }

    function finish() {
      stopped = true;
      var cursor = term.querySelector('.cursor');
      if (cursor) cursor.remove();
      status.innerHTML = (mode === 'live'
        ? '<span class="a-green">✓ ran in this tab</span>'
        : '<span class="a-yellow">recorded output</span>') +
        ' · ' + lines.length + ' lines';
    }

    function pauseHere(why) {
      paused = true;
      status.innerHTML = '<span class="a-yellow">⏸ paused</span> — ' + esc(why) +
                         ' · <b>space</b> to continue, <b>→</b> to skip to end';
    }

    function resume() {
      if (stopped) return;
      paused = false;
      budget = 0;
      lastTick = 0;
      status.textContent = mode === 'live' ? 'running…' : 'playing…';
      step();
    }

    /* Emit one line. Returns 'ok', 'pause' or 'end'. */
    function emit() {
      if (i >= lines.length) return 'end';

      var raw = lines[i];
      var plain = Ansi.strip(raw);

      // Stop before a line that opens a new section, so the speaker can set
      // it up. clearedAt stops us re-pausing on the same line after resuming.
      if (i > 0 && i !== clearedAt && pauseBefore(plain)) {
        clearedAt = i;
        pauseHere(labelFor(plain));
        return 'pause';
      }

      appendLine(raw);
      i++;

      if (pauseAfter(plain)) {
        pauseHere(labelAfter(plain));
        return 'pause';
      }
      return 'ok';
    }

    /* One tick emits however many lines the elapsed wall-clock time earns.
     * Doing it this way rather than one timeout per line means a throttled
     * background tab catches up in bursts instead of stalling. */
    var PER_LINE_MS = 15;
    var budget = 0;
    var lastTick = 0;

    function step() {
      if (stopped || paused) return;

      var now = performance.now();
      if (!animate) {
        budget = lines.length;             // no pacing; pause points still apply
      } else {
        if (lastTick === 0) lastTick = now;
        budget += (now - lastTick) / PER_LINE_MS;
        lastTick = now;
        if (budget < 1) budget = 1;        // always make progress
      }

      var guard = 0;
      while (budget >= 1 && guard < 4000) {
        var r = emit();
        if (r === 'pause') { lastTick = 0; return; }
        if (r === 'end') { finish(); return; }
        budget -= 1;
        guard += 1;
      }

      timer = setTimeout(step, 16);
    }

    state.player = {
      stop: function () { stopped = true; clearTimeout(timer); },
      toggle: function () {
        if (stopped) return;
        if (paused) resume();
        else { paused = true; clearTimeout(timer); pauseHere('manual'); }
      },
      skip: function () {
        if (stopped) return;
        clearTimeout(timer);
        paused = false;
        while (i < lines.length) { appendLine(lines[i]); i++; }
        finish();
      },
      isPaused: function () { return paused; },
      resume: resume
    };

    status.textContent = mode === 'live' ? 'running…' : 'playing…';
    step();
  }

  /* ------------------------------------------------------------------ *
   * Keys
   * ------------------------------------------------------------------ */

  function onKey(e) {
    var open = !document.getElementById('runner').hidden;
    if (!open) return;

    if (e.key === 'Escape') { closeRunner(); return; }
    if (!document.getElementById('run-video-wrap').hidden) return;  // video has its own controls
    if (!state.player) return;

    if (e.key === ' ' || e.key === 'Spacebar') {
      e.preventDefault();
      state.player.toggle();
    } else if (e.key === 'ArrowRight' || e.key === 'End') {
      e.preventDefault();
      state.player.skip();
    } else if (e.key === 'r' || e.key === 'R') {
      e.preventDefault();
      start(state.variantIndex);
    } else if (e.key >= '1' && e.key <= '9' && state.demo && state.demo.variants) {
      var n = parseInt(e.key, 10) - 1;
      if (n < state.demo.variants.length) { e.preventDefault(); start(n); }
    }
  }

  function copyOutput() {
    var text = document.getElementById('run-term').innerText;
    navigator.clipboard.writeText(text).then(function () {
      var b = document.getElementById('run-copy');
      var old = b.textContent;
      b.textContent = 'Copied';
      setTimeout(function () { b.textContent = old; }, 1200);
    });
  }

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
})();
