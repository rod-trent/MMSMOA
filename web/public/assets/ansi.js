/* ansi.js — minimal ANSI SGR to HTML.
 *
 * The demos emit exactly the codes in `MAP` below (reset, dim, bold, and the
 * eight basic foreground colours). This is not a general terminal emulator and
 * does not try to be; anything it does not recognise is dropped rather than
 * printed as garbage.
 */
(function (global) {
  'use strict';

  var MAP = {
    1: 'a-bold',
    2: 'a-dim',
    31: 'a-red',
    32: 'a-green',
    33: 'a-yellow',
    34: 'a-blue',
    35: 'a-magenta',
    36: 'a-cyan',
    37: 'a-white'
  };

  var SGR = /\[([0-9;]*)m/g;

  function esc(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  /* Convert a chunk of ANSI text to HTML. `state` carries open classes across
   * calls so a colour opened on one line survives into the next. */
  function toHtml(text, state) {
    state = state || { classes: [] };
    var out = '';
    var last = 0;
    var m;

    function open() {
      return state.classes.length
        ? '<span class="' + state.classes.join(' ') + '">'
        : '';
    }
    function close() {
      return state.classes.length ? '</span>' : '';
    }

    SGR.lastIndex = 0;
    while ((m = SGR.exec(text)) !== null) {
      var chunk = text.slice(last, m.index);
      if (chunk) out += open() + esc(chunk) + close();
      last = m.index + m[0].length;

      var codes = m[1] === '' ? [0] : m[1].split(';').map(Number);
      for (var i = 0; i < codes.length; i++) {
        var c = codes[i];
        if (c === 0) {
          state.classes = [];
        } else if (MAP[c]) {
          // Only one colour at a time; bold/dim may stack with a colour.
          if (c >= 30) state.classes = state.classes.filter(function (k) {
            return k === 'a-bold' || k === 'a-dim';
          });
          if (state.classes.indexOf(MAP[c]) === -1) state.classes.push(MAP[c]);
        }
      }
    }

    var tail = text.slice(last);
    if (tail) out += open() + esc(tail) + close();
    return out;
  }

  function strip(text) {
    return text.replace(SGR, '');
  }

  global.Ansi = { toHtml: toHtml, strip: strip };
})(window);
