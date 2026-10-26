/* Hash Lab — SHA family via SubtleCrypto, MD5 implemented below (SubtleCrypto has no MD5). */
(function () {
  "use strict";
  var $ = S3.$, $$ = S3.$$;
  var MAX_FILE = 512 * 1024 * 1024; // shortcut: whole file in memory (SubtleCrypto has no streaming API); chunk MD5 + use a WASM SHA if bigger files are needed
  var ALGS = ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"];

  // ---------- MD5 (RFC 1321) ----------
  var MD5_S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  var MD5_K = new Int32Array(64);
  for (var i = 0; i < 64; i++) MD5_K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) | 0;

  function md5(bytes) {
    var h = [0x67452301, 0xefcdab89 | 0, 0x98badcfe | 0, 0x10325476];
    var M = new Int32Array(16);
    function block(dv, off) {
      for (var j = 0; j < 16; j++) M[j] = dv.getInt32(off + j * 4, true);
      var A = h[0], B = h[1], C = h[2], D = h[3], F, g, t;
      for (var k = 0; k < 64; k++) {
        var r = k >> 4;
        if (r === 0) { F = (B & C) | (~B & D); g = k; }
        else if (r === 1) { F = (D & B) | (~D & C); g = (5 * k + 1) & 15; }
        else if (r === 2) { F = B ^ C ^ D; g = (3 * k + 5) & 15; }
        else { F = C ^ (B | ~D); g = (7 * k) & 15; }
        F = (F + A + MD5_K[k] + M[g]) | 0;
        A = D; D = C; C = B;
        t = MD5_S[(r << 2) | (k & 3)];
        B = (B + ((F << t) | (F >>> (32 - t)))) | 0;
      }
      h[0] = (h[0] + A) | 0; h[1] = (h[1] + B) | 0; h[2] = (h[2] + C) | 0; h[3] = (h[3] + D) | 0;
    }
    var n = bytes.length, full = n - (n % 64);
    var dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    for (var off = 0; off < full; off += 64) block(dv, off);
    // Padding only touches the last partial block, so the input is never copied.
    var tailLen = (n % 64) < 56 ? 64 : 128, tail = new Uint8Array(tailLen);
    tail.set(bytes.subarray(full)); tail[n - full] = 0x80;
    var tv = new DataView(tail.buffer);
    tv.setUint32(tailLen - 8, (n % 0x20000000) * 8, true);
    tv.setUint32(tailLen - 4, Math.floor(n / 0x20000000), true);
    for (var o = 0; o < tailLen; o += 64) block(tv, o);
    var out = new Uint8Array(16), ov = new DataView(out.buffer);
    for (var q = 0; q < 4; q++) ov.setInt32(q * 4, h[q], true);
    return out;
  }

  // ---------- encoding ----------
  function hex(b) { var s = ""; for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? "0" : "") + b[i].toString(16); return s; }
  function b64(b) { var s = ""; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); }
  function fmtOut(b, f) { return f === "b64" ? b64(b) : f === "HEX" ? hex(b).toUpperCase() : hex(b); }

  function digest(alg, bytes) {
    if (alg === "MD5") return Promise.resolve(md5(bytes));
    return crypto.subtle.digest(alg, bytes).then(function (d) { return new Uint8Array(d); });
  }
  function hmac(alg, keyText, bytes) {
    return crypto.subtle.importKey("raw", new TextEncoder().encode(keyText), { name: "HMAC", hash: alg }, false, ["sign"])
      .then(function (k) { return crypto.subtle.sign("HMAC", k, bytes); })
      .then(function (d) { return new Uint8Array(d); });
  }
  function hashAll(bytes, keyText, hmacAlg) {
    var jobs = ALGS.map(function (a) { return digest(a, bytes).then(function (d) { return { name: a, bytes: d }; }); });
    if (keyText) jobs.push(hmac(hmacAlg, keyText, bytes).then(function (d) { return { name: "HMAC-" + hmacAlg.replace("-", ""), bytes: d }; }));
    return Promise.all(jobs);
  }

  // Normalises "SHA256 (file) = ABC…", "ab:cd:ef", spaces, and Base64.
  function cleanExpected(s) {
    s = String(s).trim();
    var m = /([A-Fa-f0-9:\s]{32,})$/.exec(s);
    var hx = (m ? m[1] : s).replace(/[\s:]/g, "");
    if (/^[A-Fa-f0-9]+$/.test(hx) && hx.length % 2 === 0) return { hex: hx.toLowerCase() };
    return { b64: s.replace(/\s/g, "").replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "") };
  }
  function findMatch(expected, results) {
    var e = cleanExpected(expected);
    for (var i = 0; i < results.length; i++) {
      var r = results[i];
      if (e.hex && hex(r.bytes) === e.hex) return r.name;
      if (e.b64 && b64(r.bytes).replace(/=+$/, "") === e.b64) return r.name;
    }
    return null;
  }

  // ---------- UI ----------
  var state = { src: "text", fmt: S3.store("hash.fmt") || "hex", fileBytes: null, results: [], token: 0 };
  var text = $("#text"), key = $("#key"), alg = $("#hmacAlg");
  alg.value = S3.store("hash.hmacAlg") || "SHA-256";

  function seg(el, value, onPick) {
    $$("button", el).forEach(function (b) {
      b.setAttribute("aria-pressed", String(b.dataset.v === value));
      b.addEventListener("click", function () {
        $$("button", el).forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); });
        onPick(b.dataset.v);
      });
    });
  }

  function currentBytes() { return state.src === "file" ? state.fileBytes : new TextEncoder().encode(text.value); }

  function draw() {
    var box = $("#results"), match = $("#expect").value.trim() ? findMatch($("#expect").value, state.results) : null;
    box.innerHTML = "";
    if (!state.results.length) {
      box.appendChild(S3.h("div", { "class": "empty" }, [S3.h("b", { text: "Drop a file to hash it" }), "MD5, SHA-1, SHA-256, SHA-384 and SHA-512 appear here."]));
    }
    state.results.forEach(function (r) {
      var v = fmtOut(r.bytes, state.fmt);
      var row = S3.h("div", { "class": "hl-row" + (match === r.name ? " is-match" : "") }, [
        S3.h("div", { "class": "hl-name" }, [r.name, S3.h("span", { "class": "faint", text: r.bytes.length * 8 + " bit" })]),
        S3.h("code", { "class": "hl-val", text: v }),
        S3.h("button", { "class": "btn small icon", title: "Copy " + r.name, "aria-label": "Copy " + r.name, html: '<svg class="i"><use href="#i-copy"/></svg>',
          onclick: function () { S3.copy(v, r.name + " copied"); S3.done(); } })
      ]);
      box.appendChild(row);
    });
    var verdict = $("#verdict");
    if (!$("#expect").value.trim()) { verdict.className = "chip"; verdict.textContent = "Paste a hash to verify"; }
    else if (!state.results.length) { verdict.className = "chip"; verdict.textContent = "Nothing hashed yet"; }
    else if (match) { verdict.className = "chip ok"; verdict.textContent = "✓ Match — " + match; }
    else { verdict.className = "chip bad"; verdict.textContent = "✗ No match with any hash above"; }
  }

  function run() {
    var bytes = currentBytes(), my = ++state.token;
    if (state.src === "text") $("#textInfo").textContent = bytes.length.toLocaleString() + " bytes (UTF-8)";
    if (!bytes) { state.results = []; draw(); return; }
    hashAll(bytes, key.value, alg.value).then(function (res) {
      if (my !== state.token) return; // a newer keystroke won
      state.results = res; draw();
    }, function (e) { S3.toast("Hashing failed: " + e.message, "error"); });
  }
  var runSoon = S3.debounce(run, 120);

  seg($("#src"), "text", function (v) {
    state.src = v; $("#textBox").hidden = v !== "text"; $("#fileBox").hidden = v !== "file"; run();
  });
  seg($("#fmt"), state.fmt, function (v) { state.fmt = v; S3.store("hash.fmt", v); draw(); });
  text.addEventListener("input", runSoon);
  key.addEventListener("input", runSoon);
  alg.addEventListener("change", function () { S3.store("hash.hmacAlg", alg.value); run(); });
  $("#expect").addEventListener("input", draw);
  $("#clear").addEventListener("click", function () {
    text.value = ""; key.value = ""; $("#expect").value = ""; state.fileBytes = null; $("#fileInfo").hidden = true; run();
  });

  S3.drop($("#drop"), function (files) {
    var f = files[0]; if (!f) return;
    if (f.size > MAX_FILE) { S3.toast("Files over 512 MB are too big to hash in a browser tab", "error"); return; }
    $("#fileName").textContent = f.name; $("#fileSize").textContent = S3.fmtBytes(f.size) + " · hashing…"; $("#fileInfo").hidden = false;
    S3.readFile(f).then(function (buf) {
      state.fileBytes = new Uint8Array(buf);
      var t0 = performance.now();
      hashAll(state.fileBytes, key.value, alg.value).then(function (res) {
        state.results = res; draw(); S3.done();
        $("#fileSize").textContent = S3.fmtBytes(f.size) + " · hashed in " + Math.round(performance.now() - t0) + " ms";
      });
    });
  });

  function allText() {
    return state.results.map(function (r) { return r.name + ": " + fmtOut(r.bytes, state.fmt); }).join("\n");
  }
  $("#copyAll").addEventListener("click", function () { if (state.results.length) { S3.copy(allText(), "All hashes copied"); S3.done(); } });
  $("#saveAll").addEventListener("click", function () { if (state.results.length) { S3.download(allText() + "\n", "hashes.txt", "text/plain"); S3.done(); } });

  run();

  window.S3_DEMO = function () {
    text.value = "The quick brown fox jumps over the lazy dog";
    $("#expect").value = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
    run();
  };

  window.S3_SELFTEST = async function () {
    var enc = function (s) { return new TextEncoder().encode(s); };
    // RFC 1321 appendix A.5 + common vectors (incl. multi-block and the 56-byte padding edge)
    var md = {
      "": "d41d8cd98f00b204e9800998ecf8427e",
      "abc": "900150983cd24fb0d6963f7d28e17f72",
      "message digest": "f96b697d7cb7938d525a2f31aaf161d0",
      "The quick brown fox jumps over the lazy dog": "9e107d9d372bb6826bd81d3542a419d6",
      "12345678901234567890123456789012345678901234567890123456789012345678901234567890": "57edf4a22be3c955ac49da2e2107b67a"
    };
    for (var k in md) if (hex(md5(enc(k))) !== md[k]) return "md5 " + k;
    if (hex(md5(enc("a".repeat(55)))) !== "ef1772b6dff9a122358552954ad0df65" || hex(md5(enc("a".repeat(56)))) !== "3b0c8ac703f828b04c6c197006d17218" ||
        hex(md5(enc("a".repeat(64)))) !== "014842d480b571495a4a0363793f7367") return "md5 padding edges";
    // FIPS 180 "abc" vectors
    var sha = {
      "SHA-1": "a9993e364706816aba3e25717850c26c9cd0d89d",
      "SHA-256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "SHA-512": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    };
    for (var a in sha) if (hex(await digest(a, enc("abc"))) !== sha[a]) return a;
    // RFC 4231 test case 2
    if (hex(await hmac("SHA-256", "Jefe", enc("what do ya want for nothing?"))) !== "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") return "hmac";
    var res = await hashAll(enc("abc"), "", "SHA-256");
    if (findMatch("SHA256 (x.iso) = BA7816BF 8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", res) !== "SHA-256") return "compare hex";
    if (findMatch(b64(md5(enc("abc"))), res) !== "MD5") return "compare b64";
    if (findMatch("deadbeef", res) !== null) return "compare false positive";
    return true;
  };
})();
