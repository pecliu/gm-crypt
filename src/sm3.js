class SM3 {
  constructor() {
    this.reg = new Array(8);
    this.chunk = [];
    this.size = 0;

    this.reset();
  }

  reset() {
    this.reg[0] = 0x7380166f;
    this.reg[1] = 0x4914b2b9;
    this.reg[2] = 0x172442d7;
    this.reg[3] = 0xda8a0600;
    this.reg[4] = 0xa96f30bc;
    this.reg[5] = 0x163138aa;
    this.reg[6] = 0xe38dee4d;
    this.reg[7] = 0xb0fb0e4e;
    this.chunk = [];
    this.size = 0;
  }

  strToBytes(s) {
    var ch, st, re = [];
    for (var i = 0; i < s.length; i++) {
      ch = s.charCodeAt(i);
      st = [];
      do {
        st.push(ch & 0xFF);
        ch = ch >> 8;
      }
      while (ch);
      re = re.concat(st.reverse());
    }
    return re;
  }

  write(msg) {
    var m = (typeof msg === 'string') ? this.strToBytes(msg) : msg;
    this.size += m.length;
    var i = 64 - this.chunk.length;
    if (m.length < i) {
      this.chunk = this.chunk.concat(m);
      return;
    }

    this.chunk = this.chunk.concat(m.slice(0, i));
    while (this.chunk.length >= 64) {
      this.compress(this.chunk);
      if (i < m.length) {
        this.chunk = m.slice(i, Math.min(i + 64, m.length));
      } else {
        this.chunk = [];
      }
      i += 64;
    }
  }

  sum(msg, enc) {
    if (msg) {
      this.reset();
      this.write(msg);
    }

    this.fill();
    for (var i = 0; i < this.chunk.length; i += 64) {
      this.compress(this.chunk.slice(i, i + 64));
    }

    var digest = null;
    if (enc == 'hex') {
      digest = '';
      for (var i = 0; i < 8; i++) {
        digest += this.reg[i].toString(16);
      }
    } else {
      var digest = new Array(32);
      for (var i = 0; i < 8; i++) {
        var h;
        h = this.reg[i];
        digest[i * 4 + 3] = (h & 0xff) >>> 0;
        h >>>= 8;
        digest[i * 4 + 2] = (h & 0xff) >>> 0;
        h >>>= 8;
        digest[i * 4 + 1] = (h & 0xff) >>> 0;
        h >>>= 8;
        digest[i * 4] = (h & 0xff) >>> 0;
      }
    }

    this.reset();
    return digest;
  }

  compress(m) {
    if (m < 64) {
      console.error('compress error: not enough data');
      return;
    }
    var w = this.expand(m);
    var r = this.reg.slice(0);
    for (var j = 0; j < 64; j++) {
      var ss1 = this.rotl(r[0], 12) + r[4] + this.rotl(this.t(j), j);
      ss1 = (ss1 & 0xffffffff) >>> 0;
      ss1 = this.rotl(ss1, 7);

      var ss2 = (ss1 ^ this.rotl(r[0], 12)) >>> 0;
      var tt1 = this.ff(j, r[0], r[1], r[2]);
      tt1 = tt1 + r[3] + ss2 + w[j + 68];
      tt1 = (tt1 & 0xffffffff) >>> 0;
      var tt2 = this.gg(j, r[4], r[5], r[6]);
      tt2 = tt2 + r[7] + ss1 + w[j];
      tt2 = (tt2 & 0xffffffff) >>> 0;
      r[3] = r[2];
      r[2] = this.rotl(r[1], 9);
      r[1] = r[0];
      r[0] = tt1;
      r[7] = r[6];
      r[6] = this.rotl(r[5], 19);
      r[5] = r[4];
      r[4] = (tt2 ^ this.rotl(tt2, 9) ^ this.rotl(tt2, 17)) >>> 0;
    }

    for (var i = 0; i < 8; i++) {
      this.reg[i] = (this.reg[i] ^ r[i]) >>> 0;
    }
  }

  fill() {
    var l = this.size * 8;
    var len = this.chunk.push(0x80) % 64;
    if (64 - len < 8) {
      len -= 64;
    }
    for (; len < 56; len++) {
      this.chunk.push(0x00);
    }

    for (var i = 0; i < 4; i++) {
      var hi = Math.floor(l / 0x100000000);
      this.chunk.push((hi >>> ((3 - i) * 8)) & 0xff);
    }
    for (var i = 0; i < 4; i++) {
      this.chunk.push((l >>> ((3 - i) * 8)) & 0xff);
    }
  }

  expand(b) {
    var w = new Array(132);
    for (var i = 0; i < 16; i++) {
      w[i] = b[i * 4] << 24;
      w[i] |= b[i * 4 + 1] << 16;
      w[i] |= b[i * 4 + 2] << 8;
      w[i] |= b[i * 4 + 3];
      w[i] >>>= 0;
    }

    for (var j = 16; j < 68; j++) {
      var x;
      x = w[j - 16] ^ w[j - 9] ^ this.rotl(w[j - 3], 15);
      x = x ^ this.rotl(x, 15) ^ this.rotl(x, 23);
      w[j] = (x ^ this.rotl(w[j - 13], 7) ^ w[j - 6]) >>> 0;
    }

    for (var j = 0; j < 64; j++) {
      w[j + 68] = (w[j] ^ w[j + 4]) >>> 0;
    }

    return w;
  }

  rotl(x, n) {
    n %= 32;
    return ((x << n) | (x >>> (32 - n))) >>> 0;
  }

  t(j) {
    if (0 <= j && j < 16) {
      return 0x79cc4519;
    } else if (16 <= j && j < 64) {
      return 0x7a879d8a;
    } else {
      console.error("invalid j for constant Tj");
    }
  }

  ff(j, x, y, z) {
    if (0 <= j && j < 16) {
      return (x ^ y ^ z) >>> 0;
    } else if (16 <= j && j < 64) {
      return ((x & y) | (x & z) | (y & z)) >>> 0;
    } else {
      console.error("invalid j for bool function FF");
      return 0;
    }
  }

  gg(j, x, y, z) {
    if (0 <= j && j < 16) {
      return (x ^ y ^ z) >>> 0;
    } else if (16 <= j && j < 64) {
      return ((x & y) | (~x & z)) >>> 0;
    } else {
      console.error("invalid j for bool function GG");
      return 0;
    }
  }

  toArray(s, f) {
    var a = [];
    for (var i = 0; i < s.length; i++) {
      var t = s[i];
      if (f) {
        t = f(t);
      }
      a.push(t);
    }
    return a;
  }

  sm3Digest(msg) {
    var _sm3 = new SM3();
    var digest = _sm3.sum(msg);
    var hashHex = _sm3.toArray(digest, function (byte) {
      return ("0" + (byte & 0xFF).toString(16)).slice(-2);
    }).join('');
    return hashHex;
  }
}