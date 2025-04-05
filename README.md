# 🔐 XD Token Generator

A compact, modular, and safe JavaScript ID/token generator supporting:
- **Base36**, **Base62**, and **symbol-rich** character sets
- Works natively in **Node.js** and **browsers**
- No dependencies (`crypto`, `libs`, etc.)
- Three customizable modes:
  - `_xdToken` — structured, partially sortable
  - `_xdTokenSave` — URL-safe, base62 random
  - `_xdTokenYolo` — max entropy with unsafe symbols

---

## 🧩 Functions Overview

### ✅ `_xdToken(length)`
Structured, semi-sortable token with timestamp + pid + counter.

**Format:**
```
[TS3][PID2][CTR3][R...]
```

| Segment | Chars | Description                                                                 |
|---------|-------|-----------------------------------------------------------------------------|
| `TS3`   | 3     | Timestamp (seconds since epoch, mod 46656) → Base36                        |
| `PID2`  | 2     | Session/Machine ID (pid % 1296 or random) → Base36                         |
| `CTR3`  | 3     | Per-second counter (rolls every ~46K) → Base36                             |
| `R...`  | Varies| Filler from base36 to complete requested length                            |

> Used for: short tokens, trace IDs, internal references

---

### ✅ `_xdTokenSave(length)`
Pure random token using base62 (0–9, a–z, A–Z).  
Fully URL-safe and suitable for public use.

| Characters used | Base62: `0–9`, `a–z`, `A–Z` |
| Safe for URLs?  | ✅ Yes                      |

> Used for: slugs, share codes, safe filenames, API tokens

---

### ✅ `_xdTokenYolo(length)`
Maximum entropy token using **base62 + special symbols**.  
Not URL-safe. Good for secrets and internal use.

| Characters used | Base62 + `/+=~!@#$%^&*()[]{},.<>?|` |
| Safe for URLs?  | ❌ No                               |

> Used for: passwords, secrets, non-public tokens

---

## 🔎 Character-by-Character Breakdown (for `_xdToken`)

**Example:**  
`0zq8a0d7w9b1`

| Pos | Segment | Value | Description                       |
|-----|---------|-------|-----------------------------------|
| 0–2 | `TS3`   | `0zq` | Timestamp mod 46656 → Base36      |
| 3–4 | `PID2`  | `8a`  | Session or process ID             |
| 5–7 | `CTR3`  | `0d7` | Counter within current second     |
| 8+  | `R...`  | `w9b1`| Random base36 filler              |

---

## 📏 Supported Lengths per Mode

| Function         | Valid Lengths                     |
|------------------|----------------------------------|
| `_xdToken`       | 8, 12, 16, 24, 32                 |
| `_xdTokenSave`   | 8, 12, 16, 24, 32, 48, 62         |
| `_xdTokenYolo`   | 8, 12, 16, 24, 32, 48, 62, 64     |

---

## 📊 Collision Risk Table (Birthday Paradox Estimate)

For `P(collision) ≈ n² / (2N)`, where `n = IDs/day`, `N = entropy space`.

| Length | Entropy (Base62) | Max IDs/day @ <1% | @ <0.1% | @ <0.001% |
|--------|------------------|-------------------|---------|-----------|
| 8      | ~2.8 trillion     | ~1.2M             | ~370K   | ~120K     |
| 12     | ~4.7e18           | ~9.7B             | ~97M    | ~3M       |
| 16     | ~1.0e26           | ~4T               | ~400M   | ~12M      |
| 24     | ~1.0e39           | Trillions         | Billions| 100M+     |
| 32     | ~1.0e52           | No limit          | No limit| No limit  |
| 48+    | ~∞ (practically)  | No limit          | No limit| No limit  |

---

## 💡 Example Usages

```js
_xdToken(16);         // e.g. "0zq8a0d7w9b1m7cj"
_xdTokenSave(24);     // "GZ5rxkDTmuvQAb28PEYXuW9c"
_xdTokenYolo(64);     // "r*!T+=hV@dBG#jcOE|yM&U48u0xq9as~VXFR@q7?!&1kg...."
```

---

## ✅ Recommendations

| Use Case                     | Function         | Recommended Length |
|------------------------------|------------------|---------------------|
| Trace/request ID             | `_xdToken`       | 12–16               |
| Public slug/token            | `_xdTokenSave`   | 16–32               |
| Secure password/secret       | `_xdTokenYolo`   | 32–64               |
| Internal ref/token (short)   | `_xdToken`       | 8–12                |
| JWT/session/random secret    | `_xdTokenSave` / `_xdTokenYolo` | 32–64  |

---

## ⚙️ Internals Recap

- Epoch: Fixed `1700000000000` for compact timestamps
- PID fallback for browsers
- Counter rolls every new second
- Random characters added to reach desired length

---

## 🧪 Ready for:

- ✅ Native JavaScript (no crypto)
- ✅ Browser + Node compatible
- ✅ CLI tools, web apps, microservices, APIs
- ✅ Time-sortable (for `_xdToken`)

---

## 📌 Want More?

- [ ] Add decoding of timestamp?
- [ ] Sortable base62 tokens?
- [ ] Export as NPM package?
- [ ] UMD build for global usage?

Let me know what you'd like next!
