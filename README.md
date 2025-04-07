# xdTok - Enhanced Hybrid Token Generator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/Version-1.0.1-blue.svg)]()

A lightweight, dependency-free JavaScript token generator for Node.js and browsers. It produces **base36 encoded**, chronologically **sortable** tokens of variable length (**6-96 characters**), optimized for uniqueness and high throughput. Includes a UMD wrapper for maximum compatibility.

Ideal for generating unique IDs for database records, logs, events, distributed tracing, and other scenarios requiring high-performance, largely unique identifiers.

## Key Features

-   **Hybrid Structure:** Combines timestamp, instance identifier, and a monotonic counter for robustness against collisions.
-   **Millisecond Precision:** Uses `Date.now()` providing fine-grained time resolution.
-   **Sortable:** Tokens are naturally sortable lexicographically by time due to the fixed timestamp prefix.
-   **Configurable Length:** Generate tokens from 6 to 96 characters long (default: 16).
-   **Instance Aware:** Attempts to use `process.pid` in Node.js for better instance differentiation. Uses randomness in browsers.
-   **High Throughput:** Counter allows for up to `36^3 = 46,656` unique tokens *per millisecond, per generator instance*.
-   **Secure Randomness Preferred:** Uses `window.crypto.getRandomValues` in browsers when available. Falls back to `Math.random`.
-   **Zero Dependencies:** Plain JavaScript.
-   **Universal Compatibility (UMD):** Works seamlessly in Node.js (CommonJS), browsers (global `window.xdTok`), and AMD module loaders (like RequireJS).
-   **Diagnostics:** Provides console warnings for clock rollbacks or counter overflows.

## Token Structure

An `xdTok` token follows this structure:

`[Timestamp (9 chars)][Instance ID (4 chars)][Counter (3 chars)][Optional Random Suffix (...)]`

-   **Timestamp (`TS9`):** 9 base36 chars (milliseconds since Unix epoch). *Ensures sortability.*
-   **Instance ID (`INST4`):** 4 base36 chars (PID+random in Node.js, random in browser). *Helps differentiate sources.*
-   **Counter (`CTR3`):** 3 base36 chars (000-zzz, 0-46655). Increments per millisecond/instance. *Ensures uniqueness during bursts.*
-   **Random Suffix (`R...`):** Variable length base36 chars. Added if requested length > 16. *Adds entropy.*

**Total fixed length = 9 + 4 + 3 = 16 characters.**

## Installation

**1. Direct Download / Copy-Paste:**

*   **Development:** Copy `src/xdTok.js` into your project.
*   **Production:** Copy `dist/xdTok.min.js` into your project.

**2. Via Git Clone:**

```bash
git clone https://github.com/[YOUR_USERNAME]/xdTok.git
cd xdTok
# Use files from src/ or dist/
```
*(Replace `[YOUR_USERNAME]` with your GitHub username or the appropriate repository URL)*

**3. Via npm (if published):**

```bash
npm install xdtok # Or your chosen package name
# or
yarn add xdtok
# or
pnpm add xdtok
```

## Usage

Thanks to the UMD wrapper, `xdTok` works easily in different environments:

**Node.js (CommonJS):**

```javascript
// If installed via npm:
// const xdTok = require('xdtok');

// If using the source/dist file directly:
const xdTok = require('./src/xdTok.js'); // or './dist/xdTok.min.js'

console.log("Default (16):", xdTok());
console.log("Short (10):", xdTok(10));
console.log("Long (24):", xdTok(24));

try {
  xdTok(5); // Invalid length
} catch (e) {
  console.error("Error:", e.message);
}
```

**Browser (Global Variable):**

```html
<!DOCTYPE html>
<html>
<head>
  <title>xdTok Example</title>
  <!-- Include the script (use .min.js for production) -->
  <script src="dist/xdTok.min.js"></script>
  <!-- Now window.xdTok is available -->
</head>
<body>
  <h1>Check the Console</h1>
  <script>
    console.log("Browser Default (16):", xdTok());
    console.log("Browser Long (30):", xdTok(30));
    console.log("Browser Minimum (8):", xdTok(8));
  </script>
</body>
</html>
```

**AMD (e.g., RequireJS):**

```javascript
requirejs.config({
  paths: {
    'xdTok': 'path/to/dist/xdTok.min' // Adjust path, omit .js
  }
});

requirejs(['xdTok'], function(xdTok) {
  console.log("AMD Default (16):", xdTok());
  console.log("AMD Long (20):", xdTok(20));
});
```

## Diagnostics / Edge Cases

`xdTok` logs warnings (`console.warn`) for:

1.  **Clock Rollback:** If `Date.now()` returns a time earlier than the last call. Strict sortability might be affected.
2.  **Counter Overflow:** If more than 46,656 IDs are generated in the same millisecond by the same instance. The counter resets.

See `doc.md` for a detailed explanation of these cases.

## License

[MIT License](LICENSE) - Copyright (c) 2024 Jakub Śledzikowski <jsledzikowski.web@gmail.com>
*(See the LICENSE file for full license text)*
