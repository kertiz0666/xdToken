
# xdTok - Detailed Documentation

This document provides a deeper dive into the design, rationale, and nuances of the `xdTok` generator, complementing the main `README.md`. Version reflects v1.0.1 including the UMD wrapper.

## 1. Design Philosophy

`xdTok` aims to provide a practical balance between several desirable properties for generated IDs:

-   **Uniqueness:** High probability of uniqueness across time and different generator instances. Achieved through a combination of high-resolution timestamp, instance identifier, and a per-millisecond counter.
-   **Sortability:** Tokens should be roughly sortable by generation time. Achieved by placing the timestamp at the beginning of the token.
-   **Performance:** Generation should be fast and lightweight with zero external dependencies. Achieved using native JavaScript features (`Date.now()`, `Math.random`, `crypto.getRandomValues`).
-   **Configurability:** Allow users to specify the desired token length within reasonable bounds (6-96 characters).
-   **Portability & Compatibility:** Work consistently in Node.js, modern web browsers, and AMD environments thanks to the UMD wrapper.
-   **Simplicity:** Maintain a relatively simple and understandable internal structure.

It draws inspiration from concepts found in identifiers like UUIDs (uniqueness), ULIDs (timestamp + randomness, sortability), and Snowflake IDs (timestamp, worker ID, sequence).

## 2. Rationale for Components

### 2.1. Base36 Encoding

-   **Why Base36?** Uses `0-9` and `a-z` (case-insensitive).
    -   **Compactness:** More compact than Base16 (Hex).
    *   **URL/Filename Friendliness:** Contains only alphanumeric characters, generally safe without special encoding.
    *   **Readability:** Arguably more human-readable than Base64.
    *   **Simplicity:** Native `Number.prototype.toString(36)` support simplifies implementation.

### 2.2. Timestamp (9 Chars - `tsLen`)

-   **Why Milliseconds?** `Date.now()` offers good granularity for most applications.
-   **Why 9 Characters?** `36^9` provides ample space (~1x10^14) to represent milliseconds since the epoch for centuries to come, ensuring the fixed-length prefix remains valid long-term, well beyond the limits of JavaScript's `MAX_SAFE_INTEGER` for timestamps.

### 2.3. Instance ID (4 Chars - `instanceLen`)

-   **Why Include It?** Prevents collisions between different processes/tabs generating IDs simultaneously within the same millisecond.
-   **Why 4 Characters?** `36^4 = 1,679,616` possibilities.
    -   **Node.js:** Mixing `process.pid` (base36) with randomness provides reasonable differentiation. It's not a guaranteed unique worker ID like in Snowflake but significantly reduces collision probability compared to timestamp+counter alone.
    -   **Browser:** Pure randomness (preferably from `window.crypto`) makes simultaneous collisions highly improbable (`1 / 36^4` if crypto is used).
-   **Approach:** The hybrid PID+random (Node) / random (Browser) approach is a pragmatic compromise maximizing differentiation where possible without adding dependencies.

### 2.4. Counter (3 Chars - `counterLen`)

-   **Why Include It?** Handles multiple ID generations within the same millisecond by the *same* generator instance.
-   **Why 3 Characters?** `36^3 = 46,656` unique values (`maxCounter = 46655`). Allows for extremely high burst rates before overflowing. Sufficient for most common application needs.

### 2.5. Optional Random Suffix

-   **Purpose:**
    1.  Allows users to generate longer tokens if required.
    2.  Adds extra entropy, further minimizing the theoretical chance of collision, especially if the instance ID somehow wasn't unique or if counter overflow occurred.

## 3. Collision Probability Analysis

Collisions are statistically extremely rare. A collision requires the exact same string output from two different calls, meaning:

1.  **Same Millisecond:** `tsPart` must match.
2.  **Same Instance ID:** `instancePart` must match. (Probability depends on environment - lower in Node if PIDs differ, `1/36^4` in browser if simultaneous random generation matches).
3.  **Same Counter Value:** `counterPart` must match for that millisecond and instance.
4.  **Same Random Suffix (if length > 16):** The probability decreases exponentially with suffix length.

The dominant factors preventing collisions are the high resolution of the timestamp, the instance ID differentiation, and the high capacity of the counter.

## 4. Edge Case Handling Deep Dive

### 4.1. Clock Rollback (`now < lastTimestamp`)

-   **The Problem:** System time moves backward (NTP, manual changes, VM sync).
-   **`xdTok`'s Strategy (v1.0.1):**
    1.  Logs a `console.warn` indicating the time jump and potential loss of strict monotonicity.
    2.  **Proceeds with generation using the new (earlier) timestamp `now`.**
    3.  **Does NOT update `lastTimestamp` to the earlier time.** The generator "remembers" the highest timestamp seen so far.
    4.  **Does NOT reset the `counter`.** The counter continues from its current value associated with the *previous* `lastTimestamp`.
-   **Implications:**
    *   **Lost Monotonicity:** Tokens generated immediately after the rollback will sort *before* tokens generated just prior. This is explicitly warned.
    *   **Uniqueness:** Generally maintained. A collision would require the clock to jump back to a millisecond *and* counter value *and* instance ID that perfectly matches a previously generated token *before* the counter naturally increments past that value or `lastTimestamp` advances normally. The risk is low but non-zero, hence the warning.
-   **Rationale:** This strategy prioritizes simplicity and avoids blocking. It acknowledges the clock issue via warning but doesn't try to strictly enforce monotonicity in this edge case, which could add complexity or latency. Users needing strict monotonicity should heed the warnings or consider alternative ID schemes (like those strictly adhering to ULID counter-increment-on-rollback rules).

### 4.2. Counter Overflow (`counter > maxCounter`)

-   **The Problem:** > 46,656 calls within one millisecond by the same instance.
-   **`xdTok`'s Strategy (v1.0.1):**
    1.  Logs a `console.warn`.
    2.  **Resets the `counter` to 0.**
    3.  Generation continues within the same millisecond, starting the counter sequence over (`...000`, `...001`, ...).
-   **Implications:**
    *   The guarantee of uniqueness provided *solely by the counter* within that specific millisecond is momentarily lost.
    *   Overall uniqueness still heavily relies on the `instancePart` and the random suffix (if length > 16). Collisions remain highly unlikely unless the overflow condition persists *and* other components happen to align identically for reused counter values.
-   **Rationale:** Resetting is the simplest non-blocking approach. It assumes overflows are rare anomalies. Systems expecting sustained rates this high might need a generator with a larger counter or a different architecture (e.g., distributed sequence generators).

## 5. Performance Considerations

-   Core operations (`Date.now()`, `Math.random()`, `crypto.getRandomValues()`, string manipulations) are highly optimized in modern JavaScript engines.
-   The overhead of the IIFE and closure is negligible after initialization.
-   The UMD wrapper adds minimal runtime overhead (just a few environment checks).
-   Generation is designed to be allocation-light (primarily string allocations).
-   **Conclusion:** `xdTok` is very fast and suitable for performance-sensitive applications.

## 6. Security Considerations

-   **Not for Cryptographic Secrets:** `xdTok` generates *unique-ish*, *sortable* IDs, **not** cryptographically secure, unguessable tokens. The timestamp and counter parts are predictable. Do not use these for session tokens, API keys, password reset links, etc.
-   **`Math.random` Fallback:** The fallback PRNG is not cryptographically secure. While acceptable for ID uniqueness, it's less robust than `window.crypto`.
-   **Information Leakage:** The timestamp reveals the approximate generation time. Ensure this is acceptable for your use case.

## 7. UMD Wrapper Explained

The code is wrapped in a Universal Module Definition pattern:

```javascript
(function (root, factory) {
  if (typeof define === 'function' && define.amd) { // Check AMD
    define([], factory);
  } else if (typeof module === 'object' && module.exports) { // Check CommonJS/Node
    module.exports = factory();
  } else { // Fallback to Browser Global
    root.xdTok = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  // ... original generator code ...
  return xdTokGenerator; // The factory returns the generator function
}));
```

-   It defines an anonymous function (`factory`) that contains the actual `xdTok` logic and returns the generator function.
-   It immediately calls another function, passing it the global object (`this` or `self`) and the `factory`.
-   This outer function checks for the existence of `define` (AMD) or `module.exports` (CommonJS/Node) and uses the appropriate mechanism to export the result of `factory()`.
-   If neither is found, it assigns the result to a property on the global object (`root.xdTok`), making it available globally in browsers.
-   This ensures the library can be seamlessly integrated into various project setups.

## 8. License Information

This software is licensed under the MIT License.

Copyright (c) 2024 Jakub Śledzikowski <jsledzikowski.web@gmail.com>

Refer to the [LICENSE](LICENSE) file for the full license text.