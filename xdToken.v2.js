(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.xdToken = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    const CURRENT_VERSION = "6.0.0";
    const DEFAULT_PBKDF2_ITERATIONS = 250000;
    const DEFAULT_SALT_LENGTH = 16;
    const DEFAULT_NONCE_LENGTH = 12;
    const TAG_SIZE = 16;
    const KEY_SIZE = 32;
    const PBKDF2_HASH = "SHA-256";
    const MIN_TOKEN_LENGTH = 4;
    const MAX_TOKEN_LENGTH = 512;
    const DEFAULT_RANDOM_LENGTH = 32;
    const DEFAULT_MAX_DATA_SIZE = 50 * 1024 * 1024;
    const SHA256_B64URL_LEN = 44;

    const CHARSETS = Object.freeze({
        n: "0123456789",
        l: "abcdefghijklmnopqrstuvwxyz",
        u: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        s: "-_",
        a: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    });
    const DEFAULT_CHARSET = CHARSETS.a + CHARSETS.s;

    const LOG_LEVELS = { none: 0, error: 1, warn: 2, info: 3, debug: 4 };
    let currentLogLevel = LOG_LEVELS.warn;

    const ENC_VERSION = 5;
    const ENC_VERSION_OFFSET = 0; const ENC_VERSION_SIZE = 1;
    const ENC_FLAGS_OFFSET = 1; const ENC_FLAGS_SIZE = 1;
    const ENC_TIMESTAMP_OFFSET = 2; const ENC_TIMESTAMP_SIZE = 8;
    const ENC_ITERATIONS_OFFSET = 10; const ENC_ITERATIONS_SIZE = 4;
    const ENC_SALT_LEN_OFFSET = 14; const ENC_SALT_LEN_SIZE = 2;
    const ENC_NONCE_LEN_OFFSET = 16; const ENC_NONCE_LEN_SIZE = 2;
    const ENC_HEADER_SIZE = 18;
    const FLAG_BINARY_DATA = 0x01;

    class XdTokenError extends Error { constructor(message) { super(message); this.name = this.constructor.name; } }
    class XdTokenConfigurationError extends XdTokenError {}
    class XdTokenOperationError extends XdTokenError {}
    class XdTokenAuthenticationError extends XdTokenError {}

    function log(level, ...args) {
        if (LOG_LEVELS[level] === undefined || LOG_LEVELS[level] > currentLogLevel) return;
        const levelName = level.toUpperCase();
        try {
            const logFunc = console[level] || console.log;
            logFunc(`[xdToken][${levelName}]`, ...args);
        } catch (e) {}
    }

    let subtleCryptoCache = null;
    function getSubtleCrypto() {
        if (subtleCryptoCache) return subtleCryptoCache;
        if (!globalThis.crypto || !globalThis.crypto.subtle || !globalThis.crypto.getRandomValues) {
            throw new XdTokenOperationError("Web Crypto API (crypto.subtle, crypto.getRandomValues) not available.");
        }
        return subtleCryptoCache = globalThis.crypto.subtle;
    }

    function getRandomBytes(length) {
        if (!Number.isInteger(length) || length <= 0) throw new XdTokenConfigurationError("Invalid length for random bytes.");
        const bytes = new Uint8Array(length);
        globalThis.crypto.getRandomValues(bytes);
        return bytes;
    }

    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    const textEncode = (text) => encoder.encode(text);
    const textDecode = (buffer) => decoder.decode(buffer);

    function bytesToBase64Url(bytes) {
        if (!(bytes instanceof Uint8Array)) throw new XdTokenConfigurationError("Input must be Uint8Array for Base64URL encoding.");
        let binaryString = '';
        bytes.forEach(byte => binaryString += String.fromCharCode(byte));
        return btoa(binaryString).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    function bytesToBase64(bytes) {
        if (!(bytes instanceof Uint8Array)) throw new XdTokenConfigurationError("Input must be Uint8Array for Base64 encoding.");
        let binaryString = '';
        bytes.forEach(byte => binaryString += String.fromCharCode(byte));
        return btoa(binaryString);
    }
    function bytesToHex(bytes) {
        if (!(bytes instanceof Uint8Array)) throw new XdTokenConfigurationError("Input must be Uint8Array for Hex encoding.");
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function base64UrlToBytes(base64url) {
        if (typeof base64url !== 'string') throw new XdTokenConfigurationError("Input must be a Base64URL string.");
        base64url = base64url.replace(/-/g, '+').replace(/_/g, '/');
        while (base64url.length % 4) base64url += '=';
        try {
            const binaryString = atob(base64url);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
            return bytes;
        } catch (e) {
            throw new XdTokenConfigurationError("Invalid Base64URL input string.");
        }
    }

    async function getPasswordKeyMaterial(passwordOrKey, signal) {
        if (signal?.aborted) throw new DOMException('Operation aborted.', 'AbortError');
        let inputBytes;
        if (passwordOrKey instanceof Uint8Array) inputBytes = passwordOrKey;
        else if (typeof passwordOrKey === 'string') inputBytes = textEncode(passwordOrKey);
        else throw new XdTokenConfigurationError("Password/Key must be a non-empty string or a Uint8Array.");
        if (inputBytes.length === 0) throw new XdTokenConfigurationError("Password/Key cannot be empty.");
        return await getSubtleCrypto().importKey("raw", inputBytes, { name: "PBKDF2" }, false, ["deriveKey"]);
    }

    async function deriveKeyFromPassword(keyMaterial, salt, iterations, signal) {
        if (signal?.aborted) throw new DOMException('Operation aborted.', 'AbortError');
        const minIterations = 10000;
        if (!Number.isInteger(iterations) || iterations < minIterations) throw new XdTokenConfigurationError(`Invalid iterations: ${iterations}. Minimum required: ${minIterations}.`);
        return await getSubtleCrypto().deriveKey(
            { name: "PBKDF2", salt, iterations, hash: PBKDF2_HASH },
            keyMaterial,
            { name: "AES-GCM", length: KEY_SIZE * 8 }, false, ["encrypt", "decrypt"]
        );
    }

    function buildEncryptedBlob(flags, timestamp, iterations, salt, nonce, ciphertextBuffer) {
        const saltLen = salt.length; const nonceLen = nonce.length;
        if (saltLen > 65535 || nonceLen > 65535) throw new XdTokenOperationError("Salt/Nonce length exceeds 65535.");
        const totalSize = ENC_HEADER_SIZE + saltLen + nonceLen + ciphertextBuffer.byteLength;
        const resultBuffer = new ArrayBuffer(totalSize); const view = new DataView(resultBuffer); const bytes = new Uint8Array(resultBuffer);
        view.setUint8(ENC_VERSION_OFFSET, ENC_VERSION); view.setUint8(ENC_FLAGS_OFFSET, flags);
        view.setFloat64(ENC_TIMESTAMP_OFFSET, timestamp, false); view.setUint32(ENC_ITERATIONS_OFFSET, iterations, false);
        view.setUint16(ENC_SALT_LEN_OFFSET, saltLen, false); view.setUint16(ENC_NONCE_LEN_OFFSET, nonceLen, false);
        let offset = ENC_HEADER_SIZE; bytes.set(salt, offset); offset += saltLen; bytes.set(nonce, offset); offset += nonceLen;
        bytes.set(new Uint8Array(ciphertextBuffer), offset); return bytes;
    }

    function parseEncryptedBlob(encryptedBytes) {
        if (!(encryptedBytes instanceof Uint8Array)) throw new XdTokenConfigurationError("Input must be Uint8Array.");
        if (encryptedBytes.length < ENC_HEADER_SIZE) throw new XdTokenOperationError("Invalid data: too short for header.");
        const buffer = encryptedBytes.buffer, byteOffset = encryptedBytes.byteOffset, byteLength = encryptedBytes.byteLength;
        const view = new DataView(buffer, byteOffset, byteLength);
        const version = view.getUint8(ENC_VERSION_OFFSET);
        if (version !== ENC_VERSION) throw new XdTokenOperationError(`Unsupported encryption format version: ${version}. Expected ${ENC_VERSION}.`);
        const flags = view.getUint8(ENC_FLAGS_OFFSET); const timestamp = view.getFloat64(ENC_TIMESTAMP_OFFSET, false);
        const iterations = view.getUint32(ENC_ITERATIONS_OFFSET, false); const saltLen = view.getUint16(ENC_SALT_LEN_OFFSET, false);
        const nonceLen = view.getUint16(ENC_NONCE_LEN_OFFSET, false);
        const saltOffset = ENC_HEADER_SIZE; const nonceOffset = saltOffset + saltLen; const ciphertextOffset = nonceOffset + nonceLen;
        const minTotalLength = ciphertextOffset;
        if (byteLength < minTotalLength) throw new XdTokenOperationError("Invalid data: declared lengths exceed buffer size.");
        if (saltLen === 0 || nonceLen === 0) throw new XdTokenOperationError("Invalid data: zero length salt or nonce.");
        const salt = new Uint8Array(buffer, byteOffset + saltOffset, saltLen);
        const nonce = new Uint8Array(buffer, byteOffset + nonceOffset, nonceLen);
        const ciphertext = new Uint8Array(buffer, byteOffset + ciphertextOffset, byteLength - ciphertextOffset);
        return { version, flags, timestamp, iterations, salt, nonce, ciphertext };
    }

    async function encryptAesGcm(plaintextBytes, key, nonce, additionalDataBytes, signal) {
        if (signal?.aborted) throw new DOMException('Operation aborted.', 'AbortError');
        const params = { name: "AES-GCM", iv: nonce, tagLength: TAG_SIZE * 8 };
        if (additionalDataBytes) params.additionalData = additionalDataBytes;
        return await getSubtleCrypto().encrypt(params, key, plaintextBytes);
    }

    async function decryptAesGcm(ciphertext, key, nonce, additionalDataBytes, signal) {
        if (signal?.aborted) throw new DOMException('Operation aborted.', 'AbortError');
        const params = { name: "AES-GCM", iv: nonce, tagLength: TAG_SIZE * 8 };
        if (additionalDataBytes) params.additionalData = additionalDataBytes;
        try {
            return await getSubtleCrypto().decrypt(params, key, ciphertext);
        } catch (error) {
            log('error', "AES-GCM Decryption failed:", error.name);
            if (error.name === 'OperationError') {
                throw new XdTokenAuthenticationError("Decryption failed: Authentication error (invalid password/key, corrupted data, or incorrect AAD).");
            }
            throw new XdTokenOperationError(`Decryption failed: ${error.message}`);
        }
    }

    async function sha256Hash(data, signal) {
        if (signal?.aborted) throw new DOMException('Operation aborted.', 'AbortError');
        let buffer;
        if (typeof data === 'string') buffer = textEncode(data);
        else if (data instanceof Uint8Array) buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
        else if (data instanceof ArrayBuffer) buffer = data;
        else throw new XdTokenConfigurationError("Invalid data type for hashing.");
        return await getSubtleCrypto().digest("SHA-256", buffer);
    }

    async function xdToken(options = {}) {
        let config = {};
        if (typeof options === 'string') config = { mode: 'hash', input: options };
        else if (typeof options === 'number') config = { mode: 'random', length: options };
        else if (typeof options === 'object' && options !== null) config = { ...options };
        else if (options == null) config = { mode: 'random' };
        else throw new XdTokenConfigurationError("Invalid input type.");

        const mode = config.mode ?? 'random';
        const inputData = config.input ?? config.data ?? config.text;
        const inputToken = config.token;
        const passwordOrKey = config.password ?? config.key;
        const prefix = config.prefix;
        const prefixPosition = config.position ?? 'start';
        const charset = config.charset ?? DEFAULT_CHARSET;
        const iterations = config.iterations ?? DEFAULT_PBKDF2_ITERATIONS;
        const saltLength = config.saltLength ?? DEFAULT_SALT_LENGTH;
        const nonceLength = config.nonceLength ?? DEFAULT_NONCE_LENGTH;
        const additionalData = config.additionalData;
        let outputLength = config.length ?? DEFAULT_RANDOM_LENGTH;
        const maxDataSize = config.maxDataSize ?? DEFAULT_MAX_DATA_SIZE;
        const logLevel = config.logLevel;
        const signal = config.signal;
        const outputFormat = config.outputFormat ?? (mode === 'hash' ? 'base64url' : 'charset');
        const allowHashTruncation = config.allowHashTruncation ?? false;

        const originalLogLevel = currentLogLevel;
        if (logLevel && LOG_LEVELS[logLevel] !== undefined) {
            currentLogLevel = LOG_LEVELS[logLevel];
            log('debug', `Temporary log level set to ${logLevel}`);
        }

        if (currentLogLevel >= LOG_LEVELS.debug) {
            const sanitizedConfig = { ...config };
            if (sanitizedConfig.password) sanitizedConfig.password = '***';
            if (sanitizedConfig.key instanceof Uint8Array) sanitizedConfig.key = '[Uint8Array]';
            else if (sanitizedConfig.key) sanitizedConfig.key = '***';
            log('debug', `Executing mode: ${mode} with config:`, sanitizedConfig);
        }

        const minIterations = 10000;
        if (!['random', 'hash', 'encrypt', 'decrypt'].includes(mode)) throw new XdTokenConfigurationError(`Invalid mode: ${mode}`);
        if (outputLength !== undefined && (!Number.isInteger(outputLength) || outputLength < (outputFormat === 'charset' ? MIN_TOKEN_LENGTH : 1))) throw new XdTokenConfigurationError(`Invalid length: ${outputLength}.`);
        if (outputFormat === 'charset' && outputLength > MAX_TOKEN_LENGTH) throw new XdTokenConfigurationError(`Length for charset output cannot exceed ${MAX_TOKEN_LENGTH}.`);
        if (typeof charset !== 'string' || charset.length === 0) throw new XdTokenConfigurationError("Charset must be non-empty string.");
        if ((mode === 'encrypt' || mode === 'decrypt') && (!Number.isInteger(iterations) || iterations < minIterations)) throw new XdTokenConfigurationError(`Iterations must be >= ${minIterations}.`);
        if (mode === 'encrypt' && (!Number.isInteger(saltLength) || saltLength < 16)) throw new XdTokenConfigurationError("Salt length must be >= 16.");
        if (mode === 'encrypt' && (!Number.isInteger(nonceLength) || nonceLength < 12)) throw new XdTokenConfigurationError("Nonce length must be >= 12.");
        if (mode === 'encrypt' && (!Number.isInteger(maxDataSize) || maxDataSize <= 0)) throw new XdTokenConfigurationError("Max data size must be positive integer.");
        if ((mode === 'encrypt' || mode === 'decrypt') && !passwordOrKey) throw new XdTokenConfigurationError(`Mode '${mode}' requires 'password' or 'key'.`);
        if ((mode === 'encrypt' || mode === 'decrypt') && !(typeof passwordOrKey === 'string' || passwordOrKey instanceof Uint8Array)) throw new XdTokenConfigurationError("Password/Key must be string or Uint8Array.");
        if ((mode === 'encrypt' || mode === 'decrypt') && passwordOrKey.length === 0) throw new XdTokenConfigurationError("Password/Key cannot be empty.");
        if (!['charset', 'hex', 'base64', 'base64url'].includes(outputFormat)) throw new XdTokenConfigurationError(`Invalid outputFormat: ${outputFormat}`);
        if (mode === 'hash' && outputFormat === 'charset') throw new XdTokenConfigurationError("Output format 'charset' is not supported for hash mode.");
        if (mode === 'random' && outputFormat !== 'charset' && !Number.isInteger(outputLength)) throw new XdTokenConfigurationError(`Length (bytes) required for random mode with outputFormat '${outputFormat}'.`);

        if (signal?.aborted) throw new DOMException('Operation aborted before starting.', 'AbortError');
        getSubtleCrypto();

        let result = null;
        try {
            switch (mode) {
                case 'encrypt': {
                    if (inputData === null || inputData === undefined) throw new XdTokenConfigurationError("Encrypt requires 'input'.");
                    let inputBytes; let flags = 0;
                    if (inputData instanceof Uint8Array || inputData instanceof ArrayBuffer || ArrayBuffer.isView(inputData)) {
                        inputBytes = (inputData instanceof Uint8Array) ? inputData : new Uint8Array(inputData.buffer, inputData.byteOffset, inputData.byteLength);
                        flags |= FLAG_BINARY_DATA; log('debug', 'Encrypting binary data.');
                    } else if (typeof inputData === 'string') {
                        inputBytes = textEncode(inputData); log('debug', 'Encrypting text data.');
                    } else throw new XdTokenConfigurationError("Invalid input data type for encrypt.");
                    if (inputBytes.length > maxDataSize) throw new XdTokenConfigurationError(`Input data size (${inputBytes.length}) exceeds maxDataSize (${maxDataSize}).`);
                    if (signal?.aborted) throw new DOMException('Operation aborted.', 'AbortError');
                    const salt = getRandomBytes(saltLength); const nonce = getRandomBytes(nonceLength); const timestamp = Date.now();
                    const additionalDataBytes = additionalData ? (additionalData instanceof Uint8Array ? additionalData : textEncode(additionalData)) : null;
                    const keyMaterial = await getPasswordKeyMaterial(passwordOrKey, signal);
                    const key = await deriveKeyFromPassword(keyMaterial, salt, iterations, signal);
                    const ciphertextBuffer = await encryptAesGcm(inputBytes, key, nonce, additionalDataBytes, signal);
                    const resultBytes = buildEncryptedBlob(flags, timestamp, iterations, salt, nonce, ciphertextBuffer);
                    result = bytesToBase64Url(resultBytes); break;
                }
                case 'decrypt': {
                    if (typeof inputToken !== 'string' || inputToken.length === 0) throw new XdTokenConfigurationError("Decrypt requires 'token'.");
                    if (signal?.aborted) throw new DOMException('Operation aborted.', 'AbortError');
                    const encryptedBytes = base64UrlToBytes(inputToken);
                    const { version, flags, timestamp, iterations: fileIterations, salt, nonce, ciphertext } = parseEncryptedBlob(encryptedBytes);
                    log('debug', `Decrypting V${version} data from ${new Date(timestamp).toISOString()} with ${fileIterations} iterations. Flags: ${flags}`);
                    const additionalDataBytes = additionalData ? (additionalData instanceof Uint8Array ? additionalData : textEncode(additionalData)) : null;
                    const keyMaterial = await getPasswordKeyMaterial(passwordOrKey, signal);
                    const key = await deriveKeyFromPassword(keyMaterial, salt, fileIterations, signal);
                    const decryptedBuffer = await decryptAesGcm(ciphertext, key, nonce, additionalDataBytes, signal);
                    if (flags & FLAG_BINARY_DATA) { result = new Uint8Array(decryptedBuffer); log('debug', 'Decrypted to binary.'); }
                    else { result = textDecode(decryptedBuffer); log('debug', 'Decrypted to text.'); } break;
                }
                case 'hash': {
                    if (inputData === null || inputData === undefined || (typeof inputData === 'string' && inputData.length === 0)) throw new XdTokenConfigurationError("Hash requires non-empty 'input'.");
                    const hashBuffer = await sha256Hash(inputData, signal); const hashBytes = new Uint8Array(hashBuffer);
                    if (outputFormat === 'hex') result = bytesToHex(hashBytes);
                    else if (outputFormat === 'base64') result = bytesToBase64(hashBytes);
                    else result = bytesToBase64Url(hashBytes);
                    const fullLength = result.length;
                    if (outputLength < fullLength) {
                        if (!allowHashTruncation) throw new XdTokenConfigurationError(`Hash truncation not allowed. Requested length ${outputLength} < full hash length ${fullLength}. Set allowHashTruncation: true.`);
                        log('warn', `Truncating hash output (${outputFormat}) from ${fullLength} to ${outputLength} characters. Reduces collision resistance.`);
                        result = result.substring(0, outputLength);
                    } else if (outputLength > fullLength) { log('warn', `Requested length ${outputLength} > full hash length ${fullLength}. Returning full hash.`); }
                    break;
                }
                case 'random': default: {
                    if (mode !== 'random') log('warn', `Invalid mode '${mode}', defaulting to 'random'.`);
                    if (outputFormat === 'charset') {
                        if (!Number.isInteger(outputLength) || outputLength < MIN_TOKEN_LENGTH || outputLength > MAX_TOKEN_LENGTH) throw new XdTokenConfigurationError(`Invalid length for charset output: ${outputLength}.`);
                        if (!charset) throw new XdTokenConfigurationError("Charset required for random 'charset' output.");
                        let randomString = ''; const charsetLen = charset.length; const maxByteValue = Math.floor(256 / charsetLen) * charsetLen;
                        let attempts = 0; const maxAttempts = outputLength * 5;
                        while (randomString.length < outputLength && attempts < maxAttempts) {
                            const needed = outputLength - randomString.length; const batchSize = Math.max(needed, Math.min(needed * 2, 1024));
                            const randomBytesChunk = getRandomBytes(batchSize);
                            for (let i = 0; i < randomBytesChunk.length && randomString.length < outputLength; i++) {
                                if (randomBytesChunk[i] < maxByteValue) { randomString += charset[randomBytesChunk[i] % charsetLen]; }
                                attempts++;
                            }
                        }
                        if (randomString.length < outputLength) throw new XdTokenOperationError("Failed to generate enough unbiased random bytes.");
                        result = randomString;
                    } else {
                        if (!Number.isInteger(outputLength) || outputLength < 1) throw new XdTokenConfigurationError(`Length (bytes) must be >= 1 for format ${outputFormat}.`);
                        const randomBytes = getRandomBytes(outputLength);
                        if (outputFormat === 'hex') result = bytesToHex(randomBytes);
                        else if (outputFormat === 'base64') result = bytesToBase64(randomBytes);
                        else result = bytesToBase64Url(randomBytes);
                    }
                    break;
                }
            }
        } catch (error) {
            if (logLevel && LOG_LEVELS[logLevel] !== undefined) currentLogLevel = originalLogLevel;
            if (error instanceof XdTokenError || error instanceof DOMException) { log('error', `Operation failed: [${error.name}] ${error.message}`); throw error; }
            log('error', `Operation failed unexpectedly in mode '${mode}':`, error);
            if (currentLogLevel >= LOG_LEVELS.debug) console.error(error);
            throw new XdTokenOperationError(`xdToken operation failed: ${error.message}`);
        } finally {
            if (logLevel && LOG_LEVELS[logLevel] !== undefined) currentLogLevel = originalLogLevel;
        }

        if (typeof result === 'string' && prefix && typeof prefix === 'string') {
            const resultLen = result.length;
            switch (prefixPosition) {
                case 'start': return prefix + result;
                case 'end': return result + prefix;
                case 'middle': const mid = Math.floor(resultLen / 2); return result.slice(0, mid) + prefix + result.slice(mid);
                default: log('warn', `Invalid prefix position '${prefixPosition}', defaulting 'start'.`); return prefix + result;
            }
        }
        return result;
    }

    xdToken.batch = async function(count, options = {}) {
        if (typeof count !== 'number' || !Number.isInteger(count) || count <= 0) {
            throw new XdTokenConfigurationError("Batch count must be a positive integer.");
        }
        const outputLength = options.length ?? DEFAULT_RANDOM_LENGTH;
        const charset = options.charset ?? DEFAULT_CHARSET;
        const prefix = options.prefix;
        const prefixPosition = options.position ?? 'start';

        if (!Number.isInteger(outputLength) || outputLength < MIN_TOKEN_LENGTH || outputLength > MAX_TOKEN_LENGTH) {
            throw new XdTokenConfigurationError(`Batch: Invalid length. Must be int between ${MIN_TOKEN_LENGTH}-${MAX_TOKEN_LENGTH}.`);
        }
        if (typeof charset !== 'string' || charset.length === 0) {
            throw new XdTokenConfigurationError("Batch: Charset must be non-empty string.");
        }
        if (prefix && typeof prefix !== 'string') {
             throw new XdTokenConfigurationError("Batch: Prefix must be a string.");
        }

        log('info', `Generating batch of ${count} random tokens (length: ${outputLength}, charset: ${charset.length} chars).`);
        getSubtleCrypto();

        const totalBytesNeeded = count * outputLength;
        const allRandomBytes = getRandomBytes(totalBytesNeeded);
        const results = new Array(count);
        const charsetLen = charset.length;
        const maxByteValue = Math.floor(256 / charsetLen) * charsetLen;
        let byteIndex = 0;
        let attempts = 0;
        const maxAttemptsPerToken = 5; // Safety break per token

        for (let i = 0; i < count; i++) {
            let randomString = '';
            let currentTokenAttempts = 0;
            let requiredBytesForToken = [];

            // Gather unbiased bytes for this token
            while(requiredBytesForToken.length < outputLength && currentTokenAttempts < maxAttemptsPerToken * outputLength) {
                 if (byteIndex >= allRandomBytes.length) { // Need more base random bytes? (Shouldn't happen with good estimate)
                      log('warn', 'Batch needed more random bytes than initially estimated.');
                      allRandomBytes = getRandomBytes(totalBytesNeeded); // Regenerate pool (inefficient but safe)
                      byteIndex = 0;
                 }
                 const byte = allRandomBytes[byteIndex++];
                 if (byte < maxByteValue) {
                     requiredBytesForToken.push(byte);
                 }
                 currentTokenAttempts++;
                 attempts++;
            }

            if (requiredBytesForToken.length < outputLength) {
                 throw new XdTokenOperationError(`Batch: Failed to generate enough unbiased bytes for token ${i+1}.`);
            }

            // Build the string for this token
            for(let j=0; j < outputLength; j++) {
                randomString += charset[requiredBytesForToken[j] % charsetLen];
            }

            if (prefix) {
                 const resultLen = randomString.length;
                 switch (prefixPosition) {
                     case 'start': results[i] = prefix + randomString; break;
                     case 'end': results[i] = randomString + prefix; break;
                     case 'middle': const mid = Math.floor(resultLen / 2); results[i] = randomString.slice(0, mid) + prefix + randomString.slice(mid); break;
                     default: results[i] = prefix + randomString;
                 }
            } else {
                results[i] = randomString;
            }
        }
        log('debug', `Batch generation complete for ${count} tokens. Total random bytes processed: ${byteIndex}`);
        return results;
    };

    xdToken.getCiphertextInfo = function(ciphertextBase64Url) {
        log('debug', 'Attempting to get ciphertext info.');
        if (typeof ciphertextBase64Url !== 'string' || ciphertextBase64Url.length === 0) { log('error', 'getCiphertextInfo: Input must be non-empty string.'); return null; }
        try {
            const encryptedBytes = base64UrlToBytes(ciphertextBase64Url);
            if (encryptedBytes.length < ENC_HEADER_SIZE) { log('error', 'getCiphertextInfo: Data too short for header.'); return null; }
            const buffer = encryptedBytes.buffer, byteOffset = encryptedBytes.byteOffset, byteLength = encryptedBytes.byteLength;
            const view = new DataView(buffer, byteOffset, byteLength);
            const version = view.getUint8(ENC_VERSION_OFFSET);
            if (version !== ENC_VERSION) { log('error', `getCiphertextInfo: Unsupported version ${version}.`); return null; }
            const flags = view.getUint8(ENC_FLAGS_OFFSET);
            const timestamp = view.getFloat64(ENC_TIMESTAMP_OFFSET, false);
            const iterations = view.getUint32(ENC_ITERATIONS_OFFSET, false);
            const saltSize = view.getUint16(ENC_SALT_LEN_OFFSET, false);
            const nonceSize = view.getUint16(ENC_NONCE_LEN_OFFSET, false);
            const saltOffset = ENC_HEADER_SIZE;
            const nonceOffset = saltOffset + saltSize;
            const payloadOffset = nonceOffset + nonceSize;
            if (saltSize === 0 || nonceSize === 0 || payloadOffset > byteLength) { log('error', 'getCiphertextInfo: Invalid lengths in header.'); return null; }
            const saltBytes = new Uint8Array(buffer, byteOffset + saltOffset, saltSize);
            const nonceBytes = new Uint8Array(buffer, byteOffset + nonceOffset, nonceSize);
            return { version, flags, timestamp, iterations, saltSize, nonceSize, headerSize: ENC_HEADER_SIZE, payloadOffset, saltBytes, nonceBytes };
        } catch (error) {
            log('error', 'getCiphertextInfo failed:', error.message);
            return null;
        }
    };

    xdToken.setLogLevel = function(levelName) {
        const level = LOG_LEVELS[levelName];
        if (level !== undefined) {
            currentLogLevel = level;
            log('info', `Log level set to ${levelName} (${level})`);
        } else {
            log('warn', `Invalid log level: ${levelName}. Keeping ${Object.keys(LOG_LEVELS)[currentLogLevel]}.`);
        }
    };

    xdToken.version = CURRENT_VERSION;
    xdToken.CHARSETS = CHARSETS;
    xdToken.ErrorTypes = Object.freeze({
        XdTokenError,
        XdTokenConfigurationError,
        XdTokenOperationError,
        XdTokenAuthenticationError
    });

    return Object.freeze(xdToken);
}));