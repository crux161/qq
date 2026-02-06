// @ts-ignore
import factory from './libkyu.js';
export class KyuStream {
    constructor(module, password) {
        this.sinkPtr = 0;
        this.stash = null;
        // New State for Header Parsing
        this.hasHeader = false;
        this.module = module;
        this.password = password;
        const ctxSize = this.module._kyu_get_sizeof_context();
        this.ctx = this.module._malloc(ctxSize);
        this.keyPtr = this.module._malloc(32);
        this.workBuf = this.module._malloc(65536 + 128);
    }
    static async create(password) {
        const mod = await factory();
        return new KyuStream(mod, password);
    }
    appendToStash(chunk) {
        if (!this.stash)
            return chunk;
        const newBuf = new Uint8Array(this.stash.length + chunk.length);
        newBuf.set(this.stash);
        newBuf.set(chunk, this.stash.length);
        return newBuf;
    }
    get transform() {
        let currentController;
        const sinkCallback = (ctx, bufPtr, len) => {
            const cleartext = new Uint8Array(this.module.HEAPU8.subarray(bufPtr, bufPtr + len));
            currentController.enqueue(new Uint8Array(cleartext));
            return 0;
        };
        this.sinkPtr = this.module.addFunction(sinkCallback, 'iiii');
        return new TransformStream({
            start: () => { },
            transform: (chunk, controller) => {
                currentController = controller;
                let data = this.appendToStash(chunk);
                this.stash = null;
                let offset = 0;
                // 1. Process File Header (Once)
                if (!this.hasHeader) {
                    // Need 20 bytes: KYU5 (4) + Salt (16)
                    if (data.length < 20) {
                        this.stash = data;
                        return;
                    }
                    // Verify Magic
                    const magic = new TextDecoder().decode(data.subarray(0, 4));
                    if (magic !== 'KYU5') {
                        controller.error(new Error("Invalid File Format (Not KYU5)"));
                        return;
                    }
                    // Extract Salt
                    const salt = data.subarray(4, 20);
                    // DERIVE KEY (Argon2id via WASM)
                    const passBuf = new TextEncoder().encode(this.password);
                    // Alloc memory for Pass and Salt
                    const pPass = this.module._malloc(passBuf.length + 1);
                    const pSalt = this.module._malloc(16);
                    this.module.HEAPU8.set(passBuf, pPass);
                    this.module.HEAPU8.set(salt, pSalt);
                    this.module.HEAPU8[pPass + passBuf.length] = 0; // Null term
                    // Call C function
                    this.module._kyu_derive_key(pPass, pSalt, this.keyPtr);
                    // Free temp buffers
                    this.module._free(pPass);
                    this.module._free(pSalt);
                    // Init Context
                    const res = this.module._kyu_init(this.ctx, this.keyPtr, this.sinkPtr, 0, 0);
                    if (res !== 0) {
                        controller.error(new Error(`Init Failed: ${res}`));
                        return;
                    }
                    this.hasHeader = true;
                    offset = 20; // Skip header
                }
                // 2. Process Packets (Same as before)
                while (offset < data.length) {
                    const remaining = data.length - offset;
                    if (remaining < 16) {
                        this.stash = data.slice(offset);
                        break;
                    }
                    // Header V2 [SeqID:8] [Len:4] [Flags:4]
                    const p = offset;
                    const payloadLen = (data[p + 8]) | (data[p + 9] << 8) | (data[p + 10] << 16) | (data[p + 11] << 24);
                    const packetSize = 16 + 16 + payloadLen;
                    if (remaining < packetSize) {
                        this.stash = data.slice(offset);
                        break;
                    }
                    this.module.HEAPU8.set(data.subarray(offset, offset + packetSize), this.workBuf);
                    const res = this.module._kyu_pull(this.ctx, this.workBuf, packetSize);
                    if (res !== 0) {
                        controller.error(new Error(`Kyu Decrypt Error: ${res}`));
                        return;
                    }
                    offset += packetSize;
                }
            },
            flush: () => {
                this.module._free(this.ctx);
                this.module._free(this.keyPtr);
                this.module._free(this.workBuf);
                this.module.removeFunction(this.sinkPtr);
            }
        });
    }
}
