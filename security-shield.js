/**
 * StudioRelay Cryptographic Security Shield & Integrity Sentry
 * Multi-layer polymorphic encoding, honeypot traps, cascading interlock, and DOM defense.
 * (C) Tools by Kartar. All rights reserved.
 */
(function (global) {
    'use strict';

    // ─── FNV-1a 32-bit Cryptographic Checksum Routine ───
    function _fnv(s) {
        if (typeof s !== 'string') return 0;
        let h = 0x811c9dc5;
        for (let i = 0; i < s.length; i++) {
            const c = s.charCodeAt(i);
            if (c < 128) {
                h = (h ^ c) * 0x01000193 >>> 0;
            } else if (c < 2048) {
                h = (h ^ (192 | (c >> 6))) * 0x01000193 >>> 0;
                h = (h ^ (128 | (c & 63))) * 0x01000193 >>> 0;
            } else {
                h = (h ^ (224 | (c >> 12))) * 0x01000193 >>> 0;
                h = (h ^ (128 | ((c >> 6) & 63))) * 0x01000193 >>> 0;
                h = (h ^ (128 | (c & 63))) * 0x01000193 >>> 0;
            }
        }
        return h >>> 0;
    }

    // ─── Golden Integrity Hashes ───
    const HASH_TARGETS = Object.freeze({
        EXT: 0x0f3fb8a8,        // 'StudioRelay'
        AUTHOR: 0x86cde372,     // 'Tools by Kartar'
        BADGE: 0x8d6ef9ed,      // 'Dola 30s by Kartar'
        MODE: 0x50807140,       // '30s (Kartar Mode)'
        BULK: 0x57b7033e,       // 'Bulk Downloader by Kartar'
        ZIP: 0x50dfd705,        // "Kartar's ZIP"
        WA_TITLE: 0xa60e65a7,   // 'Open Kartar WhatsApp Channel'
        WA_URL: 0x73b03f3c,     // 'https://whatsapp.com/channel/0029VbDkJSq1CYoXFhiE9g1Y'
        TG_URL: 0xddfa3f9f,     // 'https://t.me/kartarverse'
        FB_URL: 0xeb5e5c84,     // 'https://www.facebook.com/Kartar.fb'
        VER: 0xa9896b8f,        // 'Studio version 1.7'
        KARTAR: 0xcdb0ac30      // 'Kartar'
    });

    // ─── Decoy Honeypot Constants (Traps for find & replace crackers) ───
    const HONEYPOT_TRAP = Object.freeze({
        AUTHOR: 'Tools by Kartar',
        WA: 'https://whatsapp.com/channel/0029VbDkJSq1CYoXFhiE9g1Y',
        TG: 'https://t.me/kartarverse',
        FB: 'https://www.facebook.com/Kartar.fb',
        EXT: 'StudioRelay'
    });

    // ─── Method 1: Encrypted Byte Streams (XOR / Feistel Chain) ───
    const _E1 = Object.freeze({
        EXT: [204, 190, 93, 125, 186, 105, 182, 184, 123, 35, 217],
        VER: [204, 190, 93, 125, 186, 105, 196, 171, 114, 48, 211, 232, 196, 240, 124, 116, 193, 237],
        AUTHOR: [203, 165, 71, 117, 160, 38, 134, 164, 55, 9, 193, 243, 223, 255, 46],
        BADGE: [219, 165, 68, 120, 243, 53, 212, 174, 55, 32, 217, 161, 224, 255, 46, 49, 142, 168],
        MODE: [172, 250, 91, 57, 251, 77, 133, 175, 99, 35, 210, 161, 230, 241, 56, 32, 198],
        BULK: [221, 191, 68, 114, 243, 66, 139, 170, 121, 46, 207, 224, 207, 251, 46, 101, 141, 163, 56, 66, 66, 100, 160, 172, 21],
        ZIP: [212, 171, 90, 109, 178, 116, 195, 174, 55, 24, 233, 209],
        WA_TITLE: [208, 186, 77, 119, 243, 77, 133, 175, 99, 35, 210, 161, 252, 246, 61, 49, 156, 155, 104, 121, 3, 85, 188, 172, 9, 60, 245, 29],
        WA_URL: [247, 190, 92, 105, 160, 60, 203, 242, 96, 42, 193, 245, 216, 255, 44, 53, 193, 185, 119, 100, 12, 117, 188, 172, 9, 60, 245, 29, 148, 158, 124, 7, 198, 188, 106, 189, 88, 108, 151, 204, 70, 33, 217, 14, 211, 248, 84, 76, 138, 195, 159, 216, 90],
        TG_URL: [247, 190, 92, 105, 160, 60, 203, 242, 99, 108, 205, 228, 132, 245, 61, 55, 155, 187, 106, 127, 70, 100, 167, 168],
        FB_URL: [247, 190, 92, 105, 160, 60, 203, 242, 96, 53, 215, 175, 205, 255, 63, 32, 141, 181, 119, 98, 13, 117, 187, 160, 72, 25, 241, 3, 207, 207, 62, 27, 153, 136],
        KARTAR: [212, 171, 90, 109, 178, 116]
    });

    // ─── Method 2: Prime Polynomial Arithmetic Character Synthesis Matrices ───
    const _E2 = Object.freeze({
        AUTHOR: [-19, -2, 77, 52, 31, -86, 35, 12, -34, -49, 4, 46, 67, 61, -10],
        WA_URL: [1, 3, 82, 56, 31, -60, -16, -62, 53, -20, 4, 48, 66, 61, -12, -11, 13, 55, 50, 25, -66, 46, 10, 51, 11, 47, 68, 4, -39, -26, -20, -18, -17, 0, -6, 35, 44, -25, 37, 19, -4, -46, 5, 50, 44, 37, -19, -19, 33, 8, 35, -44, -35],
        TG_URL: [1, 3, 82, 56, 31, -60, -16, -62, 50, -78, 16, 33, -2, 71, -27, -9, 83, 53, 53, 34, -12, 61, 21, 55],
        FB_URL: [1, 3, 82, 56, 31, -60, -16, -62, 53, -5, 26, -22, 53, 61, -25, -22, 65, 67, 50, 23, -67, 46, 17, 63, -52, 12, 64, 10, 30, 23, 46, -22, 28, 12],
        BADGE: [-35, -2, 74, 41, -52, -67, -15, 6, -34, -26, 28, -36, 26, 61, -10, -7, 64, 70],
        MODE: [-52, -65, 81, -24, -44, -43, 34, 5, 50, -27, 21, -36, 28, 75, -24, -22, 8],
        BULK: [-37, 4, 74, 51, -52, -50, 48, 10, 44, -16, 18, 29, 51, 65, -10, -91, 65, 77, -29, -9, -16, 61, 22, 51, 15],
        EXT: [-20, 3, 83, 44, 21, -7, 19, -8, 42, -27, 28]
    });

    let _tamperedState = false;
    let _verifiedBundle = null;

    // ─── Decoders ───
    function _decodeM1(bytes, keyBytes) {
        let out = '';
        for (let i = 0; i < bytes.length; i++) {
            const k = keyBytes[i % 4] ^ ((i * 17 + 53) & 0xff);
            out += String.fromCharCode(bytes[i] ^ k);
        }
        return out;
    }

    function _decodeM2(diffs, salt) {
        let out = '';
        for (let i = 0; i < diffs.length; i++) {
            const mathBase = ((i * i * 3 + i * 7 + salt) % 95) + 32;
            out += String.fromCharCode(mathBase + diffs[i]);
        }
        return out;
    }

    function _isPopupEnv() {
        if (typeof window === 'undefined' || typeof document === 'undefined') return false;
        try {
            return (
                window.location.protocol === 'chrome-extension:' ||
                Boolean(document.querySelector('.popup-container, #main-unlocked-ui, #view-license-lock'))
            );
        } catch (_) {
            return false;
        }
    }

    // ─── Cross-Layer Cascading Authenticator ───
    function _authenticateAndResolve() {
        if (_verifiedBundle && !_tamperedState) return _verifiedBundle;
        if (_tamperedState) return null;

        // 1. Manifest / Environment verification
        let manifestName = 'StudioRelay';
        try {
            if (typeof chrome !== 'undefined' && chrome.runtime && typeof chrome.runtime.getManifest === 'function') {
                const mf = chrome.runtime.getManifest();
                if (mf && mf.name) {
                    manifestName = String(mf.name).trim();
                }
            }
        } catch (_) {}

        if (_fnv(manifestName) !== HASH_TARGETS.EXT) {
            _tamperedState = true;
            return null;
        }

        // 2. Honeypot Sentry Verification (only in Popup DOM context where decoy exists)
        if (_isPopupEnv() && typeof document !== 'undefined' && document.getElementById) {
            const decoyEl = document.getElementById('sr-decoy-meta');
            if (decoyEl) {
                const dAuthor = decoyEl.getAttribute('data-author') || '';
                const dWa = decoyEl.getAttribute('data-wa') || '';
                const dTg = decoyEl.getAttribute('data-tg') || '';
                const dFb = decoyEl.getAttribute('data-fb') || '';

                if (dAuthor !== HONEYPOT_TRAP.AUTHOR || dWa !== HONEYPOT_TRAP.WA || dTg !== HONEYPOT_TRAP.TG || dFb !== HONEYPOT_TRAP.FB) {
                    _tamperedState = true;
                    return null;
                }
            }
        }

        // 3. Cascading Interlock Synthesis (Key derive)
        const seed1 = _fnv(manifestName) ^ 0xa5b3c7d9;
        const keyBytes = [
            (seed1 >>> 24) & 0xff,
            (seed1 >>> 16) & 0xff,
            (seed1 >>> 8) & 0xff,
            seed1 & 0xff
        ];

        // Step A: Decode Extension Name & Version
        const ext = _decodeM1(_E1.EXT, keyBytes);
        const ver = _decodeM1(_E1.VER, keyBytes);
        const extM2 = _decodeM2(_E2.EXT, 0x47);

        if (_fnv(ext) !== HASH_TARGETS.EXT || ext !== extM2 || _fnv(ver) !== HASH_TARGETS.VER) {
            _tamperedState = true;
            return null;
        }

        // Step B: Decode Social Links via Hash Chain
        const wa = _decodeM1(_E1.WA_URL, keyBytes);
        const waM2 = _decodeM2(_E2.WA_URL, 0x47);
        if (_fnv(wa) !== HASH_TARGETS.WA_URL || wa !== waM2) {
            _tamperedState = true;
            return null;
        }

        const tg = _decodeM1(_E1.TG_URL, keyBytes);
        const tgM2 = _decodeM2(_E2.TG_URL, 0x47);
        if (_fnv(tg) !== HASH_TARGETS.TG_URL || tg !== tgM2) {
            _tamperedState = true;
            return null;
        }

        const fb = _decodeM1(_E1.FB_URL, keyBytes);
        const fbM2 = _decodeM2(_E2.FB_URL, 0x47);
        if (_fnv(fb) !== HASH_TARGETS.FB_URL || fb !== fbM2) {
            _tamperedState = true;
            return null;
        }

        // Step C: Decode Author & Feature Brandings
        const author = _decodeM1(_E1.AUTHOR, keyBytes);
        const authorM2 = _decodeM2(_E2.AUTHOR, 0x47);
        const badge = _decodeM1(_E1.BADGE, keyBytes);
        const badgeM2 = _decodeM2(_E2.BADGE, 0x47);
        const mode = _decodeM1(_E1.MODE, keyBytes);
        const modeM2 = _decodeM2(_E2.MODE, 0x47);
        const bulk = _decodeM1(_E1.BULK, keyBytes);
        const bulkM2 = _decodeM2(_E2.BULK, 0x47);
        const zip = _decodeM1(_E1.ZIP, keyBytes);
        const kartar = _decodeM1(_E1.KARTAR, keyBytes);
        const waTitle = _decodeM1(_E1.WA_TITLE, keyBytes);

        if (
            _fnv(author) !== HASH_TARGETS.AUTHOR || author !== authorM2 ||
            _fnv(badge) !== HASH_TARGETS.BADGE || badge !== badgeM2 ||
            _fnv(mode) !== HASH_TARGETS.MODE || mode !== modeM2 ||
            _fnv(bulk) !== HASH_TARGETS.BULK || bulk !== bulkM2 ||
            _fnv(zip) !== HASH_TARGETS.ZIP ||
            _fnv(kartar) !== HASH_TARGETS.KARTAR ||
            _fnv(waTitle) !== HASH_TARGETS.WA_TITLE
        ) {
            _tamperedState = true;
            return null;
        }

        _verifiedBundle = Object.freeze({
            EXT_NAME: ext,
            VERSION: ver,
            AUTHOR: author,
            SESSION_BADGE: badge,
            MODE_LABEL: mode,
            BULK_DOWNLOADER: bulk,
            KARTAR_ZIP: zip,
            KARTAR_NAME: kartar,
            WA_TITLE: waTitle,
            WHATSAPP_URL: wa,
            TELEGRAM_URL: tg,
            FACEBOOK_URL: fb
        });

        return _verifiedBundle;
    }

    // ─── Tamper Lockout Handler (Popup only) ───
    function _triggerLockdown(reason) {
        _tamperedState = true;
        _verifiedBundle = null;
        console.error('[StudioRelay Security] Integrity assertion failure:', reason || 'Code modification detected');

        if (_isPopupEnv() && typeof document !== 'undefined' && document.body) {
            try {
                const mainUi = document.getElementById('main-unlocked-ui');
                const lockUi = document.getElementById('view-license-lock');
                if (mainUi) mainUi.style.display = 'none';
                if (lockUi) {
                    lockUi.style.display = 'block';
                    const title = lockUi.querySelector('.lock-title');
                    const sub = lockUi.querySelector('.lock-sub');
                    if (title) title.textContent = 'Extension Integrity Alert';
                    if (sub) sub.textContent = 'Unauthorized file modification detected. The original signatures, social links, or author branding have been altered.';
                }
            } catch (_) {}
        }
    }

    // ─── Active DOM & Link Mutation Sentry (Scoped strictly to extension popup) ───
    function _mountAndProtectLinks() {
        if (!_isPopupEnv()) return;
        const bundle = _authenticateAndResolve();
        if (!bundle || typeof document === 'undefined') return;

        const waLink = document.getElementById('whatsapp-channel-link');
        const tgLink = document.getElementById('telegram-channel-link');
        const fbLink = document.getElementById('facebook-page-link');
        const brandTitle = document.getElementById('sr-brand-title') || document.querySelector('.popup-container .title');
        const versionBadge = document.getElementById('sr-version-badge') || document.querySelector('.popup-container .version-badge');

        function enforceNode(el, expectedHref, expectedText, expectedTitle) {
            if (!el) return;
            if (expectedHref && el.getAttribute('href') !== expectedHref) {
                el.setAttribute('href', expectedHref);
            }
            if (expectedTitle && el.getAttribute('title') !== expectedTitle) {
                el.setAttribute('title', expectedTitle);
            }
            if (expectedText) {
                const span = el.querySelector('span') || el;
                if (span && span.textContent.trim() !== expectedText.trim()) {
                    span.textContent = expectedText;
                }
            }
        }

        function applyAll() {
            if (waLink) enforceNode(waLink, bundle.WHATSAPP_URL, 'Join Official WhatsApp Channel', bundle.WA_TITLE);
            if (tgLink) enforceNode(tgLink, bundle.TG_URL, 'Telegram Channel', 'Join Telegram Channel');
            if (fbLink) enforceNode(fbLink, bundle.FACEBOOK_URL, 'Facebook Page', 'Open Facebook Page');
            if (brandTitle && brandTitle.textContent.trim() !== bundle.EXT_NAME) {
                brandTitle.textContent = bundle.EXT_NAME;
            }
            if (versionBadge && versionBadge.textContent.trim() !== bundle.VERSION) {
                versionBadge.textContent = bundle.VERSION;
            }
        }

        applyAll();

        // Attach Active MutationObserver strictly to popup container
        try {
            const footer = document.querySelector('.popup-container .app-footer') || document.querySelector('.popup-container');
            if (footer) {
                const observer = new MutationObserver(() => {
                    if (_tamperedState) return;
                    if (waLink && waLink.getAttribute('href') !== bundle.WHATSAPP_URL) {
                        _triggerLockdown('WhatsApp link altered');
                        return;
                    }
                    if (tgLink && tgLink.getAttribute('href') !== bundle.TG_URL) {
                        _triggerLockdown('Telegram link altered');
                        return;
                    }
                    if (fbLink && fbLink.getAttribute('href') !== bundle.FACEBOOK_URL) {
                        _triggerLockdown('Facebook link altered');
                        return;
                    }
                    applyAll();
                });

                observer.observe(footer, {
                    attributes: true,
                    attributeFilter: ['href', 'title', 'target'],
                    childList: true,
                    subtree: true
                });
            }
        } catch (_) {}
    }

    // ─── Initial Autonomous Run ───
    const initialBundle = _authenticateAndResolve();
    if (!initialBundle && _isPopupEnv()) {
        _triggerLockdown('Initial integrity check failed');
    }

    // ─── Public Sealed Interface ───
    const SecurityShield = Object.freeze({
        fnv32: _fnv,
        getVerifiedBundle: _authenticateAndResolve,
        isTampered: () => _tamperedState,
        mountProtectedLinks: _mountAndProtectLinks,
        triggerLockdown: _triggerLockdown,
        HONEYPOT: HONEYPOT_TRAP,
        HASHES: HASH_TARGETS
    });

    global.__SR_SECURITY_SHIELD__ = SecurityShield;

    if (typeof document !== 'undefined') {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', _mountAndProtectLinks, { once: true });
        } else {
            _mountAndProtectLinks();
        }
    }
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : self));
