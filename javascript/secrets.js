(function () {
    'use strict';

    function getEHelper() {
        return typeof window.e !== 'undefined' ? window.e : null;
    }

    const I18N_DEFAULTS = {
        fallbackError: 'Something went wrong. Please try again.',
        incompleteLinkError: 'This link is invalid or incomplete. Ask the sender for a fresh link.',
        retrieveMissingMessage: 'The secret is either not yet submitted, already viewed, or expired. Ask the sender for a fresh link.',
        fulfillMissingMessage: 'This request has expired or was already answered. Ask the requester for a fresh link.',
        unsupportedBrowserMessage: 'This feature requires a recent browser version (Chrome 133+, Firefox 137+, Safari 18.4+, or Edge equivalent).',
        bootUnavailableMessage: 'Secrets unavailable. Please refresh the page.',
        networkError: 'Network error. Please check your connection and try again.',
        pasteFullUrl: 'Please paste the full URL.',
        invalidUrl: 'This does not look like a valid URL.',
        urlWrongFormat: 'This URL does not match the expected format.',
        urlMissingFragment: 'The URL is missing the fragment (the part after #).',
        enterSecretFirst: 'Please enter a secret before creating a link.',
        chooseLifetime: 'Please choose a lifetime.',
        serverNoToken: 'Server did not return a valid token.',
        linkCreated: 'Secret link created. Copy and share it now.',
        linkCopied: 'Link copied to clipboard.',
        copyFailedSelectManually: 'Could not copy. Please select and copy manually.',
        serverResponseIncomplete: 'Server response was incomplete.',
        secretCopied: 'Secret copied to clipboard.',
        clipboardCopyFailed: 'Clipboard copy failed. Please select and copy manually.',
        requestCreated: 'Request created. Save both links before leaving this page.',
        senderLinkCopied: 'Sender link copied.',
        retrievalLinkCopied: 'Your retrieval link copied.',
        enterSecretSubmit: 'Please enter a secret to submit.',
        linkTampered: 'The link appears tampered with. Please ask for a fresh link.',
        clipboardCleared: 'Clipboard cleared for safety.',
        labelPrefix: 'Label:',
        expiresPrefix: 'Expires:',
        requestFailed: 'Request failed',
        pwEnterPassword: 'Please enter a password.',
        pwWrong: 'Wrong password. Try again.',
        statusSectionTitle: 'Live status',
        statusWaitingSecret: 'Waiting for the recipient to open the link.',
        statusWaitingRequest: 'Waiting for the sender to submit the secret.',
        statusFulfilled: 'Secret submitted, ready for you to retrieve.',
        statusRetrievedSecret: 'Retrieved and destroyed on the server.',
        statusRetrievedRequest: 'You picked up the secret and the server destroyed it.',
        statusExpired: 'Expired without retrieval.',
        statusCleanedUp: 'No longer tracked. The status entry has been removed.',
        statusLabelWaiting: 'Waiting',
        statusLabelFulfilled: 'Submitted',
        statusLabelRetrieved: 'Retrieved',
        statusLabelExpired: 'Expired',
        statusLabelCleanedUp: 'Cleaned up',
        statusCreatedAt: 'Created',
        statusFulfilledAt: 'Submitted',
        statusRetrievedAt: 'Retrieved',
        statusLive: 'Live',
        statusConnecting: 'Reconnecting',
        statusOffline: 'Offline. Reload the page to see the current status.',
        statusSessionExpired: 'Session expired, please sign in again.',
        statusUnavailable: 'No longer available. Reload the page to see the final status.',
        dashboardConnecting: 'Connecting',
        countdownExpiresIn: 'Expires in {time}',
        countdownLessThanMinute: 'Expires in less than a minute',
        countdownExpired: 'Expired',
        countdownUnitDay: 'd',
        countdownUnitHour: 'h',
        countdownUnitMinute: 'min',
        countdownUnitSecond: 's',
        attachmentTooLarge: 'This file is too large. The maximum size is 10 MB.',
        attachmentDownload: 'Download attachment',
        attachmentDecryptFailed: 'The attachment could not be decrypted.',
        agentPurposeCommand: 'The program that asked for this will pass it to exactly this command:',
        agentPurposeEnvFile: 'The program that asked for this will write it into exactly this .env file:',
        agentPurposeFile: 'The program that asked for this will write it into exactly this file:',
        agentEnterValue: 'Please enter a value for {name}.',
    };

    let i18nCache = null;

    function readI18n() {
        if (i18nCache !== null) {
            return i18nCache;
        }
        const node = document.getElementById('secrets-i18n');
        if (!node || !node.textContent) {
            i18nCache = Object.assign({}, I18N_DEFAULTS);
            return i18nCache;
        }
        try {
            const parsed = JSON.parse(node.textContent);
            if (parsed && typeof parsed === 'object') {
                i18nCache = Object.assign({}, I18N_DEFAULTS, parsed);
                return i18nCache;
            }
        } catch (parseError) {
            if (window.console && typeof window.console.warn === 'function') {
                window.console.warn('secrets-i18n: JSON parse failed, using EN defaults', parseError);
            }
        }
        i18nCache = Object.assign({}, I18N_DEFAULTS);
        return i18nCache;
    }

    function t(key) {
        return readI18n()[key];
    }

    const PROJECT_PREFIX = (getEHelper() && typeof getEHelper().getProjectPrefix === 'function')
        ? getEHelper().getProjectPrefix()
        : (document.querySelector('meta[name="project"]')?.getAttribute('content') || '');
    const API_BASE = PROJECT_PREFIX + '/api/secrets';
    const PAGE_BASE = PROJECT_PREFIX;
    const APP_ORIGIN = window.location.origin;
    const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
    const CLIPBOARD_CLEAR_DELAY_MS = 30000;

    function notify(message, isError) {
        const eh = getEHelper();
        const type = isError ? 'error' : 'success';
        if (eh && typeof eh.notify === 'function') {
            eh.notify(message, type, isError ? 10000 : 5000);
            return;
        }
        document.dispatchEvent(new CustomEvent('ec-notify', {
            detail: { message: message, type: type, duration: isError ? 10000 : 5000 },
        }));
    }

    function reportSseError(message) {
        const eh = getEHelper();
        if (eh && typeof eh.reportError === 'function') {
            eh.reportError(message, null, { errorName: 'SecretsSseError' });
            return;
        }
        if (window.console && typeof window.console.error === 'function') {
            window.console.error(message);
        }
    }

    function b64urlEncode(bytes) {
        let binary = '';
        const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
        for (let i = 0; i < view.length; i += 1) {
            binary += String.fromCharCode(view[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/g, '');
    }

    function b64urlDecode(text) {
        if (typeof text !== 'string' || !BASE64URL_PATTERN.test(text)) {
            throw new Error('Invalid base64url input');
        }
        const normalized = text.replace(/-/g, '+').replace(/_/g, '/');
        const padLength = (4 - (normalized.length % 4)) % 4;
        const padded = normalized + '='.repeat(padLength);
        const binary = atob(padded);
        return Uint8Array.from(binary, (c) => c.charCodeAt(0));
    }

    function b64urlEncodeLarge(bytes) {
        const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
        const chunkSize = 0x8000;
        let binary = '';
        for (let offset = 0; offset < view.length; offset += chunkSize) {
            const chunk = view.subarray(offset, offset + chunkSize);
            binary += String.fromCharCode.apply(null, chunk);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/g, '');
    }

    function b64urlDecodeLarge(text) {
        if (typeof text !== 'string' || !BASE64URL_PATTERN.test(text)) {
            throw new Error('Invalid base64url input');
        }
        const normalized = text.replace(/-/g, '+').replace(/_/g, '/');
        const padLength = (4 - (normalized.length % 4)) % 4;
        const binary = atob(normalized + '='.repeat(padLength));
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i += 1) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    function packAttachmentMeta(nonceBytes, ciphertextBytes) {
        const combined = new Uint8Array(nonceBytes.length + ciphertextBytes.length);
        combined.set(nonceBytes, 0);
        combined.set(ciphertextBytes, nonceBytes.length);
        return b64urlEncodeLarge(combined);
    }

    function unpackAttachmentMeta(encoded) {
        const combined = b64urlDecodeLarge(encoded);
        return {
            nonce: combined.subarray(0, 12),
            ciphertext: combined.subarray(12),
        };
    }

    function sanitizeFilename(value) {
        if (typeof value !== 'string' || value.trim() === '') {
            return 'attachment';
        }
        let cleaned = '';
        for (let i = 0; i < value.length; i += 1) {
            const code = value.charCodeAt(i);
            if (code <= 0x1F || code === 0x7F) {
                continue;
            }
            cleaned += value[i];
        }
        cleaned = cleaned.replace(/[\\/]/g, '_');
        cleaned = cleaned.replace(/\.{2,}/g, '_');
        cleaned = cleaned.replace(/^\.+/, '');
        cleaned = cleaned.trim();
        if (cleaned === '') {
            return 'attachment';
        }
        return cleaned.length > 200 ? cleaned.slice(0, 200) : cleaned;
    }

    const ATTACHMENT_OBJECT_URL_TTL_MS = 5 * 60 * 1000;

    const SAFE_BLOB_MIME_TYPES = new Set([
        'application/pdf',
        'application/zip',
        'image/png',
        'image/jpeg',
        'image/gif',
        'image/webp',
        'text/plain',
    ]);

    function safeBlobType(mime) {
        if (typeof mime === 'string' && SAFE_BLOB_MIME_TYPES.has(mime.toLowerCase())) {
            return mime.toLowerCase();
        }
        return 'application/octet-stream';
    }

    const activeObjectUrls = [];

    function revokeObjectUrl(url) {
        const index = activeObjectUrls.indexOf(url);
        if (index !== -1) {
            activeObjectUrls.splice(index, 1);
        }
        try {
            URL.revokeObjectURL(url);
        } catch (revokeError) {
            void revokeError;
        }
    }

    function isValidBase64Url(text) {
        return typeof text === 'string' && text.length > 0 && BASE64URL_PATTERN.test(text);
    }

    function stringToBytes(value) {
        return new TextEncoder().encode(value);
    }

    function bytesToString(bytes) {
        return new TextDecoder().decode(bytes);
    }

    const LABEL_MAX_LENGTH = 120;

    function sanitizeLabel(value) {
        if (typeof value !== 'string') {
            return '';
        }
        const trimmed = value.trim();
        if (trimmed.length <= LABEL_MAX_LENGTH) {
            return trimmed;
        }
        return trimmed.slice(0, LABEL_MAX_LENGTH);
    }

    function packBundle(label, plaintext) {
        return JSON.stringify({ l: sanitizeLabel(label), t: plaintext });
    }

    function unpackBundle(serialized) {
        const bundle = JSON.parse(serialized);
        if (!bundle || typeof bundle !== 'object') {
            return { label: '', plaintext: '' };
        }
        return {
            label: typeof bundle.l === 'string' ? bundle.l : '',
            plaintext: typeof bundle.t === 'string' ? bundle.t : '',
        };
    }

    const AGENT_REQUEST_VERSION = 1;
    const AGENT_BUNDLE_VERSION = 2;
    const AGENT_PURPOSE_KINDS = ['command', 'env-file', 'file'];
    const AGENT_PURPOSE_MAX_LENGTH = 2000;
    const AGENT_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
    const AGENT_MAX_NAMES = 20;

    function parseAgentRequest(param) {
        if (!isValidBase64Url(param)) {
            return null;
        }
        let parsed;
        try {
            parsed = JSON.parse(bytesToString(b64urlDecode(param)));
        } catch (parseError) {
            return null;
        }
        if (!parsed || typeof parsed !== 'object' || parsed.v !== AGENT_REQUEST_VERSION) {
            return null;
        }
        if (AGENT_PURPOSE_KINDS.indexOf(parsed.k) === -1) {
            return null;
        }
        if (typeof parsed.c !== 'string' || parsed.c === '' || parsed.c.length > AGENT_PURPOSE_MAX_LENGTH) {
            return null;
        }
        if (!Array.isArray(parsed.n) || parsed.n.length === 0 || parsed.n.length > AGENT_MAX_NAMES) {
            return null;
        }
        const names = [];
        for (const name of parsed.n) {
            if (typeof name !== 'string' || !AGENT_NAME_PATTERN.test(name) || names.indexOf(name) !== -1) {
                return null;
            }
            names.push(name);
        }
        if (parsed.k === 'file' && names.length !== 1) {
            return null;
        }
        return { kind: parsed.k, purpose: parsed.c, names: names };
    }

    function agentPurposeText(kind) {
        if (kind === 'env-file') {
            return t('agentPurposeEnvFile');
        }
        if (kind === 'file') {
            return t('agentPurposeFile');
        }
        return t('agentPurposeCommand');
    }

    function renderAgentRequest(root, agentRequest, plaintextInput) {
        const purposeCard = queryRole(root, 'secrets-agent-purpose');
        setText(queryRole(root, 'secrets-agent-purpose-kind'), agentPurposeText(agentRequest.kind));
        setText(queryRole(root, 'secrets-agent-purpose-value'), agentRequest.purpose);
        setHidden(purposeCard, false);

        if (plaintextInput) {
            plaintextInput.removeAttribute('required');
            setHidden(plaintextInput, true);
        }

        const container = queryRole(root, 'secrets-agent-fields');
        if (!container) {
            return [];
        }
        const fields = agentRequest.names.map((name, index) => {
            const field = document.createElement('ec-form-textarea');
            field.setAttribute('name', 'agent-value-' + index);
            field.setAttribute('label', name);
            field.setAttribute('rows', '2');
            field.setAttribute('required', '');
            field.setAttribute('data-role', 'secrets-agent-value');
            field.addEventListener('input', () => setFieldError(field, null));
            container.appendChild(field);
            return { name: name, field: field };
        });
        setHidden(container, false);
        return fields;
    }

    function readAgentValues(agentFields) {
        const values = {};
        for (const entry of agentFields) {
            const value = readValue(entry.field);
            setFieldError(entry.field, null);
            if (!value || value.trim() === '') {
                setFieldError(entry.field, t('agentEnterValue').replace('{name}', entry.name));
                entry.field.focus?.();
                return null;
            }
            values[entry.name] = value;
        }
        return values;
    }

    function packAgentBundle(agentRequest, values) {
        return JSON.stringify({ v: AGENT_BUNDLE_VERSION, k: agentRequest.kind, c: agentRequest.purpose, s: values });
    }

    function showLabelDisplay(root, label) {
        const display = queryRole(root, 'secrets-label-display');
        if (!display) {
            return;
        }
        const safe = typeof label === 'string' ? label.trim() : '';
        if (safe === '') {
            setHidden(display, true);
            setText(display, '');
            return;
        }
        setText(display, t('labelPrefix') + ' ' + safe);
        setHidden(display, false);
    }

    function getFragmentParam(key) {
        const hash = window.location.hash.replace(/^#/, '');
        if (!hash) {
            return null;
        }
        const pairs = hash.split('&');
        for (const pair of pairs) {
            const separatorIndex = pair.indexOf('=');
            if (separatorIndex === -1) {
                continue;
            }
            const currentKey = pair.slice(0, separatorIndex);
            const currentValue = pair.slice(separatorIndex + 1);
            if (currentKey === key) {
                return currentValue;
            }
        }
        return null;
    }

    function buildFragment(pairs) {
        return Object.keys(pairs)
            .map((key) => encodeURIComponent(key) + '=' + encodeURIComponent(pairs[key]))
            .join('&');
    }

    function prefersReducedMotion() {
        return typeof window.matchMedia === 'function'
            && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }

    function scrollTo(element) {
        if (!element) {
            return;
        }
        element.scrollIntoView({
            behavior: prefersReducedMotion() ? 'auto' : 'smooth',
            block: 'nearest',
        });
    }

    async function generateAesKey() {
        return window.crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt'],
        );
    }

    async function exportAesKey(key) {
        const raw = await window.crypto.subtle.exportKey('raw', key);
        return new Uint8Array(raw);
    }

    async function importAesKey(bytes) {
        return window.crypto.subtle.importKey(
            'raw',
            bytes,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt'],
        );
    }

    async function aesDecrypt(key, ciphertextBytes, nonceBytes) {
        const plain = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonceBytes },
            key,
            ciphertextBytes,
        );
        return new Uint8Array(plain);
    }

    async function generateX25519Keypair() {
        const pair = await window.crypto.subtle.generateKey(
            { name: 'X25519' },
            true,
            ['deriveBits'],
        );
        const publicRaw = await window.crypto.subtle.exportKey('raw', pair.publicKey);
        const privatePkcs8 = await window.crypto.subtle.exportKey('pkcs8', pair.privateKey);
        return {
            publicKey: new Uint8Array(publicRaw),
            privateKey: new Uint8Array(privatePkcs8),
            cryptoKey: pair.privateKey,
        };
    }

    const PBKDF2_ITERATIONS = 1200000;
    const PBKDF2_SALT_BYTES = 16;

    async function derivePbkdf2Bits(password, saltBytes, iterations) {
        const baseKey = await window.crypto.subtle.importKey(
            'raw',
            stringToBytes(password),
            { name: 'PBKDF2' },
            false,
            ['deriveBits'],
        );
        const bits = await window.crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: saltBytes,
                iterations: iterations,
                hash: 'SHA-256',
            },
            baseKey,
            256,
        );
        return new Uint8Array(bits);
    }

    function promptForPassword(errorMessage) {
        return new Promise((resolve) => {
            const dialog = document.getElementById('secrets-password-dialog');
            if (!dialog) {
                resolve(null);
                return;
            }
            const input = dialog.querySelector('[data-role="secrets-password-dialog-input"]');
            const unlockButton = dialog.querySelector('[data-role="secrets-password-dialog-unlock"]');
            const cancelButton = dialog.querySelector('[data-role="secrets-password-dialog-cancel"]');
            if (!input || !unlockButton) {
                resolve(null);
                return;
            }

            setFieldError(input, errorMessage || null);

            const cleanup = () => {
                unlockButton.removeEventListener('click', handleUnlock);
                if (cancelButton) {
                    cancelButton.removeEventListener('click', handleCancel);
                }
                dialog.removeEventListener('dialog-close', handleClose);
                input.removeEventListener('keydown', handleKeydown);
            };
            const handleUnlock = () => {
                const value = readValue(input);
                if (!value || value.length === 0) {
                    setFieldError(input, t('pwEnterPassword'));
                    return;
                }
                cleanup();
                dialog.hide();
                resolve(value);
            };
            const handleCancel = () => {
                cleanup();
                resolve(null);
            };
            const handleClose = () => {
                cleanup();
                resolve(null);
            };
            const handleKeydown = (event) => {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    handleUnlock();
                }
            };

            unlockButton.addEventListener('click', handleUnlock);
            if (cancelButton) {
                cancelButton.addEventListener('click', handleCancel);
            }
            dialog.addEventListener('dialog-close', handleClose);
            input.addEventListener('keydown', handleKeydown);

            if (typeof dialog.show === 'function') {
                dialog.show();
            }
            if (typeof input.focus === 'function') {
                input.focus();
            }
        });
    }

    async function decryptWithPasswordLoop(fragmentKeyBytes, saltBytes, iterations, ciphertextBytes, nonceBytes) {
        let lastError = null;
        for (let attempt = 0; attempt < 10; attempt += 1) {
            const password = await promptForPassword(lastError);
            if (password === null) {
                return null;
            }
            try {
                const pbkdfBits = await derivePbkdf2Bits(password, saltBytes, iterations);
                const aesKey = await deriveMixedAesKey(fragmentKeyBytes, pbkdfBits);
                const plaintextBytes = await aesDecrypt(aesKey, ciphertextBytes, nonceBytes);
                return { bundle: unpackBundle(bytesToString(plaintextBytes)), aesKey: aesKey };
            } catch (decryptError) {
                lastError = t('pwWrong');
            }
        }
        return null;
    }

    async function deriveMixedAesKey(fragmentKeyBytes, pbkdfBits) {
        const mixed = new Uint8Array(fragmentKeyBytes.length + pbkdfBits.length);
        mixed.set(fragmentKeyBytes, 0);
        mixed.set(pbkdfBits, fragmentKeyBytes.length);
        const hkdfKey = await window.crypto.subtle.importKey(
            'raw',
            mixed,
            { name: 'HKDF' },
            false,
            ['deriveKey'],
        );
        return window.crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new Uint8Array(),
                info: stringToBytes('secrets-component:pw-v1:aes-gcm'),
            },
            hkdfKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt'],
        );
    }

    async function importX25519PublicKey(bytes) {
        return window.crypto.subtle.importKey(
            'raw',
            bytes,
            { name: 'X25519' },
            true,
            [],
        );
    }

    async function importX25519PrivateKey(pkcs8Bytes) {
        return window.crypto.subtle.importKey(
            'pkcs8',
            pkcs8Bytes,
            { name: 'X25519' },
            false,
            ['deriveBits'],
        );
    }

    async function deriveSharedAesKey(myPrivateCryptoKey, theirPublicCryptoKey) {
        const sharedBits = await window.crypto.subtle.deriveBits(
            {
                name: 'X25519',
                public: theirPublicCryptoKey,
            },
            myPrivateCryptoKey,
            256,
        );
        const baseKey = await window.crypto.subtle.importKey(
            'raw',
            sharedBits,
            { name: 'HKDF' },
            false,
            ['deriveKey'],
        );
        return window.crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new Uint8Array(),
                info: stringToBytes('secrets-component:x25519-aes-gcm:v1'),
            },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt'],
        );
    }

    async function ecEncryptForRecipient(recipientPublicBytes, plaintextBytes) {
        const recipientKey = await importX25519PublicKey(recipientPublicBytes);
        const ephemeral = await generateX25519Keypair();
        const aesKey = await deriveSharedAesKey(ephemeral.cryptoKey, recipientKey);
        const { ciphertext, nonce } = await aesEncryptWithKey(aesKey, plaintextBytes);
        return {
            ephemeralPublic: ephemeral.publicKey,
            ciphertext: ciphertext,
            nonce: nonce,
            aesKey: aesKey,
        };
    }

    async function aesEncryptWithKey(aesKey, plaintextBytes) {
        const nonce = window.crypto.getRandomValues(new Uint8Array(12));
        const cipher = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce },
            aesKey,
            plaintextBytes,
        );
        return {
            ciphertext: new Uint8Array(cipher),
            nonce: nonce,
        };
    }

    async function ecDecryptFromSender(myPrivatePkcs8Bytes, senderPublicBytes, ciphertextBytes, nonceBytes) {
        const myPrivate = await importX25519PrivateKey(myPrivatePkcs8Bytes);
        const senderPublic = await importX25519PublicKey(senderPublicBytes);
        const aesKey = await deriveSharedAesKey(myPrivate, senderPublic);
        const plain = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonceBytes },
            aesKey,
            ciphertextBytes,
        );
        return {
            plaintext: new Uint8Array(plain),
            aesKey: aesKey,
        };
    }

    async function detectX25519Support() {
        if (!window.crypto || !window.crypto.subtle) {
            return false;
        }
        try {
            await window.crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
            return true;
        } catch (error) {
            return false;
        }
    }

    function unwrapResponse(json) {
        if (json && typeof json === 'object') {
            if (json.success === true && json.data && typeof json.data === 'object') {
                return json.data;
            }
        }
        const error = new Error(extractError(json, 0));
        error.payload = json;
        throw error;
    }

    function extractError(json, status) {
        if (json && typeof json === 'object') {
            if (json.data && typeof json.data === 'object' && typeof json.data.errorMessage === 'string' && json.data.errorMessage !== '') {
                return json.data.errorMessage;
            }
            if (json.formErrors && typeof json.formErrors === 'object') {
                const values = Object.values(json.formErrors).filter((value) => typeof value === 'string' && value !== '');
                if (values.length > 0) {
                    return values.join(' ');
                }
            }
            if (typeof json.errorMessage === 'string' && json.errorMessage !== '') {
                return json.errorMessage;
            }
            if (typeof json.error === 'string' && json.error !== '') {
                return json.error;
            }
        }
        if (status > 0) {
            return t('requestFailed') + ' (' + status + ').';
        }
        return t('fallbackError');
    }

    async function apiPost(path, body) {
        const eh = getEHelper();
        if (!eh || typeof eh.post !== 'function') {
            throw new Error(t('bootUnavailableMessage'));
        }
        let response;
        try {
            response = await eh.post(path, body || {});
        } catch (networkError) {
            throw new Error(t('networkError'), { cause: networkError });
        }

        let json;
        try {
            json = await response.json();
        } catch {
            json = null;
        }

        if (!response.ok) {
            const error = new Error(extractError(json, response.status));
            error.status = response.status;
            error.payload = json;
            throw error;
        }

        return unwrapResponse(json);
    }

    async function apiGet(path) {
        let response;
        try {
            response = await fetch(path, {
                method: 'GET',
                credentials: 'same-origin',
                headers: { Accept: 'application/json' },
            });
        } catch (networkError) {
            throw new Error(t('networkError'), { cause: networkError });
        }

        let json;
        try {
            json = await response.json();
        } catch {
            json = null;
        }

        if (!response.ok) {
            const error = new Error(extractError(json, response.status));
            error.status = response.status;
            error.payload = json;
            throw error;
        }

        return unwrapResponse(json);
    }

    function queryRole(host, role) {
        if (!host) {
            return null;
        }
        return host.querySelector('[data-role="' + role + '"]');
    }

    function setHidden(element, hidden) {
        if (!element) {
            return;
        }
        if (hidden) {
            element.setAttribute('data-hidden', 'true');
        } else {
            element.removeAttribute('data-hidden');
        }
    }

    function isHidden(element) {
        return element ? element.hasAttribute('data-hidden') : true;
    }

    function setText(element, value) {
        if (!element) {
            return;
        }
        if (element.textContent === value) {
            return;
        }
        element.textContent = value;
    }

    function setButtonLoading(button, isLoading) {
        if (!button) {
            return;
        }
        if (isLoading) {
            button.setAttribute('loading', '');
            button.setAttribute('disabled', '');
        } else {
            button.removeAttribute('loading');
            button.removeAttribute('disabled');
        }
    }

    function isBusy(button) {
        return button ? button.hasAttribute('loading') : false;
    }

    function setFieldError(field, message) {
        if (!field) {
            return;
        }
        if (message) {
            field.setAttribute('error', message);
        } else {
            field.removeAttribute('error');
        }
    }

    function readValue(component) {
        if (!component) {
            return '';
        }
        if (typeof component.value === 'string' || typeof component.value === 'number') {
            return String(component.value);
        }
        const nested = component.shadowRoot && component.shadowRoot.querySelector('input, textarea, select');
        if (nested) {
            return nested.value || '';
        }
        const fallback = component.querySelector && component.querySelector('input, textarea, select');
        return fallback ? fallback.value : '';
    }

    function readTtlValue(root, fallbackSeconds) {
        const selectComponent = queryRole(root, 'secrets-ttl');
        if (selectComponent) {
            const raw = readValue(selectComponent);
            if (raw) {
                return raw;
            }
        }
        const activeChip = root.querySelector('[data-role="secrets-ttl-chip"][aria-checked="true"]');
        if (activeChip) {
            const ttl = activeChip.getAttribute('data-ttl');
            if (ttl) {
                return ttl;
            }
        }
        return String(fallbackSeconds);
    }

    function applyTtlPrefill(root) {
        const ttlParam = getFragmentParam('t');
        if (!ttlParam || !/^[0-9]{1,8}$/.test(ttlParam)) {
            return;
        }
        const chips = root.querySelectorAll('[data-role="secrets-ttl-chip"]');
        if (!chips || chips.length === 0) {
            return;
        }
        let requested = null;
        chips.forEach((chip) => {
            if (chip.getAttribute('data-ttl') === ttlParam) {
                requested = chip;
            }
        });
        if (requested === null) {
            return;
        }
        chips.forEach((chip) => {
            chip.setAttribute('aria-checked', chip === requested ? 'true' : 'false');
        });
    }

    function wireTtlChips(root) {
        const chips = root.querySelectorAll('[data-role="secrets-ttl-chip"]');
        if (!chips || chips.length === 0) {
            return;
        }
        chips.forEach((chip) => {
            chip.addEventListener('click', () => {
                chips.forEach((other) => {
                    other.setAttribute('aria-checked', other === chip ? 'true' : 'false');
                });
            });
            chip.addEventListener('keydown', (event) => {
                if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') {
                    return;
                }
                event.preventDefault();
                const chipList = Array.from(chips);
                const currentIndex = chipList.indexOf(chip);
                if (currentIndex === -1) {
                    return;
                }
                const delta = event.key === 'ArrowRight' ? 1 : -1;
                const nextIndex = (currentIndex + delta + chipList.length) % chipList.length;
                const next = chipList[nextIndex];
                next.focus();
                next.click();
            });
        });
    }

    function flashCopyFeedback(button) {
        if (!button || !button.classList) {
            return;
        }
        button.classList.add('copied');
        if (button._copyResetTimer) {
            window.clearTimeout(button._copyResetTimer);
        }
        button._copyResetTimer = window.setTimeout(() => {
            button.classList.remove('copied');
            button._copyResetTimer = null;
        }, 2000);
    }

    function markRevealed(root) {
        const icon = queryRole(root, 'secrets-reveal-icon');
        if (icon && icon.classList) {
            icon.classList.add('revealed');
            const iconInner = icon.querySelector('ec-fa-icon');
            if (iconInner) {
                iconInner.setAttribute('icon', 'lock-open');
            }
        }
    }

    async function copyToClipboard(text) {
        if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            try {
                await navigator.clipboard.writeText(text);
                return { success: true, usedClipboardApi: true };
            } catch (clipboardError) {
                return { success: false, usedClipboardApi: false };
            }
        }
        return { success: false, usedClipboardApi: false };
    }

    async function copyLinkToClipboard(text) {
        const result = await copyToClipboard(text);
        if (result.success) {
            return true;
        }
        const holder = document.createElement('textarea');
        holder.value = text;
        holder.setAttribute('readonly', '');
        holder.setAttribute('aria-hidden', 'true');
        holder.setAttribute('data-role', 'secrets-clipboard');
        document.body.appendChild(holder);
        holder.select();
        let success;
        try {
            success = document.execCommand('copy');
        } catch {
            success = false;
        }
        document.body.removeChild(holder);
        return success;
    }

    async function copyPlaintextToClipboard(text) {
        const result = await copyToClipboard(text);
        if (!result.success) {
            return false;
        }
        scheduleClipboardClear();
        return true;
    }

    let clipboardClearTimer = null;

    function scheduleClipboardClear() {
        if (!(navigator.clipboard && typeof navigator.clipboard.writeText === 'function')) {
            return;
        }
        if (clipboardClearTimer !== null) {
            window.clearTimeout(clipboardClearTimer);
        }
        clipboardClearTimer = window.setTimeout(async () => {
            try {
                await navigator.clipboard.writeText('');
                notify(t('clipboardCleared'), false);
            } catch (clearError) {
                void clearError;
            }
            clipboardClearTimer = null;
        }, CLIPBOARD_CLEAR_DELAY_MS);
    }

    window.addEventListener('beforeunload', () => {
        if (clipboardClearTimer !== null) {
            window.clearTimeout(clipboardClearTimer);
            clipboardClearTimer = null;
        }
        while (activeObjectUrls.length > 0) {
            revokeObjectUrl(activeObjectUrls[0]);
        }
    });

    function formatExpiry(expiresAt) {
        if (!expiresAt) {
            return '';
        }
        const date = new Date(expiresAt);
        if (Number.isNaN(date.getTime())) {
            return t('expiresPrefix') + ' ' + expiresAt;
        }
        return t('expiresPrefix') + ' ' + date.toLocaleString(undefined, {
            dateStyle: 'medium',
            timeStyle: 'short',
        });
    }

    function overrideFormSubmit(form, handler) {
        if (!form) {
            return;
        }
        form.handleSubmit = async function () {
            if (this._isSubmitting) {
                return;
            }
            this._isSubmitting = true;
            try {
                await handler();
            } finally {
                this._isSubmitting = false;
            }
        };
    }

    function wireIncompleteLinkRecovery(root, expectedPrefix) {
        const form = queryRole(root, 'secrets-recovery-form');
        if (!form) {
            return;
        }
        const submit = queryRole(root, 'secrets-recovery-submit');
        const input = queryRole(root, 'secrets-recovery-url');
        overrideFormSubmit(form, async () => {
            const raw = readValue(input);
            if (!raw || raw.trim() === '') {
                notify(t('pasteFullUrl'), true);
                return;
            }
            let parsed;
            try {
                parsed = new URL(raw.trim());
            } catch (parseError) {
                notify(t('invalidUrl'), true);
                return;
            }
            if (!parsed.pathname || parsed.pathname.indexOf(expectedPrefix) !== 0) {
                notify(t('urlWrongFormat'), true);
                return;
            }
            if (!parsed.hash || parsed.hash.length < 2) {
                notify(t('urlMissingFragment'), true);
                return;
            }
            setButtonLoading(submit, true);
            const target = parsed.pathname + (parsed.search || '') + parsed.hash;
            window.location.replace(target);
        });
    }

    const STATUS_END_STATES = new Set(['retrieved', 'expired', 'cleaned-up']);
    const SSE_RECONNECT_BASE_MS = 2000;
    const SSE_RECONNECT_MAX_MS = 60000;
    const SSE_RECONNECT_MAX_ATTEMPTS = 12;

    function statusEndpointFor(kind, token) {
        if (kind === 'request') {
            return API_BASE + '/requests/' + token + '/status';
        }
        return API_BASE + '/' + token + '/status';
    }

    function statusChannelFor(kind, token) {
        return (kind === 'request' ? 'secret-request' : 'secret') + ':' + token;
    }

    const PUBLIC_TOKEN_CHANNEL_PATTERN = /^(?:secret|secret-request):/;

    function isFinalValidateRejection(error) {
        return error === 'unauthorized';
    }

    function rejectedChannelState(channel) {
        return PUBLIC_TOKEN_CHANNEL_PATTERN.test(channel) ? 'unavailable' : 'session-expired';
    }

    function statusBadgeText(status) {
        switch (status) {
            case 'fulfilled':
                return t('statusLabelFulfilled');
            case 'retrieved':
                return t('statusLabelRetrieved');
            case 'expired':
                return t('statusLabelExpired');
            case 'cleaned-up':
                return t('statusLabelCleanedUp');
            default:
                return t('statusLabelWaiting');
        }
    }

    function statusMessageText(status, kind) {
        switch (status) {
            case 'fulfilled':
                return t('statusFulfilled');
            case 'retrieved':
                return kind === 'request' ? t('statusRetrievedRequest') : t('statusRetrievedSecret');
            case 'expired':
                return t('statusExpired');
            case 'cleaned-up':
                return t('statusCleanedUp');
            default:
                return kind === 'request' ? t('statusWaitingRequest') : t('statusWaitingSecret');
        }
    }

    function formatStatusTime(value) {
        if (!value) {
            return '';
        }
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
            return value;
        }
        return date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
    }

    function renderStatusInto(card, kind, payload) {
        const status = payload.status;
        const badge = queryRole(card, 'secrets-status-badge');
        if (badge) {
            badge.setAttribute('data-status', status);
            setText(badge, statusBadgeText(status));
        }
        const message = queryRole(card, 'secrets-status-message');
        if (message) {
            setText(message, statusMessageText(status, kind));
        }
        const createdField = queryRole(card, 'secrets-status-created');
        if (createdField) {
            setText(createdField, formatStatusTime(payload.created_at));
        }
        const expiresLabel = queryRole(card, 'secrets-status-expires-label');
        const expiresField = queryRole(card, 'secrets-status-expires');
        const showExpires = !!payload.expires_at;
        if (expiresLabel) {
            setHidden(expiresLabel, !showExpires);
        }
        if (expiresField) {
            setHidden(expiresField, !showExpires);
            setText(expiresField, payload.expires_at ? formatStatusTime(payload.expires_at) : '');
        }
        if (kind === 'request') {
            const fulfilledLabel = queryRole(card, 'secrets-status-fulfilled-label');
            const fulfilledField = queryRole(card, 'secrets-status-fulfilled');
            const showFulfilled = !!payload.fulfilled_at;
            if (fulfilledLabel) {
                setHidden(fulfilledLabel, !showFulfilled);
            }
            if (fulfilledField) {
                setHidden(fulfilledField, !showFulfilled);
                setText(fulfilledField, payload.fulfilled_at ? formatStatusTime(payload.fulfilled_at) : '');
            }
        }
        const retrievedLabel = queryRole(card, 'secrets-status-retrieved-label');
        const retrievedField = queryRole(card, 'secrets-status-retrieved');
        const showRetrieved = !!payload.retrieved_at;
        if (retrievedLabel) {
            setHidden(retrievedLabel, !showRetrieved);
        }
        if (retrievedField) {
            setHidden(retrievedField, !showRetrieved);
            setText(retrievedField, payload.retrieved_at ? formatStatusTime(payload.retrieved_at) : '');
        }
    }

    const STATUS_CHANNEL_LABEL_KEYS = {
        live: 'statusLive',
        connecting: 'statusConnecting',
        offline: 'statusOffline',
        'session-expired': 'statusSessionExpired',
        unavailable: 'statusUnavailable',
    };

    function setStatusChannelLabel(card, channel) {
        const label = queryRole(card, 'secrets-status-channel');
        if (!label) {
            return;
        }
        label.setAttribute('data-channel', channel);
        const labelKey = STATUS_CHANNEL_LABEL_KEYS[channel];
        setText(label, labelKey ? t(labelKey) : '');
    }

    function attachStatusTracker(card, token, kind) {
        const tracker = card ? card.querySelector('[data-role="secrets-status-tracker"]') : null;
        if (!tracker || !token || !kind) {
            return;
        }
        setHidden(tracker, false);

        const channel = statusChannelFor(kind, token);
        let endStateReached = false;
        let reconnectTimer = null;
        let eventSource = null;
        let inFlight = false;
        let attempts = 0;
        let stopped = false;
        let failureReported = false;
        let deniedReached = false;
        const abortController = (typeof window.AbortController === 'function') ? new window.AbortController() : null;

        const stopAll = () => {
            stopped = true;
            if (reconnectTimer !== null) {
                window.clearTimeout(reconnectTimer);
                reconnectTimer = null;
            }
            if (eventSource) {
                try { eventSource.close(); } catch (closeError) { void closeError; }
                eventSource = null;
            }
            if (abortController) {
                try { abortController.abort(); } catch (abortError) { void abortError; }
            }
        };

        const handlePayload = (payload) => {
            if (!payload || typeof payload !== 'object') {
                return;
            }
            renderStatusInto(tracker, kind, payload);
            if (STATUS_END_STATES.has(payload.status)) {
                endStateReached = true;
                setStatusChannelLabel(tracker, 'ended');
                stopAll();
            }
        };

        const fetchStatus = async () => {
            if (endStateReached || inFlight) {
                return;
            }
            inFlight = true;
            try {
                const response = await fetch(statusEndpointFor(kind, token), {
                    method: 'GET',
                    credentials: 'same-origin',
                    headers: { 'Accept': 'application/json' },
                });
                if (response.status === 404) {
                    handlePayload({
                        status: 'cleaned-up',
                        kind: kind,
                        created_at: null,
                        expires_at: null,
                        fulfilled_at: null,
                        retrieved_at: null,
                    });
                    return;
                }
                if (!response.ok) {
                    return;
                }
                const json = await response.json();
                const data = (json && json.data) ? json.data : json;
                handlePayload(data);
            } catch (fetchError) {
                void fetchError;
            } finally {
                inFlight = false;
            }
        };

        const giveUp = (reason) => {
            if (!failureReported) {
                failureReported = true;
                reportSseError('Secrets status stream gave up for a ' + kind + ': ' + reason);
            }
            setStatusChannelLabel(tracker, 'offline');
            stopAll();
        };

        const stopRejected = () => {
            deniedReached = true;
            setStatusChannelLabel(tracker, rejectedChannelState(channel));
            if (reconnectTimer !== null) {
                window.clearTimeout(reconnectTimer);
                reconnectTimer = null;
            }
            if (eventSource) {
                try { eventSource.close(); } catch (closeError) { void closeError; }
                eventSource = null;
            }
        };

        const scheduleReconnect = (reason) => {
            if (stopped || endStateReached || reconnectTimer !== null) {
                return;
            }
            if (attempts >= SSE_RECONNECT_MAX_ATTEMPTS) {
                giveUp(reason);
                return;
            }
            setStatusChannelLabel(tracker, 'connecting');
            const delay = Math.min(SSE_RECONNECT_BASE_MS * Math.pow(2, attempts), SSE_RECONNECT_MAX_MS);
            attempts += 1;
            reconnectTimer = window.setTimeout(() => {
                reconnectTimer = null;
                openEventSource();
            }, delay);
        };

        const openEventSource = async () => {
            if (stopped || endStateReached || deniedReached) {
                return;
            }
            if (typeof window.EventSource !== 'function') {
                giveUp('this browser has no EventSource');
                return;
            }
            const validateBody = new FormData();
            validateBody.append('channels[]', channel);
            try {
                const validateResponse = await fetch(PROJECT_PREFIX + '/api/sse/validate', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Accept': 'application/json' },
                    body: validateBody,
                });
                if (!validateResponse.ok) {
                    scheduleReconnect('validate responded ' + validateResponse.status);
                    return;
                }
                const validateJson = await validateResponse.json();
                const validatePayload = (validateJson && validateJson.data) ? validateJson.data : validateJson;
                if (!validatePayload || !validatePayload.success) {
                    const rejection = validatePayload ? validatePayload.error : null;
                    if (isFinalValidateRejection(rejection)) {
                        stopRejected();
                        return;
                    }
                    scheduleReconnect('validate rejected the channel: ' + (rejection || 'unknown'));
                    return;
                }
            } catch (validateError) {
                scheduleReconnect('validate request failed: ' + (validateError && validateError.name ? validateError.name : 'unknown'));
                return;
            }

            if (stopped || endStateReached || deniedReached) {
                return;
            }

            const streamUrl = PROJECT_PREFIX + '/api/sse?channels=' + encodeURIComponent(channel);
            try {
                eventSource = new window.EventSource(streamUrl);
            } catch (esError) {
                scheduleReconnect('EventSource constructor failed: ' + (esError && esError.name ? esError.name : 'unknown'));
                return;
            }

            eventSource.addEventListener('open', () => {
                attempts = 0;
                setStatusChannelLabel(tracker, 'live');
            });
            eventSource.addEventListener('status', (event) => {
                try {
                    const data = JSON.parse(event.data);
                    handlePayload(data);
                } catch (parseError) {
                    void parseError;
                }
            });
            eventSource.addEventListener('error', () => {
                if (endStateReached) {
                    stopAll();
                    return;
                }
                if (eventSource && eventSource.readyState === window.EventSource.CLOSED) {
                    try { eventSource.close(); } catch (closeError) { void closeError; }
                    eventSource = null;
                    scheduleReconnect('stream closed by the server');
                }
            });
        };

        const listenerOptions = abortController ? { signal: abortController.signal } : undefined;

        document.addEventListener('visibilitychange', () => {
            if (endStateReached || stopped) {
                return;
            }
            if (document.visibilityState !== 'visible') {
                return;
            }
            fetchStatus();
            if (deniedReached) {
                deniedReached = false;
                attempts = 0;
                setStatusChannelLabel(tracker, 'connecting');
                openEventSource();
            }
        }, listenerOptions);

        window.addEventListener('beforeunload', stopAll, listenerOptions);

        fetchStatus().then(() => {
            if (!endStateReached) {
                openEventSource();
            }
        });
    }

    const ATTACHMENT_HARD_CAP_BYTES = 10485760;

    function readMaxAttachmentBytes(attachmentInput) {
        const attr = attachmentInput.getAttribute('data-secrets-max-attachment');
        const parsed = attr ? parseInt(attr, 10) : 0;
        if (!Number.isFinite(parsed) || parsed <= 0) {
            return 0;
        }
        return Math.min(parsed, ATTACHMENT_HARD_CAP_BYTES);
    }

    async function buildAttachmentFields(attachmentInput, encryptionKey) {
        if (!attachmentInput) {
            return null;
        }
        const maxBytes = readMaxAttachmentBytes(attachmentInput);
        if (maxBytes <= 0) {
            return null;
        }
        const files = attachmentInput.files;
        if (!files || files.length === 0) {
            return null;
        }
        const file = files[0];
        if (file.size > maxBytes) {
            setFieldError(attachmentInput, t('attachmentTooLarge'));
            return false;
        }
        const buffer = await file.arrayBuffer();
        const fileBytes = new Uint8Array(buffer);
        const fileEncrypted = await aesEncryptWithKey(encryptionKey, fileBytes);
        const metaJson = JSON.stringify({ n: file.name, m: file.type || 'application/octet-stream' });
        const metaEncrypted = await aesEncryptWithKey(encryptionKey, stringToBytes(metaJson));
        return {
            attachment_ciphertext: b64urlEncodeLarge(fileEncrypted.ciphertext),
            attachment_nonce: b64urlEncode(fileEncrypted.nonce),
            attachment_meta: packAttachmentMeta(metaEncrypted.nonce, metaEncrypted.ciphertext),
        };
    }

    async function renderAttachment(root, data, aesKey) {
        const container = queryRole(root, 'secrets-attachment-download');
        if (!container) {
            return;
        }
        const cipherB64 = data.attachment_ciphertext;
        const nonceB64 = data.attachment_nonce;
        const metaB64 = data.attachment_meta;
        if (!isValidBase64Url(cipherB64) || !isValidBase64Url(nonceB64) || !isValidBase64Url(metaB64)) {
            return;
        }
        let meta;
        let fileBytes;
        try {
            const metaPacked = unpackAttachmentMeta(metaB64);
            const metaBytes = await aesDecrypt(aesKey, metaPacked.ciphertext, metaPacked.nonce);
            meta = JSON.parse(bytesToString(metaBytes));
            const cipherBytes = b64urlDecodeLarge(cipherB64);
            const nonceBytes = b64urlDecode(nonceB64);
            fileBytes = await aesDecrypt(aesKey, cipherBytes, nonceBytes);
        } catch (attachmentError) {
            void attachmentError;
            notify(t('attachmentDecryptFailed'), true);
            return;
        }
        const filename = sanitizeFilename(meta && meta.n);
        const blob = new Blob([fileBytes], { type: safeBlobType(meta && meta.m) });
        while (activeObjectUrls.length > 0) {
            revokeObjectUrl(activeObjectUrls[0]);
        }
        const objectUrl = URL.createObjectURL(blob);
        activeObjectUrls.push(objectUrl);
        window.setTimeout(() => revokeObjectUrl(objectUrl), ATTACHMENT_OBJECT_URL_TTL_MS);

        const link = document.createElement('a');
        link.setAttribute('href', objectUrl);
        link.setAttribute('download', filename);
        link.setAttribute('data-role', 'secrets-attachment-link');

        const button = document.createElement('ec-button');
        button.setAttribute('as', 'span');
        button.setAttribute('contained', '');
        button.setAttribute('primary', '');
        button.setAttribute('full', '');
        const icon = document.createElement('ec-fa-icon');
        icon.setAttribute('icon', 'download');
        button.appendChild(icon);
        const labelSpan = document.createElement('span');
        labelSpan.textContent = t('attachmentDownload') + ' (' + filename + ')';
        button.appendChild(labelSpan);
        link.appendChild(button);

        link.addEventListener('click', () => {
            window.setTimeout(() => revokeObjectUrl(objectUrl), 60000);
        });

        container.replaceChildren(link);
        setHidden(container, false);
    }

    function initSendPage(root) {
        const form = queryRole(root, 'secrets-form');
        const submit = queryRole(root, 'secrets-submit');
        const plaintextInput = queryRole(root, 'secrets-plaintext');
        const attachmentInput = queryRole(root, 'secrets-attachment');
        const labelInput = queryRole(root, 'secrets-label');
        const passwordInput = queryRole(root, 'secrets-password');
        const resultCard = queryRole(root, 'secrets-result');
        const linkDisplay = queryRole(root, 'secrets-link-display');
        const expiryDisplay = queryRole(root, 'secrets-expiry');
        const copyButton = queryRole(root, 'secrets-copy');
        const advancedContainer = queryRole(root, 'secrets-advanced');
        const advancedToggle = queryRole(root, 'secrets-advanced-toggle');

        wireTtlChips(root);
        applyTtlPrefill(root);

        if (advancedToggle && advancedContainer) {
            advancedToggle.addEventListener('click', () => {
                setHidden(advancedContainer, false);
                setHidden(advancedToggle, true);
                advancedToggle.setAttribute('aria-expanded', 'true');
                if (labelInput && typeof labelInput.focus === 'function') {
                    labelInput.focus();
                }
            });
        }

        const prefillLabelParam = getFragmentParam('l');
        if (prefillLabelParam && isValidBase64Url(prefillLabelParam) && labelInput) {
            try {
                const prefillLabel = sanitizeLabel(bytesToString(b64urlDecode(prefillLabelParam)));
                if (prefillLabel !== '') {
                    const applyLabel = () => {
                        try {
                            labelInput.value = prefillLabel;
                        } catch (setterError) {
                            if (window.console && typeof window.console.debug === 'function') {
                                window.console.debug('secrets: label prefill setter failed', setterError && setterError.message);
                            }
                        }
                    };
                    if (window.customElements && typeof window.customElements.whenDefined === 'function') {
                        window.customElements.whenDefined('ec-form-text').then(applyLabel);
                    } else {
                        applyLabel();
                    }
                    if (advancedContainer && advancedToggle) {
                        setHidden(advancedContainer, false);
                        setHidden(advancedToggle, true);
                        advancedToggle.setAttribute('aria-expanded', 'true');
                    }
                }
            } catch (prefillError) {
                void prefillError;
            }
        }

        if (!form || !submit || !plaintextInput) {
            return;
        }

        plaintextInput.addEventListener('input', () => setFieldError(plaintextInput, null));

        if (attachmentInput) {
            attachmentInput.addEventListener('change', () => setFieldError(attachmentInput, null));
        }

        overrideFormSubmit(form, async () => {
            if (isBusy(submit)) {
                return;
            }
            const plaintext = readValue(plaintextInput);
            const label = sanitizeLabel(readValue(labelInput));
            const password = passwordInput ? readValue(passwordInput) : '';
            const ttlRaw = readTtlValue(root, 86400);
            const ttl = parseInt(ttlRaw, 10);

            setFieldError(plaintextInput, null);
            if (!plaintext || plaintext.trim() === '') {
                setFieldError(plaintextInput, t('enterSecretFirst'));
                plaintextInput.focus?.();
                return;
            }
            if (!ttl || ttl <= 0) {
                notify(t('chooseLifetime'), true);
                return;
            }

            setButtonLoading(submit, true);
            try {
                const fragmentAesKey = await generateAesKey();
                const fragmentKeyBytes = await exportAesKey(fragmentAesKey);
                const bundle = packBundle(label, plaintext);

                let encryptionKey = fragmentAesKey;
                let saltParam = null;
                if (password && password.length > 0) {
                    const salt = window.crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_BYTES));
                    const pbkdfBits = await derivePbkdf2Bits(password, salt, PBKDF2_ITERATIONS);
                    encryptionKey = await deriveMixedAesKey(fragmentKeyBytes, pbkdfBits);
                    saltParam = b64urlEncode(salt);
                }

                const { ciphertext, nonce } = await aesEncryptWithKey(encryptionKey, stringToBytes(bundle));

                const requestBody = {
                    ciphertext: b64urlEncode(ciphertext),
                    nonce: b64urlEncode(nonce),
                    ttl_seconds: ttl,
                };

                const attachmentFields = await buildAttachmentFields(attachmentInput, encryptionKey);
                if (attachmentFields === false) {
                    return;
                }
                if (attachmentFields) {
                    Object.assign(requestBody, attachmentFields);
                }

                const data = await apiPost(API_BASE, requestBody);

                const token = data.token;
                if (!token || !BASE64URL_PATTERN.test(token)) {
                    throw new Error(t('serverNoToken'));
                }

                const keyParam = b64urlEncode(fragmentKeyBytes);
                const fragmentPairs = { k: keyParam };
                if (saltParam) {
                    fragmentPairs.s = saltParam;
                    fragmentPairs.i = String(PBKDF2_ITERATIONS);
                }
                const url = APP_ORIGIN + PAGE_BASE + '/view/' + token + '#' + buildFragment(fragmentPairs);

                setText(linkDisplay, url);
                setText(expiryDisplay, formatExpiry(data.expires_at));
                setHidden(resultCard, false);
                if (typeof resultCard.focus === "function") { resultCard.focus(); }
                scrollTo(resultCard);
                attachStatusTracker(resultCard, token, 'secret');
                notify(t('linkCreated'), false);
            } catch (error) {
                notify(error.message || t('fallbackError'), true);
            } finally {
                if (!isHidden(form)) {
                    setButtonLoading(submit, false);
                }
            }
        });

        if (copyButton) {
            copyButton.addEventListener('click', async () => {
                const text = linkDisplay ? linkDisplay.textContent : '';
                if (!text) {
                    return;
                }
                const ok = await copyLinkToClipboard(text);
                if (ok) {
                    flashCopyFeedback(copyButton);
                }
                notify(ok ? t('linkCopied') : t('copyFailedSelectManually'), !ok);
            });
        }
    }

    function initViewPage(root) {
        const token = root.getAttribute('data-secrets-token');
        const revealCard = queryRole(root, 'secrets-reveal-card');
        const revealButton = queryRole(root, 'secrets-reveal');
        const plaintextCard = queryRole(root, 'secrets-plaintext-card');
        const plaintextDisplay = queryRole(root, 'secrets-plaintext-display');
        const fragmentMissing = queryRole(root, 'secrets-fragment-missing');
        const copyButton = queryRole(root, 'secrets-copy-plaintext');

        wireIncompleteLinkRecovery(root, PAGE_BASE + '/view/');

        const keyParam = getFragmentParam('k');
        const saltParam = getFragmentParam('s');
        const itersParam = getFragmentParam('i');
        const needsPassword = saltParam !== null && itersParam !== null;

        if (!token || !isValidBase64Url(keyParam) || (needsPassword && !isValidBase64Url(saltParam))) {
            if (keyParam && !isValidBase64Url(keyParam)) {
                if (typeof window.console !== 'undefined' && typeof window.console.warn === 'function') {
                    window.console.warn('secrets-component: fragment value has invalid format');
                }
                notify(t('incompleteLinkError'), true);
            }
            setHidden(revealCard, true);
            setHidden(fragmentMissing, false);
            return;
        }

        if (!revealButton) {
            return;
        }

        revealButton.addEventListener('click', async () => {
            if (isBusy(revealButton)) {
                return;
            }
            setButtonLoading(revealButton, true);
            let retrievedCiphertext;
            let retrievedNonce;
            try {
                const data = await apiPost(API_BASE + '/' + token + '/retrieve', {});
                const ciphertextB64 = data.ciphertext;
                const nonceB64 = data.nonce;
                if (!isValidBase64Url(ciphertextB64) || !isValidBase64Url(nonceB64)) {
                    throw new Error(t('serverResponseIncomplete'));
                }
                retrievedCiphertext = b64urlDecode(ciphertextB64);
                retrievedNonce = b64urlDecode(nonceB64);
                const fragmentKeyBytes = b64urlDecode(keyParam);

                if (!needsPassword) {
                    const aesKey = await importAesKey(fragmentKeyBytes);
                    const plaintextBytes = await aesDecrypt(aesKey, retrievedCiphertext, retrievedNonce);
                    const bundle = unpackBundle(bytesToString(plaintextBytes));
                    showLabelDisplay(plaintextCard, bundle.label);
                    setText(plaintextDisplay, bundle.plaintext);
                    markRevealed(root);
                    setHidden(revealCard, true);
                    setHidden(plaintextCard, false);
                if (typeof plaintextCard.focus === "function") { plaintextCard.focus(); }
                    scrollTo(plaintextCard);
                    await renderAttachment(root, data, aesKey);
                    return;
                }

                const saltBytes = b64urlDecode(saltParam);
                const iters = parseInt(itersParam, 10);
                if (!Number.isFinite(iters) || iters < 100000 || iters > 2000000) {
                    throw new Error(t('incompleteLinkError'));
                }

                const passwordResult = await decryptWithPasswordLoop(
                    fragmentKeyBytes,
                    saltBytes,
                    iters,
                    retrievedCiphertext,
                    retrievedNonce,
                );
                if (passwordResult === null) {
                    notify(t('retrieveMissingMessage'), true);
                    return;
                }

                const bundle = passwordResult.bundle;
                showLabelDisplay(plaintextCard, bundle.label);
                setText(plaintextDisplay, bundle.plaintext);
                markRevealed(root);
                setHidden(revealCard, true);
                setHidden(plaintextCard, false);
                if (typeof plaintextCard.focus === "function") { plaintextCard.focus(); }
                scrollTo(plaintextCard);
                await renderAttachment(root, data, passwordResult.aesKey);
            } catch (error) {
                const message = error.status === 404
                    ? t('retrieveMissingMessage')
                    : (error.message || t('fallbackError'));
                notify(message, true);
            } finally {
                if (!isHidden(revealCard)) {
                    setButtonLoading(revealButton, false);
                }
            }
        });

        if (copyButton) {
            copyButton.addEventListener('click', async () => {
                const text = plaintextDisplay ? plaintextDisplay.textContent : '';
                if (!text) {
                    return;
                }
                const ok = await copyPlaintextToClipboard(text);
                if (ok) {
                    flashCopyFeedback(copyButton);
                }
                notify(ok ? t('secretCopied') : t('clipboardCopyFailed'), !ok);
            });
        }
    }

    function initRequestPage(root) {
        const form = queryRole(root, 'secrets-form');
        const submit = queryRole(root, 'secrets-submit');
        const labelInput = queryRole(root, 'secrets-label');
        const attachmentsToggle = queryRole(root, 'secrets-attachments-allowed');
        const fulfillCard = queryRole(root, 'secrets-fulfill-card');
        const retrieveCard = queryRole(root, 'secrets-retrieve-card');
        const fulfillLink = queryRole(root, 'secrets-fulfill-link');
        const retrieveLink = queryRole(root, 'secrets-retrieve-link');
        const expiryDisplay = queryRole(root, 'secrets-expiry');
        const copyFulfill = queryRole(root, 'secrets-copy-fulfill');
        const copyRetrieve = queryRole(root, 'secrets-copy-retrieve');

        wireTtlChips(root);

        if (!form || !submit) {
            return;
        }

        overrideFormSubmit(form, async () => {
            if (isBusy(submit)) {
                return;
            }
            const ttlRaw = readTtlValue(root, 86400);
            const ttl = parseInt(ttlRaw, 10);
            const label = sanitizeLabel(readValue(labelInput));

            if (!ttl || ttl <= 0) {
                notify(t('chooseLifetime'), true);
                return;
            }

            const supported = await detectX25519Support();
            if (!supported) {
                notify(t('unsupportedBrowserMessage'), true);
                return;
            }

            setButtonLoading(submit, true);
            try {
                const keypair = await generateX25519Keypair();

                const data = await apiPost(API_BASE + '/requests', {
                    requester_pub: b64urlEncode(keypair.publicKey),
                    ttl_seconds: ttl,
                    attachments_allowed: attachmentsToggle ? attachmentsToggle.checked === true : false,
                });

                const token = data.token;
                if (!token || !BASE64URL_PATTERN.test(token)) {
                    throw new Error(t('serverNoToken'));
                }

                const publicParam = b64urlEncode(keypair.publicKey);
                const privateParam = b64urlEncode(keypair.privateKey);

                const fulfillFragmentPairs = { rp: publicParam };
                if (label !== '') {
                    fulfillFragmentPairs.l = b64urlEncode(stringToBytes(label));
                }

                const fulfillUrl = APP_ORIGIN + PAGE_BASE + '/fulfill/' + token + '#' + buildFragment(fulfillFragmentPairs);
                const retrieveUrl = APP_ORIGIN + PAGE_BASE + '/request/' + token + '/retrieve#' + buildFragment({ p: privateParam });

                setText(fulfillLink, fulfillUrl);
                setText(retrieveLink, retrieveUrl);
                setText(expiryDisplay, formatExpiry(data.expires_at));
                setHidden(fulfillCard, false);
                setHidden(retrieveCard, false);
                if (typeof retrieveCard.focus === "function") { retrieveCard.focus(); }
                scrollTo(fulfillCard);
                attachStatusTracker(retrieveCard, token, 'request');
                notify(t('requestCreated'), false);
            } catch (error) {
                notify(error.message || t('fallbackError'), true);
            } finally {
                if (!isHidden(form)) {
                    setButtonLoading(submit, false);
                }
            }
        });

        if (copyFulfill) {
            copyFulfill.addEventListener('click', async () => {
                const text = fulfillLink ? fulfillLink.textContent : '';
                if (!text) {
                    return;
                }
                const ok = await copyLinkToClipboard(text);
                if (ok) {
                    flashCopyFeedback(copyFulfill);
                }
                notify(ok ? t('senderLinkCopied') : t('copyFailedSelectManually'), !ok);
            });
        }

        if (copyRetrieve) {
            copyRetrieve.addEventListener('click', async () => {
                const text = retrieveLink ? retrieveLink.textContent : '';
                if (!text) {
                    return;
                }
                const ok = await copyLinkToClipboard(text);
                if (ok) {
                    flashCopyFeedback(copyRetrieve);
                }
                notify(ok ? t('retrievalLinkCopied') : t('copyFailedSelectManually'), !ok);
            });
        }
    }

    function formatRemaining(secondsLeft) {
        if (secondsLeft < 60) {
            return null;
        }
        const days = Math.floor(secondsLeft / 86400);
        const hours = Math.floor((secondsLeft % 86400) / 3600);
        const minutes = Math.floor((secondsLeft % 3600) / 60);
        const seconds = secondsLeft % 60;
        const parts = [];
        if (days > 0) {
            parts.push(days + t('countdownUnitDay'));
            parts.push(hours + t('countdownUnitHour'));
        } else if (hours > 0) {
            parts.push(hours + t('countdownUnitHour'));
            parts.push(minutes + t('countdownUnitMinute'));
        } else if (minutes >= 5) {
            parts.push(minutes + t('countdownUnitMinute'));
        } else {
            parts.push(minutes + t('countdownUnitMinute'));
            parts.push(seconds + t('countdownUnitSecond'));
        }
        return parts.join(' ');
    }

    function startCountdown(countdownEl, textEl, expiresAt, onExpired) {
        if (!countdownEl || !textEl) {
            return;
        }
        const expiryDate = new Date(expiresAt);
        if (Number.isNaN(expiryDate.getTime())) {
            return;
        }
        const expiryMs = expiryDate.getTime();
        let timerId = null;
        let currentInterval = null;

        const stop = () => {
            if (timerId !== null) {
                window.clearTimeout(timerId);
                timerId = null;
            }
        };

        const schedule = (delayMs) => {
            stop();
            timerId = window.setTimeout(tick, delayMs);
        };

        const tick = () => {
            const remainingMs = expiryMs - Date.now();
            const secondsLeft = Math.floor(remainingMs / 1000);
            if (secondsLeft <= 0) {
                setText(textEl, t('countdownExpired'));
                countdownEl.setAttribute('data-state', 'expired');
                stop();
                if (typeof onExpired === 'function') {
                    onExpired();
                }
                return;
            }
            const formatted = formatRemaining(secondsLeft);
            if (formatted === null) {
                setText(textEl, t('countdownLessThanMinute'));
                countdownEl.setAttribute('data-state', 'urgent');
            } else {
                setText(textEl, t('countdownExpiresIn').replace('{time}', formatted));
                countdownEl.setAttribute('data-state', secondsLeft < 600 ? 'urgent' : 'normal');
            }
            const nextInterval = secondsLeft < 600 ? 1000 : 30000;
            if (nextInterval !== currentInterval) {
                currentInterval = nextInterval;
            }
            schedule(nextInterval);
        };

        setHidden(countdownEl, false);
        window.addEventListener('beforeunload', stop, { once: true });
        tick();
    }

    function initFulfillPage(root) {
        const token = root.getAttribute('data-secrets-token');
        const requesterPubParam = getFragmentParam('rp');
        const labelParam = getFragmentParam('l');
        const agentParam = getFragmentParam('a');
        const form = queryRole(root, 'secrets-form');
        const formCard = queryRole(root, 'secrets-form-card');
        const successCard = queryRole(root, 'secrets-success-card');
        const fragmentMissing = queryRole(root, 'secrets-fragment-missing');
        const requestContext = queryRole(root, 'secrets-request-context');
        const requestLabel = queryRole(root, 'secrets-request-label');
        const countdownEl = queryRole(root, 'secrets-countdown');
        const countdownText = queryRole(root, 'secrets-countdown-text');
        const expiredCard = queryRole(root, 'secrets-expired-card');
        const submit = queryRole(root, 'secrets-submit');
        const plaintextInput = queryRole(root, 'secrets-plaintext');
        const attachmentSection = queryRole(root, 'secrets-attachment-section');
        const attachmentInput = queryRole(root, 'secrets-attachment');

        wireIncompleteLinkRecovery(root, PAGE_BASE + '/fulfill/');

        if (!token || !isValidBase64Url(requesterPubParam)) {
            if (requesterPubParam && !isValidBase64Url(requesterPubParam)) {
                if (typeof window.console !== 'undefined' && typeof window.console.warn === 'function') {
                    window.console.warn('secrets-component: fragment value has invalid format');
                }
                notify(t('incompleteLinkError'), true);
            }
            setHidden(formCard, true);
            setHidden(fragmentMissing, false);
            return;
        }

        const agentRequest = agentParam !== null ? parseAgentRequest(agentParam) : null;
        if (agentParam !== null && agentRequest === null) {
            if (typeof window.console !== 'undefined' && typeof window.console.warn === 'function') {
                window.console.warn('secrets-component: agent request in the fragment has an invalid format');
            }
            notify(t('incompleteLinkError'), true);
            setHidden(formCard, true);
            setHidden(fragmentMissing, false);
            return;
        }
        const agentFields = agentRequest !== null ? renderAgentRequest(root, agentRequest, plaintextInput) : [];

        if (labelParam && isValidBase64Url(labelParam) && requestLabel && requestContext) {
            try {
                const decoded = sanitizeLabel(bytesToString(b64urlDecode(labelParam)));
                if (decoded !== '') {
                    setText(requestLabel, decoded);
                    setHidden(requestContext, false);
                }
            } catch (labelError) {
                void labelError;
            }
        }

        if (labelParam && isValidBase64Url(labelParam)) {
            const expiredSendLink = queryRole(root, 'secrets-expired-send-link');
            if (expiredSendLink) {
                const baseHref = expiredSendLink.getAttribute('href') || (PAGE_BASE + '/send');
                expiredSendLink.setAttribute('href', baseHref + '#l=' + labelParam);
            }
        }

        const lockFormOnExpiry = () => {
            setHidden(formCard, true);
            setHidden(expiredCard, false);
        };

        apiGet(API_BASE + '/requests/' + token + '/status').then((status) => {
            if (!status || !status.expires_at) {
                return;
            }
            if (status.status === 'expired' || status.status === 'cleaned-up') {
                lockFormOnExpiry();
                return;
            }
            startCountdown(countdownEl, countdownText, status.expires_at, lockFormOnExpiry);
        }).catch((statusError) => {
            if (window.console && typeof window.console.debug === 'function') {
                window.console.debug('secrets: status fetch failed, countdown unavailable', statusError && statusError.message);
            }
        });

        if (attachmentInput) {
            const applyAttachmentCap = (request) => {
                const cap = request ? parseInt(request.max_attachment_bytes, 10) : 0;
                if (!Number.isFinite(cap) || cap <= 0) {
                    return;
                }
                attachmentInput.setAttribute('data-secrets-max-attachment', String(Math.min(cap, ATTACHMENT_HARD_CAP_BYTES)));
                setHidden(attachmentSection, false);
            };

            apiGet(API_BASE + '/requests/' + token)
                .then(applyAttachmentCap)
                .catch(() => apiGet(API_BASE + '/requests/' + token).then(applyAttachmentCap))
                .catch((capError) => {
                    if (window.console && typeof window.console.debug === 'function') {
                        window.console.debug('secrets: attachment cap unavailable', capError && capError.message);
                    }
                    notify(t('fallbackError'), true);
                });
            attachmentInput.addEventListener('change', () => setFieldError(attachmentInput, null));
        }

        if (!form || !submit || !plaintextInput) {
            return;
        }

        plaintextInput.addEventListener('input', () => setFieldError(plaintextInput, null));

        overrideFormSubmit(form, async () => {
            if (isBusy(submit)) {
                return;
            }
            let bundle;
            if (agentRequest !== null) {
                const agentValues = readAgentValues(agentFields);
                if (agentValues === null) {
                    return;
                }
                bundle = packAgentBundle(agentRequest, agentValues);
            } else {
                const plaintext = readValue(plaintextInput);
                setFieldError(plaintextInput, null);
                if (!plaintext || plaintext.trim() === '') {
                    setFieldError(plaintextInput, t('enterSecretSubmit'));
                    plaintextInput.focus?.();
                    return;
                }
                bundle = packBundle('', plaintext);
            }

            const supported = await detectX25519Support();
            if (!supported) {
                notify(t('unsupportedBrowserMessage'), true);
                return;
            }

            setButtonLoading(submit, true);
            try {
                const verification = await apiGet(API_BASE + '/requests/' + token);
                if (!verification || verification.requester_pub !== requesterPubParam) {
                    throw new Error(t('linkTampered'));
                }

                const requesterPub = b64urlDecode(requesterPubParam);
                const encrypted = await ecEncryptForRecipient(requesterPub, stringToBytes(bundle));

                const fulfillBody = {
                    filler_pub: b64urlEncode(encrypted.ephemeralPublic),
                    ciphertext: b64urlEncode(encrypted.ciphertext),
                    nonce: b64urlEncode(encrypted.nonce),
                };

                const attachmentFields = await buildAttachmentFields(attachmentInput, encrypted.aesKey);
                if (attachmentFields === false) {
                    return;
                }
                if (attachmentFields) {
                    Object.assign(fulfillBody, attachmentFields);
                }

                await apiPost(API_BASE + '/requests/' + token + '/fulfill', fulfillBody);

                setHidden(formCard, true);
                setHidden(successCard, false);
                if (typeof successCard.focus === "function") { successCard.focus(); }
                scrollTo(successCard);
            } catch (error) {
                const message = error.status === 404
                    ? t('fulfillMissingMessage')
                    : (error.message || t('fallbackError'));
                notify(message, true);
            } finally {
                if (!isHidden(formCard)) {
                    setButtonLoading(submit, false);
                }
            }
        });
    }

    function initRetrievePage(root) {
        const token = root.getAttribute('data-secrets-token');
        const privateParam = getFragmentParam('p');
        const revealCard = queryRole(root, 'secrets-reveal-card');
        const revealButton = queryRole(root, 'secrets-reveal');
        const plaintextCard = queryRole(root, 'secrets-plaintext-card');
        const plaintextDisplay = queryRole(root, 'secrets-plaintext-display');
        const fragmentMissing = queryRole(root, 'secrets-fragment-missing');
        const copyButton = queryRole(root, 'secrets-copy-plaintext');

        wireIncompleteLinkRecovery(root, PAGE_BASE + '/request/');

        attachStatusTracker(root, token, 'request');

        if (!token || !isValidBase64Url(privateParam)) {
            if (privateParam && !isValidBase64Url(privateParam)) {
                if (typeof window.console !== 'undefined' && typeof window.console.warn === 'function') {
                    window.console.warn('secrets-component: fragment value has invalid format');
                }
                notify(t('incompleteLinkError'), true);
            }
            setHidden(revealCard, true);
            setHidden(fragmentMissing, false);
            return;
        }

        if (!revealButton) {
            return;
        }

        revealButton.addEventListener('click', async () => {
            if (isBusy(revealButton)) {
                return;
            }
            setButtonLoading(revealButton, true);
            try {
                const supported = await detectX25519Support();
                if (!supported) {
                    throw new Error(t('unsupportedBrowserMessage'));
                }

                const data = await apiPost(API_BASE + '/requests/' + token + '/fulfillment/retrieve', {});
                const fillerPubB64 = data.filler_pub;
                const ciphertextB64 = data.ciphertext;
                const nonceB64 = data.nonce;
                if (!isValidBase64Url(fillerPubB64) || !isValidBase64Url(ciphertextB64) || !isValidBase64Url(nonceB64)) {
                    throw new Error(t('serverResponseIncomplete'));
                }

                const privateBytes = b64urlDecode(privateParam);
                const fillerPub = b64urlDecode(fillerPubB64);
                const ciphertext = b64urlDecode(ciphertextB64);
                const nonce = b64urlDecode(nonceB64);
                const decrypted = await ecDecryptFromSender(privateBytes, fillerPub, ciphertext, nonce);

                const bundle = unpackBundle(bytesToString(decrypted.plaintext));
                setText(plaintextDisplay, bundle.plaintext);
                markRevealed(root);
                setHidden(revealCard, true);
                setHidden(plaintextCard, false);
                if (typeof plaintextCard.focus === "function") { plaintextCard.focus(); }
                scrollTo(plaintextCard);
                await renderAttachment(root, data, decrypted.aesKey);
            } catch (error) {
                const message = error.status === 404
                    ? t('retrieveMissingMessage')
                    : (error.message || t('fallbackError'));
                notify(message, true);
            } finally {
                if (!isHidden(revealCard)) {
                    setButtonLoading(revealButton, false);
                }
            }
        });

        if (copyButton) {
            copyButton.addEventListener('click', async () => {
                const text = plaintextDisplay ? plaintextDisplay.textContent : '';
                if (!text) {
                    return;
                }
                const ok = await copyPlaintextToClipboard(text);
                if (ok) {
                    flashCopyFeedback(copyButton);
                }
                notify(ok ? t('secretCopied') : t('clipboardCopyFailed'), !ok);
            });
        }
    }

    const pageHandlers = {
        send: initSendPage,
        view: initViewPage,
        request: initRequestPage,
        fulfill: initFulfillPage,
        retrieve: initRetrievePage,
    };

    function disableInteractiveControls(host) {
        const forms = host.querySelectorAll('[data-role="secrets-form"], [data-role="secrets-recovery-form"]');
        forms.forEach((form) => {
            form.handleSubmit = async function () {
                notify(t('bootUnavailableMessage'), true);
            };
        });
        const buttons = host.querySelectorAll('[data-role="secrets-reveal"], [data-role="secrets-submit"], [data-role="secrets-recovery-submit"]');
        buttons.forEach((button) => {
            button.setAttribute('disabled', '');
        });
    }

    function parseAttributeMap(container, attribute) {
        const raw = container.getAttribute(attribute);
        if (!raw) {
            return {};
        }
        try {
            const parsed = JSON.parse(raw);
            return (parsed && typeof parsed === 'object') ? parsed : {};
        } catch (parseError) {
            return {};
        }
    }

    function subscribeStatusChannel(channel, eventType, onPayload, onConnection) {
        const notifyConnection = (state) => {
            if (typeof onConnection === 'function') {
                onConnection(state);
            }
        };

        if (typeof window.EventSource !== 'function') {
            notifyConnection('gave_up');
            reportSseError('Secrets status list stream unavailable: this browser has no EventSource');
            return;
        }

        const streamUrl = PROJECT_PREFIX + '/api/sse?channels=' + encodeURIComponent(channel);
        const abortController = (typeof window.AbortController === 'function') ? new window.AbortController() : null;
        const listenerOptions = abortController ? { signal: abortController.signal } : { once: true };

        let eventSource = null;
        let reconnectTimer = null;
        let attempts = 0;
        let stopped = false;
        let failureReported = false;
        let deniedReached = false;

        const closeSource = () => {
            if (eventSource) {
                try { eventSource.close(); } catch (closeError) { void closeError; }
                eventSource = null;
            }
        };

        const stop = () => {
            stopped = true;
            if (reconnectTimer !== null) {
                window.clearTimeout(reconnectTimer);
                reconnectTimer = null;
            }
            closeSource();
            if (abortController) {
                try { abortController.abort(); } catch (abortError) { void abortError; }
            }
        };

        const stopRejected = () => {
            deniedReached = true;
            if (reconnectTimer !== null) {
                window.clearTimeout(reconnectTimer);
                reconnectTimer = null;
            }
            closeSource();
            notifyConnection(rejectedChannelState(channel));
        };

        const validateChannel = async () => {
            const validateBody = new FormData();
            validateBody.append('channels[]', channel);
            try {
                const validateResponse = await fetch(PROJECT_PREFIX + '/api/sse/validate', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Accept': 'application/json' },
                    body: validateBody,
                });
                if (!validateResponse.ok) {
                    return { ok: false, final: false, reason: 'validate responded ' + validateResponse.status };
                }
                const validateJson = await validateResponse.json();
                const validatePayload = (validateJson && validateJson.data) ? validateJson.data : validateJson;
                if (validatePayload && validatePayload.success) {
                    return { ok: true, final: false, reason: '' };
                }
                const rejection = validatePayload ? validatePayload.error : null;
                return {
                    ok: false,
                    final: isFinalValidateRejection(rejection),
                    reason: 'validate rejected the channel: ' + (rejection || 'unknown'),
                };
            } catch (validateError) {
                return {
                    ok: false,
                    final: false,
                    reason: 'validate request failed: ' + (validateError && validateError.name ? validateError.name : 'unknown'),
                };
            }
        };

        const scheduleReconnect = (reason) => {
            if (stopped || reconnectTimer !== null) {
                return;
            }
            if (attempts >= SSE_RECONNECT_MAX_ATTEMPTS) {
                if (!failureReported) {
                    failureReported = true;
                    reportSseError('Secrets status list stream gave up after ' + attempts + ' attempts: ' + reason);
                }
                notifyConnection('gave_up');
                closeSource();
                return;
            }
            notifyConnection('connecting');
            const delay = Math.min(SSE_RECONNECT_BASE_MS * Math.pow(2, attempts), SSE_RECONNECT_MAX_MS);
            attempts += 1;
            reconnectTimer = window.setTimeout(() => {
                reconnectTimer = null;
                connect();
            }, delay);
        };

        const connect = async () => {
            if (stopped || deniedReached) {
                return;
            }
            const validation = await validateChannel();
            if (!validation.ok) {
                if (validation.final) {
                    stopRejected();
                    return;
                }
                scheduleReconnect(validation.reason);
                return;
            }

            if (stopped || deniedReached) {
                return;
            }
            try {
                eventSource = new window.EventSource(streamUrl);
            } catch (esError) {
                scheduleReconnect('EventSource constructor failed: ' + (esError && esError.name ? esError.name : 'unknown'));
                return;
            }

            eventSource.addEventListener('open', () => {
                attempts = 0;
                notifyConnection('live');
            });
            eventSource.addEventListener(eventType, (event) => {
                try {
                    onPayload(JSON.parse(event.data));
                } catch (parseError) {
                    void parseError;
                }
            });
            eventSource.addEventListener('error', () => {
                if (stopped) {
                    return;
                }
                if (eventSource && eventSource.readyState === window.EventSource.CLOSED) {
                    closeSource();
                    scheduleReconnect('stream closed by the server');
                }
            });
        };

        document.addEventListener('visibilitychange', () => {
            if (stopped || document.visibilityState !== 'visible') {
                return;
            }
            const streamClosed = !eventSource || eventSource.readyState === window.EventSource.CLOSED;
            if (!deniedReached && !streamClosed) {
                validateChannel().then((validation) => {
                    if (stopped || deniedReached || !validation.final) {
                        return;
                    }
                    stopRejected();
                });
                return;
            }
            if (reconnectTimer !== null) {
                window.clearTimeout(reconnectTimer);
                reconnectTimer = null;
            }
            closeSource();
            deniedReached = false;
            attempts = 0;
            notifyConnection('connecting');
            connect();
        }, abortController ? { signal: abortController.signal } : undefined);

        window.addEventListener('beforeunload', stop, listenerOptions);
        notifyConnection('connecting');
        connect();
    }

    const SSE_CONNECTION_LABEL_KEYS = {
        connecting: 'dashboardConnecting',
        live: 'statusLive',
        offline: 'statusOffline',
        gave_up: 'statusOffline',
        'session-expired': 'statusSessionExpired',
        unavailable: 'statusUnavailable',
    };

    function findConnectionIndicator(container) {
        let node = container.parentElement;
        while (node) {
            const indicator = queryRole(node, 'sse-connection-indicator');
            if (indicator) {
                return indicator;
            }
            node = node.parentElement;
        }
        return null;
    }

    function initStatusList(container) {
        if (container.dataset.sseStatusBound === '1') {
            return;
        }
        const channel = container.getAttribute('data-sse-status-channel');
        const eventType = container.getAttribute('data-sse-status-event');
        if (!channel || !eventType) {
            return;
        }
        container.dataset.sseStatusBound = '1';
        const idField = container.getAttribute('data-sse-status-id-field') || 'id';
        const statusField = container.getAttribute('data-sse-status-field') || 'status';
        const labels = parseAttributeMap(container, 'data-sse-status-labels');
        const colors = parseAttributeMap(container, 'data-sse-status-colors');
        const messages = parseAttributeMap(container, 'data-sse-status-messages');
        container.setAttribute('data-sse-connection', 'connecting');

        const applyPayload = (payload) => {
            if (!payload || typeof payload !== 'object') {
                return;
            }
            const rawId = payload[idField] !== undefined ? payload[idField] : payload.id;
            const status = payload[statusField];
            if (rawId === undefined || rawId === null || !status) {
                return;
            }
            const id = String(rawId);
            if (!/^[A-Za-z0-9_-]+$/.test(id)) {
                return;
            }
            const row = container.querySelector('[data-sse-id="' + id + '"]');
            if (!row) {
                return;
            }
            const badge = row.querySelector('[data-role="sse-status-badge"]');
            if (!badge) {
                return;
            }
            const hasLabel = Object.prototype.hasOwnProperty.call(labels, status);
            const hasColor = Object.prototype.hasOwnProperty.call(colors, status);
            const hasMessage = Object.prototype.hasOwnProperty.call(messages, status);
            if (!hasLabel && !hasColor && !hasMessage) {
                return;
            }
            badge.setAttribute('data-status', status);
            if (hasLabel) {
                setText(badge, labels[status]);
            }
            if (hasColor) {
                badge.setAttribute('color', colors[status]);
            }
            if (hasMessage) {
                const messageEl = row.querySelector('[data-role="sse-status-message"]');
                if (messageEl) {
                    setText(messageEl, messages[status]);
                }
            }
        };

        const indicator = findConnectionIndicator(container);

        subscribeStatusChannel(channel, eventType, applyPayload, (state) => {
            container.setAttribute('data-sse-connection', state);
            const labelKey = SSE_CONNECTION_LABEL_KEYS[state];
            if (indicator && labelKey) {
                setText(indicator, t(labelKey));
            }
        });
    }

    function bootStatusLists() {
        const containers = document.querySelectorAll('[data-sse-status-channel]');
        containers.forEach((container) => {
            try {
                initStatusList(container);
            } catch (listError) {
                void listError;
            }
        });
    }

    function boot() {
        const host = document.querySelector('[data-secrets-page]');
        if (!host) {
            return;
        }
        const eh = getEHelper();
        if (!eh || typeof eh.post !== 'function') {
            disableInteractiveControls(host);
            notify(t('bootUnavailableMessage'), true);
            return;
        }
        const page = host.getAttribute('data-secrets-page');
        const handler = pageHandlers[page];
        if (typeof handler === 'function') {
            try {
                handler(host);
            } catch (bootError) {
                if (typeof window.reportError === 'function') {
                    window.reportError(bootError);
                }
                notify(t('fallbackError'), true);
            }
        }
    }

    function bootAll() {
        boot();
        bootStatusLists();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bootAll);
    } else {
        bootAll();
    }
})();
