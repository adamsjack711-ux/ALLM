// Puppeteer spray-bot — Chromium driven via Node + CDP.
//
// Sibling to playwright_bot/bot.py and selenium_bot/bot.py: same engine
// underneath, but a different runtime stack and HTTP client surface,
// which gives the detector a third agent-family fingerprint to learn
// from. Class = agent, family = puppeteer_bot.
//
// X-Allm-* labels travel on every request via page.setExtraHTTPHeaders.
// Provenance is written via the in-page fetch (inherits cookies from
// the browser jar, including the allm_sid the proxy mints on first nav).
// Target-guard runs as a pre-exec sh step in the Dockerfile so this
// process never starts against a non-loopback target.

import { createHash } from 'node:crypto';
import puppeteer from 'puppeteer-core';

const LABEL = 'puppeteer_bot';
const TARGET = process.env.ALLM_TARGET || 'http://capture:8080';
const TARGET_APP = (process.env.ALLM_TARGET_APP || 'dvwa').toLowerCase();
const SECURITY_LEVEL = process.env.DVWA_SECURITY_LEVEL || 'low';
const SESSIONS = parseInt(process.env.ALLM_SESSIONS || '3', 10);
const DVWA_USER = process.env.DVWA_USER || 'admin';
const DVWA_PASS = process.env.DVWA_PASS || 'password';

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
        'X-Allm-Source': payload.family,
        'X-Allm-Class': payload.class,
        'X-Allm-Family': payload.family,
        'X-Allm-TargetApp': payload.target_app,
        'X-Allm-SecurityLevel': payload.security_level,
        'X-Allm-Stealth': payload.stealth ? 'true' : 'false',
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
    const inputs = await page.$$(
        'input[type="text"]:not([disabled]):not([readonly]), textarea:not([disabled]):not([readonly])'
    );
    if (!inputs.length) return;
    const payload = PAYLOADS[Math.floor(Math.random() * PAYLOADS.length)];
    for (const inp of inputs) {
        try { await inp.evaluate((el) => (el.value = '')); } catch {}
        try { await inp.type(payload); } catch {}
    }
    try {
        const submit = await page.$('input[type="submit"], button[type="submit"]');
        if (submit) await submit.click();
        await page.waitForNetworkIdle({ idleTime: 200, timeout: 3000 }).catch(() => {});
    } catch {}
}

async function runSession(browser, sessionIdx) {
    const payload = buildPayload(
        'agent', LABEL, 'puppeteer_bot', '0.1.0',
        { engine: 'puppeteer', paths: VULN_PATHS },
    );
    const headers = labelHeaders(payload);

    const context = await browser.createBrowserContext();
    const page = await context.newPage();
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
    console.log(`[${LABEL}] target=${TARGET} target_app=${TARGET_APP} sessions=${SESSIONS}`);
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
