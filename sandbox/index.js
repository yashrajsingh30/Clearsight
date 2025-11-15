const express = require('express');
const puppeteer = require('puppeteer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
app.use(express.json());

const SCREENSHOT_DIR = '/app/screenshots';

if (!fs.existsSync(SCREENSHOT_DIR)) {
    fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
}

app.post('/scan', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    console.log(`[Sandbox] Starting scan for: ${url}`);
    let browser = null;

    try {
        browser = await puppeteer.launch({
            headless: 'new',
            executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium-browser',
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu'
            ]
        });

        const page = await browser.newPage();
        await page.setViewport({ width: 1366, height: 768 });
        // Set a realistic User-Agent to avoid being blocked by anti-bot systems
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36');

        try {
            // UPDATED: Increased timeout to 30s and relaxed wait condition to 'networkidle2'
            await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
        } catch (navError) {
            console.warn(`[Sandbox] Navigation warning for ${url}: ${navError.message}. Attempting to take screenshot anyway.`);
            // We continue here to try and take a partial screenshot even if it timed out
        }

        const pageTitle = await page.title();
        const finalUrl = page.url();
        const filename = `${crypto.randomUUID()}.png`;
        const filepath = path.join(SCREENSHOT_DIR, filename);

        await page.screenshot({ path: filepath, fullPage: false });

        console.log(`[Sandbox] Successfully scanned: ${url}`);
        res.json({
            status: 'success',
            original_url: url,
            final_url: finalUrl,
            page_title: pageTitle,
            screenshot_filename: filename
        });

    } catch (error) {
        console.error(`[Sandbox] Fatal error scanning ${url}:`, error.message);
        res.status(200).json({
            status: 'error',
            original_url: url,
            error: 'Scan failed: ' + error.message
        });
    } finally {
        if (browser) await browser.close();
    }
});

const PORT = 3001;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🛡️ ClearSight Sandbox Service running on port ${PORT}`);
});