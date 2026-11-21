// Drives the demo dashboard with a visible mouse cursor, saves docs/screenshots/*.png and builds docs/dashboard_demo.gif.
// Needs the demo server running (python scripts/demo/serve_demo.py), Microsoft Edge and ffmpeg on the PATH.
// Run: npm install && npm run record
import { chromium } from "playwright";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const HERE = import.meta.dirname;
const DOCS_DIR = resolve(HERE, "../../docs");
const SCREENSHOT_DIR = resolve(DOCS_DIR, "screenshots");
const FRAMES_DIR = resolve(HERE, ".demo/frames");
const GIF_PATH = resolve(DOCS_DIR, "dashboard_demo.gif");
const BROWSER_CHANNEL = "msedge"; // shortcut: uses the installed Edge to skip a browser download, switch to bundled chromium on CI
const VIEWPORT = { width: 1280, height: 900 }; // tall enough that the alert drawer shows its triage buttons
const GIF_FPS = 10;
const GIF_SPEEDUP = 1.3; // the walkthrough is slow enough to follow; this keeps the GIF short
const GIF_WIDTH = 960;
const GLIDE_STEPS = 28;
const TYPING_DELAY_MS = 80;
const AFTER_CLICK_MS = 900;
const pause = (ms) => new Promise((done) => setTimeout(done, ms));

const state = JSON.parse(readFileSync(resolve(HERE, ".demo/state.json"), "utf8"));

// the arrow and click ripple are page elements, because a headless browser draws no mouse pointer
function installCursor() {
    window.addEventListener("DOMContentLoaded", () => {
        const svgNs = "http://www.w3.org/2000/svg";
        const arrow = document.createElementNS(svgNs, "svg");
        arrow.setAttribute("width", "26");
        arrow.setAttribute("height", "31");
        arrow.setAttribute("viewBox", "0 0 28 34");
        arrow.style.cssText = "position:fixed;z-index:99999;left:-60px;top:-60px;pointer-events:none;filter:drop-shadow(2px 3px 3px rgba(0,0,0,.6))";
        const path = document.createElementNS(svgNs, "path");
        path.setAttribute("d", "M3 2 L3 27 L9.5 21 L14 31 L18.5 29 L14 19.5 L23 19.5 Z");
        path.setAttribute("fill", "white");
        path.setAttribute("stroke", "black");
        path.setAttribute("stroke-width", "2");
        path.setAttribute("stroke-linejoin", "round");
        arrow.append(path);
        document.body.append(arrow);
        let x = -60, y = -60;
        document.addEventListener("mousemove", (event) => {
            x = event.clientX;
            y = event.clientY;
            arrow.style.left = `${x - 3}px`;
            arrow.style.top = `${y - 2}px`;
        }, true);
        window.__ripple = () => {
            const ring = document.createElement("div");
            ring.style.cssText = `position:fixed;z-index:99998;left:${x - 18}px;top:${y - 18}px;width:36px;height:36px;border-radius:50%;border:3px solid #38bdf8;pointer-events:none`;
            document.body.append(ring);
            ring.animate([{ transform: "scale(.3)", opacity: 1 }, { transform: "scale(1.5)", opacity: 0 }], { duration: 500 })
                .finished.then(() => ring.remove());
        };
    });
}

async function glideTo(page, locator) {
    await locator.scrollIntoViewIfNeeded();
    const box = await locator.boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: GLIDE_STEPS });
    await pause(200);
}

async function glideAndClick(page, locator) {
    await glideTo(page, locator);
    await page.evaluate(() => window.__ripple());
    await pause(200);
    await locator.click();
    await pause(AFTER_CLICK_MS);
}

async function glideAndType(page, locator, text) {
    await glideAndClick(page, locator);
    await page.keyboard.type(text, { delay: TYPING_DELAY_MS });
    await pause(500);
}

// the sensor reports a flood from a new address; the server pushes it to the open dashboard
async function sendLiveAlert() {
    const now = Date.now() / 1000;
    const response = await fetch(`${state.url}/api/sensor/flows`, {
        method: "POST",
        headers: { Authorization: `Bearer ${state.sensor_token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ records: [{
            src_ip: "203.0.113.150", dst_ip: "10.0.0.10", src_port: 51234, dst_port: 443, protocol: 6,
            start_time: now - 3, end_time: now, packet_count: 40, event: "finished", features: {},
            src_connections_last_minute: 240,
        }] }),
    });
    if (!response.ok) throw new Error(`live alert rejected: ${response.status}`);
}

rmSync(FRAMES_DIR, { recursive: true, force: true });
mkdirSync(FRAMES_DIR, { recursive: true });
mkdirSync(SCREENSHOT_DIR, { recursive: true });

const browser = await chromium.launch({ channel: BROWSER_CHANNEL });
const context = await browser.newContext({ viewport: VIEWPORT, bypassCSP: true }); // bypassCSP: only for the cursor overlay
const page = await context.newPage();
await page.addInitScript(installCursor);
await page.goto(state.url);
await page.locator("#auth-username").waitFor();

let frameCount = 0;
const startedAt = Date.now();
let recording = true;
let capturePaused = false;
const captureLoop = (async () => {
    while (recording) {
        if (capturePaused) { await pause(20); continue; }
        const frame = await page.screenshot({ type: "jpeg", quality: 85 });
        writeFileSync(`${FRAMES_DIR}/${String(frameCount++).padStart(5, "0")}.jpg`, frame);
    }
})();

async function snapshot(name) {
    capturePaused = true;
    await pause(400); // lets the frame that is being captured finish
    await page.screenshot({ path: `${SCREENSHOT_DIR}/${name}.png` });
    capturePaused = false;
}

async function openView(label) {
    await glideAndClick(page, page.locator("#nav").getByRole("button", { name: label }));
    await pause(1400);
}

await pause(1200);
await glideAndType(page, page.locator("#auth-username"), state.username);
await glideAndType(page, page.locator("#auth-password"), state.password);
await glideAndClick(page, page.locator("#auth-submit"));
await page.locator("#app").waitFor();
await pause(2200); // the strip and the open counts are the first thing a reader sees
await snapshot("alerts");

const search = page.locator("#f-search");
await glideAndType(page, search, "Web attack");
const firstRow = page.locator("#alert-rows tr").first();
await glideAndClick(page, firstRow);
await pause(1200);
await snapshot("alert-detail");
await glideAndClick(page, page.getByRole("button", { name: "Acknowledge" }));
await pause(1500);
await glideAndClick(page, page.locator("#drawer .close"));
await search.fill("");
await pause(1000);

await sendLiveAlert();
await pause(2800); // the new row and the flash on the last bar of the strip

await openView("Rules");
await snapshot("rules");
await openView("Sensors");
await snapshot("sensors");
await openView("Users");
await snapshot("users");
await openView("Activity");
await snapshot("activity");
await openView("Alerts");
await pause(1200);

recording = false;
await captureLoop;
await browser.close();

// frames are taken as fast as the browser delivers them, so tell ffmpeg the real rate to keep real-time pacing
const capturedFps = frameCount / ((Date.now() - startedAt) / 1000);
execFileSync("ffmpeg", [
    "-y", "-framerate", capturedFps.toFixed(2), "-i", `${FRAMES_DIR}/%05d.jpg`,
    "-vf", `setpts=PTS/${GIF_SPEEDUP},fps=${GIF_FPS},scale=${GIF_WIDTH}:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128[p];[b][p]paletteuse=dither=bayer:bayer_scale=4`,
    GIF_PATH,
], { stdio: "ignore" });
console.log(`${frameCount} frames -> ${GIF_PATH}`);
