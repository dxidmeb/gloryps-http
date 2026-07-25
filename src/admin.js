"use strict";
/**
 * GloryPs Admin Panel — secure, mobile-first management panel for the GTPS.
 * Mounted at /admin by main.js.
 *
 * Security model:
 *  - scrypt password hashing, HMAC-signed HttpOnly Secure SameSite=Strict session cookie
 *  - CSRF: signed token issued per session, required as X-CSRF-Token header on POST/PUT/DELETE
 *  - strict path confinement to server_path (no traversal, no escape)
 *  - allowlisted directories/files only
 *  - atomic writes + automatic timestamped backups before every save (keep last 5)
 *  - rate-limited login
 *  - server control via STRICT command allowlist (child_process.spawn, fixed args)
 *
 * Keep module signature: module.exports = function createAdmin(CONFIG_FILE, getConfig){...}
 */
const path = require("path");
module.paths.push(path.resolve(__dirname, "../db/node_modules"));
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const rateLimit = require("express-rate-limit");
const dgram = require("dgram");
const net = require("net");
const { spawn } = require("child_process");
const itemsCodec = require("./items_codec");

const SESSION_SECRET = crypto.randomBytes(32); // random each startup
const COOKIE_NAME = "gp_admin";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h
const AUDIT_FILE = path.resolve(__dirname, "../db/logs/admin_log.txt");
// Cookie flags. Production runs over HTTPS => Secure. A test harness may set
// ADMIN_INSECURE_COOKIE=1 to drop the Secure flag for plain-HTTP browser QA only.
const SECURE_ATTR = process.env.ADMIN_INSECURE_COOKIE === "1" ? "" : " Secure;";

// game server binary + working directory (fixed)
const GAME_BIN = "/root/90824/build/Server";
const GAME_CWD = "/root/90824/Core/x64/Release";

// ---------- crypto helpers ----------
function scryptHash(password) {
    const salt = crypto.randomBytes(16);
    const key = crypto.scryptSync(password, salt, 64);
    return `scrypt:${salt.toString("hex")}:${key.toString("hex")}`;
}
function verifyPassword(password, stored) {
    try {
        const [scheme, saltHex, keyHex] = String(stored).split(":");
        if (scheme !== "scrypt") return false;
        const key = crypto.scryptSync(password, Buffer.from(saltHex, "hex"), 64);
        const expected = Buffer.from(keyHex, "hex");
        return key.length === expected.length && crypto.timingSafeEqual(key, expected);
    } catch (e) { return false; }
}
function sign(data) {
    return crypto.createHmac("sha256", SESSION_SECRET).update(data).digest("hex");
}
function makeSession(user) {
    const payload = Buffer.from(JSON.stringify({ u: user, exp: Date.now() + SESSION_TTL_MS })).toString("base64url");
    return payload + "." + sign(payload);
}
function readSession(cookieHeader) {
    if (!cookieHeader) return null;
    const m = cookieHeader.split(/;\s*/).find(c => c.startsWith(COOKIE_NAME + "="));
    if (!m) return null;
    const token = decodeURIComponent(m.slice(COOKIE_NAME.length + 1));
    const idx = token.lastIndexOf(".");
    if (idx < 0) return null;
    const payload = token.slice(0, idx), sig = token.slice(idx + 1);
    const expected = sign(payload);
    if (sig.length !== expected.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    try {
        const data = JSON.parse(Buffer.from(payload, "base64url").toString());
        if (!data.u || Date.now() > data.exp) return null;
        return data;
    } catch (e) { return null; }
}
// CSRF token bound to the authenticated user
function makeCsrf(user) {
    const payload = Buffer.from(JSON.stringify({ u: user, t: Date.now() })).toString("base64url");
    return payload + "." + sign("csrf:" + payload);
}
function verifyCsrf(token, user) {
    if (typeof token !== "string") return false;
    const idx = token.lastIndexOf(".");
    if (idx < 0) return false;
    const payload = token.slice(0, idx), sig = token.slice(idx + 1);
    const expected = sign("csrf:" + payload);
    if (sig.length !== expected.length) return false;
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
    try {
        const data = JSON.parse(Buffer.from(payload, "base64url").toString());
        return data.u === user;
    } catch (e) { return false; }
}

function audit(user, action, detail) {
    try {
        const line = `[${new Date().toISOString()}] ${user} ${action} ${detail || ""}\n`;
        fs.appendFileSync(AUDIT_FILE, line);
    } catch (e) {}
}

module.exports = function createAdmin(CONFIG_FILE, getConfig) {
    const router = express.Router();

    // in-memory tracking of the game server child process we spawn
    let gameChild = null;
    let gameStartedAt = 0;

    // --- one-time credential setup (persist hash to config.json) ---
    (function ensureCreds() {
        let cfg;
        try { cfg = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8")); } catch (e) { cfg = {}; }
        if (!cfg.admin) cfg.admin = {};
        if (!cfg.admin.user) cfg.admin.user = "gloryadmin";
        if (!cfg.admin.server_path) cfg.admin.server_path = "/root/90824/Core/x64/Release";
        if (!cfg.admin.pass_hash) {
            const pw = crypto.randomBytes(14).toString("base64url"); // ~19 chars
            cfg.admin.pass_hash = scryptHash(pw);
            const tmp = CONFIG_FILE + ".tmp";
            fs.writeFileSync(tmp, JSON.stringify(cfg, null, 4));
            fs.renameSync(tmp, CONFIG_FILE);
            console.log("\x1b[36m==================================================\x1b[0m");
            console.log("\x1b[32m[ADMIN PANEL] First-time setup — credentials generated:\x1b[0m");
            console.log(`  URL:      https://<host>/admin`);
            console.log(`  Username: ${cfg.admin.user}`);
            console.log(`  Password: ${pw}`);
            console.log("  (Save this now — it is shown ONCE. Hash stored in config/config.json)");
            console.log("\x1b[36m==================================================\x1b[0m");
        }
    })();

    const adminCfg = () => (getConfig().admin || {});
    const serverRoot = () => path.resolve(adminCfg().server_path || "/root/90824/Core/x64/Release");

    // --- strict path confinement ---
    function safePath(rel) {
        if (typeof rel !== "string" || rel.includes("\0")) return null;
        const root = serverRoot();
        const full = path.resolve(root, rel.replace(/^\/+/, ""));
        if (full !== root && !full.startsWith(root + path.sep)) return null;
        return full;
    }
    function atomicWrite(full, content) {
        const tmp = full + ".tmp-" + crypto.randomBytes(4).toString("hex");
        fs.writeFileSync(tmp, content);
        fs.renameSync(tmp, full);
    }
    // backup before overwrite (keeps last 5)
    function backupFile(full) {
        try {
            if (!fs.existsSync(full)) return;
            const dir = path.dirname(full);
            const base = path.basename(full);
            const stamp = new Date().toISOString().replace(/[:.]/g, "-");
            fs.copyFileSync(full, path.join(dir, base + ".bak-" + stamp));
            const backs = fs.readdirSync(dir).filter(f => f.startsWith(base + ".bak-")).sort().reverse();
            for (const b of backs.slice(5)) { try { fs.unlinkSync(path.join(dir, b)); } catch (e) {} }
        } catch (e) {}
    }

    // --- auth middleware ---
    function requireAuth(req, res, next) {
        const sess = readSession(req.headers.cookie);
        if (sess) { req.adminUser = sess.u; return next(); }
        if (req.path.startsWith("/api/")) return res.status(401).json({ error: "Not authenticated" });
        return res.redirect("/admin/login");
    }
    // --- CSRF middleware for mutating methods ---
    // NOTE: /api/login and /api/logout are exempt — you cannot hold a CSRF
    // token before establishing a session, and logout destroys it.
    const CSRF_EXEMPT = new Set(["/api/login", "/api/logout"]);
    function requireCsrf(req, res, next) {
        if (CSRF_EXEMPT.has(req.path)) return next();
        if (["POST", "PUT", "DELETE"].includes(req.method)) {
            const token = req.headers["x-csrf-token"];
            if (!verifyCsrf(token, req.adminUser)) {
                return res.status(403).json({ error: "Invalid or missing CSRF token" });
            }
        }
        next();
    }

    const loginLimiter = rateLimit({
        windowMs: 10 * 60 * 1000, max: 8,
        standardHeaders: true, legacyHeaders: false,
        message: { error: "Too many login attempts. Try again later." }
    });

    router.use(express.json({ limit: "64mb" }));

    // --- login page (inline, dark) ---
    const LOGIN_HTML = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GloryPs Admin — Login</title><style>
body{margin:0;background:#0d0d0d;color:#e0e0e0;font-family:'Segoe UI',system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:16px}
.card{background:#161616;border:1px solid #262626;border-radius:10px;padding:32px 28px;width:100%;max-width:340px;box-shadow:0 8px 30px rgba(0,0,0,.6)}
h1{font-size:18px;margin:0 0 4px;font-weight:600}p.sub{color:#7a8288;font-size:12px;margin:0 0 22px}
label{display:block;font-size:12px;color:#9aa3aa;margin:12px 0 4px}
input{width:100%;box-sizing:border-box;background:#0d0d0d;border:1px solid #2c2c2c;border-radius:6px;color:#e0e0e0;padding:12px;font-size:15px;outline:none;min-height:44px}
input:focus{border-color:#3a4a5a}
button{width:100%;margin-top:20px;background:#2e3d4d;border:1px solid #3a4a5a;color:#dfe6ec;padding:12px;border-radius:6px;font-size:15px;cursor:pointer;min-height:44px}
button:hover{background:#354657}
#err{color:#b06a6a;font-size:12px;margin-top:12px;min-height:14px}
</style></head><body><div class="card"><h1>GloryPs Admin</h1><p class="sub">Restricted area — authorized personnel only</p>
<label>Username</label><input id="u" autocomplete="username">
<label>Password</label><input id="p" type="password" autocomplete="current-password">
<button onclick="go()">Sign in</button><div id="err"></div>
<script>
async function go(){
  const r=await fetch('/admin/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user:u.value,pass:p.value})});
  if(r.ok){location.href='/admin';}else{const j=await r.json().catch(()=>({}));err.textContent=j.error||'Login failed';}
}
p.addEventListener('keydown',e=>{if(e.key==='Enter')go();});
</script></div></body></html>`;

    router.get("/login", (req, res) => {
        if (readSession(req.headers.cookie)) return res.redirect("/admin");
        res.type("html").send(LOGIN_HTML);
    });

    router.post("/api/login", loginLimiter, (req, res) => {
        const { user, pass } = req.body || {};
        const cfg = adminCfg();
        const userOk = typeof user === "string" && user === cfg.user;
        const passOk = typeof pass === "string" && verifyPassword(pass, cfg.pass_hash);
        if (!userOk || !passOk) {
            console.log(`\x1b[31m[ADMIN PANEL] Failed login attempt (user='${String(user).slice(0,32)}')\x1b[0m`);
            return res.status(401).json({ error: "Invalid credentials" });
        }
        const token = makeSession(user);
        res.setHeader("Set-Cookie", `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly;${SECURE_ATTR} SameSite=Strict; Path=/admin; Max-Age=${SESSION_TTL_MS / 1000}`);
        audit(user, "LOGIN", "success");
        res.json({ success: true });
    });

    router.post("/api/logout", (req, res) => {
        const sess = readSession(req.headers.cookie);
        if (sess) audit(sess.u, "LOGOUT", "");
        res.setHeader("Set-Cookie", `${COOKIE_NAME}=; HttpOnly;${SECURE_ATTR} SameSite=Strict; Path=/admin; Max-Age=0`);
        res.json({ success: true });
    });

    // everything below requires auth (+ CSRF on mutations)
    router.use(requireAuth);
    router.use(requireCsrf);
    // Never let browsers cache admin pages/APIs (prevents "stale page" bugs)
    router.use((req, res, next) => { res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate"); res.set("Pragma", "no-cache"); res.set("Expires", "0"); next(); });

    router.get("/", (req, res) => { try { res.type("html").send(fs.readFileSync(path.join(__dirname, "html", "admin.html"))); } catch (e) { res.status(500).end(); } });

    // CSRF token endpoint (page fetches this after load)
    router.get("/api/csrf", (req, res) => res.json({ token: makeCsrf(req.adminUser) }));

    // ---- probes ----
    function probeUDP(host, port) {
        return new Promise((resolve) => {
            const s = dgram.createSocket("udp4");
            let done = false;
            const finish = (up) => { if (done) return; done = true; try { s.close(); } catch (e) {} resolve(up); };
            s.on("error", () => finish(false));
            try { s.connect(port, host, () => { try { s.send(Buffer.from([0, 1, 0, 0])); } catch (e) {} }); } catch (e) { return finish(false); }
            setTimeout(() => finish(true), 250);
        });
    }
    function probeTCP(host, port) {
        return new Promise((resolve) => {
            const sock = new net.Socket();
            let done = false;
            const finish = (up) => { if (done) return; done = true; try { sock.destroy(); } catch (e) {} resolve(up); };
            sock.setTimeout(700);
            sock.once("connect", () => finish(true));
            sock.once("timeout", () => finish(false));
            sock.once("error", () => finish(false));
            try { sock.connect(port, host); } catch (e) { finish(false); }
        });
    }

    function count(p) {
        try {
            return fs.readdirSync(path.join(serverRoot(), p))
                .filter(f => f.endsWith(".json") || f.endsWith(".txt") || f.endsWith(".xaml")).length;
        } catch (e) { return 0; }
    }
    // Cheap item count: read just the dat header (version@0 uint16, item_count@2 uint32).
    // No full decode — safe to call on every dashboard load.
    function headerItemCount() {
        try {
            const full = safePath("database/items.dat");
            if (!full || !fs.existsSync(full)) return 0;
            const buf = fs.readFileSync(full);
            if (buf.length < 6) return 0;
            return (buf[2] | (buf[3] << 8) | (buf[4] << 16) | (buf[5] << 24)) >>> 0;
        } catch (e) { return 0; }
    }

    // ---- API: dashboard info + live server status ----
    router.get("/api/info", async (req, res) => {
        const root = serverRoot();
        let subdirs = [];
        try { subdirs = fs.readdirSync(path.join(root, "database"), { withFileTypes: true }).filter(d => d.isDirectory()).map(d => d.name); } catch (e) {}
        const host = (getConfig().ip) || "127.0.0.1";
        const udp = Number(getConfig().port_udp) || 55000;
        const tcp = Number(getConfig().port_tcp) || 443;
        let gameUp = false, httpUp = false;
        try { [gameUp, httpUp] = await Promise.all([probeUDP("127.0.0.1", udp), probeTCP("127.0.0.1", tcp)]); } catch (e) {}
        res.json({
            user: req.adminUser, server_path: root, database_subdirs: subdirs,
            counts: { players: count("database/players"), worlds: count("database/worlds"), json: count("database/json"), text: count("database/text"), items: headerItemCount() },
            status: {
                game_udp: { host, port: udp, up: gameUp, pid: (gameChild && !gameChild.killed) ? gameChild.pid : null,
                    uptime: gameStartedAt ? Math.floor((Date.now() - gameStartedAt) / 1000) : 0 },
                http: { host, port: tcp, up: httpUp, pid: process.pid }
            }
        });
    });

    // ---- API: audit log ----
    router.get("/api/logs", (req, res) => {
        try {
            if (!fs.existsSync(AUDIT_FILE)) return res.json({ lines: [] });
            const n = Math.min(Number(req.query.n) || 200, 500);
            const lines = fs.readFileSync(AUDIT_FILE, "utf8").trim().split("\n").reverse().slice(0, n);
            res.json({ lines });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // =========================================================
    //  SERVER CONTROL — strict command allowlist, no arbitrary exec
    // =========================================================
    router.get("/api/server/status", async (req, res) => {
        const udp = Number(getConfig().port_udp) || 55000;
        const tcp = Number(getConfig().port_tcp) || 443;
        let gameUp = false, httpUp = false;
        try { [gameUp, httpUp] = await Promise.all([probeUDP("127.0.0.1", udp), probeTCP("127.0.0.1", tcp)]); } catch (e) {}
        res.json({
            game: { up: gameUp, port: udp, pid: (gameChild && !gameChild.killed) ? gameChild.pid : null,
                uptime: gameStartedAt ? Math.floor((Date.now() - gameStartedAt) / 1000) : 0,
                bin: GAME_BIN, cwd: GAME_CWD },
            http: { up: httpUp, port: tcp, pid: process.pid }
        });
    });

    function startGame() {
        if (gameChild && !gameChild.killed) return { ok: false, error: "Game server already running (tracked pid " + gameChild.pid + ")" };
        if (!fs.existsSync(GAME_BIN)) return { ok: false, error: "Game binary not found: " + GAME_BIN };
        try {
            const child = spawn(GAME_BIN, [], { cwd: GAME_CWD, detached: true, stdio: "ignore" });
            child.on("exit", () => { if (gameChild === child) { gameChild = null; gameStartedAt = 0; } });
            child.unref();
            gameChild = child; gameStartedAt = Date.now();
            return { ok: true, pid: child.pid };
        } catch (e) { return { ok: false, error: e.message }; }
    }
    function stopGame() {
        if (!gameChild || gameChild.killed) return { ok: false, error: "No tracked game server process to stop" };
        try {
            try { process.kill(-gameChild.pid, "SIGTERM"); } catch (e) { process.kill(gameChild.pid, "SIGTERM"); }
            const pid = gameChild.pid; gameChild = null; gameStartedAt = 0;
            return { ok: true, pid };
        } catch (e) { return { ok: false, error: e.message }; }
    }

    // STRICT allowlist of actions — no arbitrary command execution
    const SERVER_ACTIONS = {
        "game:start": () => startGame(),
        "game:stop": () => stopGame(),
        "game:restart": () => { stopGame(); return startGame(); },
        // http:restart re-execs THIS node process by exiting; a supervisor/start.sh must relaunch.
        "http:restart": () => {
            setTimeout(() => { audit("system", "HTTP_RESTART", "exit for supervisor relaunch"); process.exit(0); }, 400);
            return { ok: true, note: "HTTP server exiting; relaunch handled by start.sh/supervisor" };
        }
    };

    router.post("/api/server/control", (req, res) => {
        const action = String((req.body || {}).action || "");
        const fn = SERVER_ACTIONS[action];
        if (!fn) return res.status(400).json({ error: "Action not allowed" });
        const result = fn();
        audit(req.adminUser, "SERVER_CONTROL", action + " " + JSON.stringify(result));
        console.log(`\x1b[33m[ADMIN PANEL] ${req.adminUser} server-control: ${action}\x1b[0m`);
        if (result && result.ok === false) return res.status(400).json(result);
        res.json(result || { ok: true });
    });

    // ---- allowlisted targets ----
    const ALLOWED_DIRS = ["database/json", "database/players", "database/worlds", "database/text"];
    const ALLOWED_FILES = ["database/roles.xaml"];

    function checkAllowed(rel) {
        const norm = path.posix.normalize(String(rel).replace(/\\/g, "/")).replace(/^\/+/, "");
        if (ALLOWED_FILES.includes(norm)) return norm;
        if (ALLOWED_DIRS.some(d => norm.startsWith(d + "/") && !norm.slice(d.length + 1).includes("/"))) return norm;
        return null;
    }

    router.get("/api/list", (req, res) => {
        const dir = String(req.query.dir || "");
        if (!ALLOWED_DIRS.includes(dir)) return res.status(400).json({ error: "Directory not allowed" });
        const full = safePath(dir);
        if (!full) return res.status(400).json({ error: "Invalid path" });
        try {
            const files = fs.readdirSync(full, { withFileTypes: true })
                .filter(f => f.isFile() && !f.name.includes(".bak-"))
                .map(f => {
                    const st = fs.statSync(path.join(full, f.name));
                    return { name: f.name, size: st.size, mtime: st.mtimeMs };
                })
                .sort((a, b) => b.mtime - a.mtime);
            res.json({ files });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    router.get("/api/file", (req, res) => {
        const rel = checkAllowed(req.query.path || "");
        if (!rel) return res.status(400).json({ error: "Path not allowed" });
        const full = safePath(rel);
        if (!full) return res.status(400).json({ error: "Invalid path" });
        try {
            const st = fs.statSync(full);
            if (st.size > 20 * 1024 * 1024) return res.status(413).json({ error: "File too large" });
            res.json({ path: rel, content: fs.readFileSync(full, "utf8") });
        } catch (e) { res.status(404).json({ error: "File not found" }); }
    });

    router.post("/api/file", (req, res) => {
        const { path: relIn, content } = req.body || {};
        const rel = checkAllowed(relIn || "");
        if (!rel) return res.status(400).json({ error: "Path not allowed" });
        if (typeof content !== "string") return res.status(400).json({ error: "Missing content" });
        const full = safePath(rel);
        if (!full || !fs.existsSync(full)) return res.status(400).json({ error: "File does not exist" });
        if (rel.endsWith(".json")) {
            try { JSON.parse(content); } catch (e) { return res.status(400).json({ error: "Invalid JSON: " + e.message }); }
        }
        try {
            backupFile(full);
            atomicWrite(full, content);
            audit(req.adminUser, "SAVE", rel);
            console.log(`\x1b[33m[ADMIN PANEL] ${req.adminUser} saved ${rel}\x1b[0m`);
            res.json({ success: true });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // create new file (inside allowed dir, must not already exist)
    router.post("/api/file/new", (req, res) => {
        const { dir, name, content } = req.body || {};
        if (!ALLOWED_DIRS.includes(String(dir))) return res.status(400).json({ error: "Directory not allowed" });
        const rel = checkAllowed(dir + "/" + String(name || ""));
        if (!rel) return res.status(400).json({ error: "Invalid name" });
        if (!/^[\w.\-]+$/.test(String(name))) return res.status(400).json({ error: "Name has invalid characters" });
        const full = safePath(rel);
        if (!full || fs.existsSync(full)) return res.status(400).json({ error: "File exists" });
        if (rel.endsWith(".json") && content != null) { try { JSON.parse(content); } catch (e) { return res.status(400).json({ error: "Invalid JSON" }); } }
        try {
            atomicWrite(full, content != null ? content : (rel.endsWith(".json") ? "{}" : ""));
            audit(req.adminUser, "CREATE", rel);
            res.json({ success: true, path: rel });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // delete file (with backup retained)
    router.delete("/api/file", (req, res) => {
        const rel = checkAllowed(req.query.path || "");
        if (!rel) return res.status(400).json({ error: "Path not allowed" });
        const full = safePath(rel);
        if (!full || !fs.existsSync(full)) return res.status(404).json({ error: "Not found" });
        try {
            backupFile(full);
            fs.unlinkSync(full);
            audit(req.adminUser, "DELETE", rel);
            res.json({ success: true });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // =========================================================
    //  BACKUP MANAGER
    // =========================================================
    router.get("/api/backups", (req, res) => {
        const rel = checkAllowed(req.query.path || "");
        if (!rel) return res.status(400).json({ error: "Path not allowed" });
        const full = safePath(rel);
        if (!full) return res.status(400).json({ error: "Invalid path" });
        try {
            const dir = path.dirname(full);
            const base = path.basename(full);
            let backs = [];
            try {
                backs = fs.readdirSync(dir).filter(f => f.startsWith(base + ".bak-")).map(f => {
                    const st = fs.statSync(path.join(dir, f));
                    return { name: f, size: st.size, mtime: st.mtimeMs };
                }).sort((a, b) => b.mtime - a.mtime);
            } catch (e) {}
            res.json({ path: rel, backups: backs });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    router.post("/api/restore", (req, res) => {
        const { path: relIn, backup } = req.body || {};
        const rel = checkAllowed(relIn || "");
        if (!rel) return res.status(400).json({ error: "Path not allowed" });
        const full = safePath(rel);
        if (!full) return res.status(400).json({ error: "Invalid path" });
        const base = path.basename(full);
        // strict: backup name must be for THIS file and contain no path separators
        if (typeof backup !== "string" || backup.includes("/") || backup.includes("\\") ||
            backup.includes("..") || !backup.startsWith(base + ".bak-")) {
            return res.status(400).json({ error: "Invalid backup name" });
        }
        const dir = path.dirname(full);
        const bakFull = path.join(dir, backup);
        if (!fs.existsSync(bakFull)) return res.status(404).json({ error: "Backup not found" });
        try {
            if (fs.existsSync(full)) backupFile(full); // snapshot current before restoring
            atomicWrite(full, fs.readFileSync(bakFull));
            audit(req.adminUser, "RESTORE", rel + " <- " + backup);
            console.log(`\x1b[33m[ADMIN PANEL] ${req.adminUser} restored ${rel} from ${backup}\x1b[0m`);
            res.json({ success: true });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // =========================================================
    //  PLAYERS
    // =========================================================
    function deriveRole(data) {
        // GTPS stores roles as Role.<Name> booleans; report the highest set one
        const order = ["Owner_Server", "Developer", "Coder", "Administrator", "Staff", "Moderator",
            "God", "Unlimited", "SUPER_BOOST", "BOOST", "Donatur", "Vip"];
        for (const r of order) {
            if (data["Role." + r] === true) return r;
        }
        if (typeof data.role === "string" && data.role) return data.role;
        return "player";
    }
    function isBanned(data) {
        if (data.banned === true) return true;
        if (data.baninfo && data.baninfo.banned) return true;
        if (typeof data.ban_time === "number" && data.ban_time > Date.now() / 1000) return true;
        return false;
    }

    router.get("/api/players", (req, res) => {
        const full = safePath("database/players");
        if (!full) return res.status(400).json({ error: "Invalid path" });
        try {
            const players = fs.readdirSync(full).filter(f => f.endsWith(".json") && !f.includes(".bak-")).map(f => {
                const fp = path.join(full, f);
                let name = f.replace(/_?\.json$/, ""), gems = 0, role = "player", banned = false, keys = 0;
                try {
                    const data = JSON.parse(fs.readFileSync(fp, "utf8"));
                    name = data.name || data.username || data.GrowID || name;
                    if (typeof data.gems === "number") gems = data.gems;
                    role = deriveRole(data);
                    banned = isBanned(data);
                    keys = Object.keys(data).length;
                } catch (e) {}
                return { file: f, name, gems, role, banned, keys };
            });
            res.json({ players });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    router.get("/api/player", (req, res) => {
        const file = String(req.query.file || "");
        if (!/^[\w.\-]+\.json$/.test(file) || file.includes(".bak-")) return res.status(400).json({ error: "Invalid file" });
        const full = safePath("database/players/" + file);
        if (!full || !fs.existsSync(full)) return res.status(404).json({ error: "Not found" });
        try {
            const data = JSON.parse(fs.readFileSync(full, "utf8"));
            res.json({
                file, data,
                summary: { name: data.name || file, gems: data.gems || 0, role: deriveRole(data), banned: isBanned(data) }
            });
        } catch (e) { res.status(500).json({ error: "Parse error: " + e.message }); }
    });

    // quick actions: ban toggle / set gems / raw field edit (writes player JSON)
    router.post("/api/player/update", (req, res) => {
        const { file, action, value } = req.body || {};
        if (!/^[\w.\-]+\.json$/.test(String(file)) || String(file).includes(".bak-")) return res.status(400).json({ error: "Invalid file" });
        const full = safePath("database/players/" + file);
        if (!full || !fs.existsSync(full)) return res.status(404).json({ error: "Not found" });
        let data;
        try { data = JSON.parse(fs.readFileSync(full, "utf8")); } catch (e) { return res.status(500).json({ error: "Parse error" }); }
        try {
            if (action === "ban") { data.banned = true; if (typeof value === "string") data.ban_reason = value.slice(0, 200); }
            else if (action === "unban") { data.banned = false; delete data.ban_time; }
            else if (action === "setgems") {
                const g = Number(value);
                if (!Number.isFinite(g) || g < 0) return res.status(400).json({ error: "Invalid gems value" });
                data.gems = Math.floor(g);
            } else if (action === "raw") {
                // value is a full JSON object replacing the file (validated)
                if (typeof value !== "object" || value === null) return res.status(400).json({ error: "Invalid data" });
                data = value;
            } else return res.status(400).json({ error: "Unknown action" });

            backupFile(full);
            atomicWrite(full, JSON.stringify(data, null, 2));
            audit(req.adminUser, "PLAYER_" + String(action).toUpperCase(), file + (action === "setgems" ? " =" + value : ""));
            console.log(`\x1b[33m[ADMIN PANEL] ${req.adminUser} player ${action}: ${file}\x1b[0m`);
            res.json({ success: true, summary: { name: data.name || file, gems: data.gems || 0, role: deriveRole(data), banned: isBanned(data) } });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // =========================================================
    //  WORLDS
    // =========================================================
    router.get("/api/worlds", (req, res) => {
        const full = safePath("database/worlds");
        if (!full) return res.status(400).json({ error: "Invalid path" });
        try {
            const worlds = fs.readdirSync(full).filter(f => f.endsWith(".json") && !f.includes(".bak-")).map(f => {
                let owner = "-", name = f.replace(/_?\.json$/, "") || f, blocks = 0, width = null, height = null;
                try {
                    const data = JSON.parse(fs.readFileSync(path.join(full, f), "utf8"));
                    owner = data.owner || data.world_owner || "-";
                    if (typeof data.name === "string" && data.name) name = data.name;
                    if (Array.isArray(data.blocks)) blocks = data.blocks.length;
                    width = data.width || data.w || null;
                    height = data.height || data.h || null;
                } catch (e) {}
                return { file: f, name, owner: owner || "-", blocks, width, height };
            });
            res.json({ worlds });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    router.get("/api/world", (req, res) => {
        const file = String(req.query.file || "");
        if (!/^[\w.\-]+\.json$/.test(file) || file.includes(".bak-")) return res.status(400).json({ error: "Invalid file" });
        const full = safePath("database/worlds/" + file);
        if (!full || !fs.existsSync(full)) return res.status(404).json({ error: "Not found" });
        try {
            const data = JSON.parse(fs.readFileSync(full, "utf8"));
            const width = data.width || data.w || null;
            const height = data.height || data.h || null;
            const blocks = Array.isArray(data.blocks) ? data.blocks.length : 0;
            // Avoid shipping the huge blocks array to the client; summarize it.
            const preview = Object.assign({}, data);
            if (Array.isArray(preview.blocks)) preview.blocks = `[${blocks} blocks omitted]`;
            res.json({
                file, summary: { name: data.name || file, owner: data.owner || "-", blocks, width, height },
                data: preview
            });
        } catch (e) { res.status(500).json({ error: "Parse error: " + e.message }); }
    });

    // =========================================================
    //  ITEMS.DAT EDITOR
    //  items.dat is edited directly by the panel here. A separate
    //  watchdog (Release/start.sh) watches database/items.json and only
    //  re-encodes when items.json changes — so the two never fight:
    //  panel -> items.dat directly; watchdog -> items.json -> items.dat.
    // =========================================================
    function itemsPath() { return safePath("database/items.dat"); }
    function itemsJsonPath() { return safePath("database/items.json"); }

    // items.dat page
    router.get("/items", (req, res) => { try { res.type("html").send(fs.readFileSync(path.join(__dirname, "html", "admin_items.html"))); } catch (e) { res.status(500).end(); } });

    // decode items.dat -> JSON
    router.get("/api/items", (req, res) => {
        const full = itemsPath();
        if (!full) return res.status(400).json({ error: "Invalid path" });
        if (!fs.existsSync(full)) return res.json({ items: [], version: 0, item_count: 0 });
        try {
            const buf = fs.readFileSync(full);
            const decoded = itemsCodec.decodeItems(buf);
            res.json(decoded);
        } catch (e) {
            if (e.code === "UNSUPPORTED_VERSION") return res.status(400).json({ error: e.message });
            res.status(500).json({ error: "Decode failed: " + e.message });
        }
    });

    // save JSON -> items.dat (backup first, atomic)
    // NOTE: body is sent as text/plain so the global bodyParser.json() (100kb
    // default, defined in main.js which we must not edit) skips it; we parse it
    // here with a 64mb text parser since items.json is ~22MB.
    const bigText = express.text({ limit: "64mb", type: () => true });
    router.post("/api/items/save", bigText, (req, res) => {
        let body;
        try { body = JSON.parse(req.body || "{}"); } catch (e) { return res.status(400).json({ error: "Invalid JSON body" }); }
        const items = body.items;
        const version = Number(body.version);
        if (!Array.isArray(items)) return res.status(400).json({ error: "Missing items array" });
        if (!Number.isFinite(version) || version < 1 || version > 26) return res.status(400).json({ error: "Invalid version" });
        const full = itemsPath();
        if (!full) return res.status(400).json({ error: "Invalid path" });
        let encoded;
        try {
            encoded = itemsCodec.encodeItems({ version, item_count: items.length, items });
        } catch (e) {
            return res.status(400).json({ error: "Encode failed: " + e.message });
        }
        try {
            backupFile(full);
            atomicWrite(full, encoded);
            audit(req.adminUser, "ITEMS_SAVE", `items=${items.length} version=${version} bytes=${encoded.length}`);
            console.log(`\x1b[33m[ADMIN PANEL] ${req.adminUser} saved items.dat (${items.length} items)\x1b[0m`);
            res.json({ success: true, item_count: items.length, bytes: encoded.length });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // upload a raw .dat (base64) -> items.dat (backup first, atomic)
    // Also sent as text/plain (base64 body ~7.5MB) to bypass the 100kb global json parser.
    router.post("/api/items/upload", bigText, (req, res) => {
        let parsed;
        try { parsed = JSON.parse(req.body || "{}"); } catch (e) { return res.status(400).json({ error: "Invalid JSON body" }); }
        const b64 = parsed.content;
        if (typeof b64 !== "string" || !b64.length) return res.status(400).json({ error: "Missing content" });
        let bytes;
        try { bytes = Buffer.from(b64, "base64"); } catch (e) { return res.status(400).json({ error: "Invalid base64" }); }
        if (bytes.length < 6) return res.status(400).json({ error: "File too small" });
        const ver = bytes[0] + (bytes[1] << 8);
        if (ver < 1 || ver > 26) return res.status(400).json({ error: "Implausible version byte: " + ver });
        // sanity: decodes cleanly
        try { itemsCodec.decodeItems(bytes); }
        catch (e) { return res.status(400).json({ error: "Not a valid items.dat: " + e.message }); }
        const full = itemsPath();
        if (!full) return res.status(400).json({ error: "Invalid path" });
        try {
            backupFile(full);
            atomicWrite(full, bytes);
            audit(req.adminUser, "ITEMS_UPLOAD", `bytes=${bytes.length} version=${ver}`);
            console.log(`\x1b[33m[ADMIN PANEL] ${req.adminUser} uploaded items.dat (${bytes.length} bytes)\x1b[0m`);
            res.json({ success: true, bytes: bytes.length, version: ver });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    return router;
};
