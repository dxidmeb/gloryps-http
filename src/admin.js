"use strict";
/**
 * GloryPs Admin Panel — secure file-management panel for the GTPS data dir.
 * Mounted at /admin by main.js. Pure read/write of data files, no execution.
 *
 * Security model:
 *  - scrypt password hashing, HMAC-signed HttpOnly session cookie
 *  - strict path confinement to server_path (no traversal, no escape)
 *  - allowlisted directories/files only
 *  - atomic writes + automatic timestamped backups before every save
 *  - rate-limited login
 */
const path = require("path");
module.paths.push(path.resolve(__dirname, "../db/node_modules"));
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const rateLimit = require("express-rate-limit");
const dgram = require("dgram");

const SESSION_SECRET = crypto.randomBytes(32); // random each startup
const COOKIE_NAME = "gp_admin";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h
const AUDIT_FILE = path.resolve(__dirname, "../db/logs/admin_log.txt");

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

function audit(user, action, detail) {
    try {
        const line = `[${new Date().toISOString()}] ${user} ${action} ${detail || ""}\n`;
        fs.appendFileSync(AUDIT_FILE, line);
    } catch (e) {}
}

module.exports = function createAdmin(CONFIG_FILE, getConfig) {
    const router = express.Router();

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
            // prune old backups (keep 5)
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

    const loginLimiter = rateLimit({
        windowMs: 10 * 60 * 1000, max: 8,
        standardHeaders: true, legacyHeaders: false,
        message: { error: "Too many login attempts. Try again later." }
    });

    router.use(express.json({ limit: "20mb" }));

    // --- login page (inline, dark) ---
    const LOGIN_HTML = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GloryPs Admin — Login</title><style>
body{margin:0;background:#0d0d0d;color:#e0e0e0;font-family:'Segoe UI',system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh}
.card{background:#161616;border:1px solid #262626;border-radius:10px;padding:36px 40px;width:320px;box-shadow:0 8px 30px rgba(0,0,0,.6)}
h1{font-size:18px;margin:0 0 4px;font-weight:600}p.sub{color:#7a8288;font-size:12px;margin:0 0 22px}
label{display:block;font-size:12px;color:#9aa3aa;margin:12px 0 4px}
input{width:100%;box-sizing:border-box;background:#0d0d0d;border:1px solid #2c2c2c;border-radius:6px;color:#e0e0e0;padding:10px;font-size:14px;outline:none}
input:focus{border-color:#3a4a5a}
button{width:100%;margin-top:20px;background:#2e3d4d;border:1px solid #3a4a5a;color:#dfe6ec;padding:10px;border-radius:6px;font-size:14px;cursor:pointer}
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
        res.setHeader("Set-Cookie", `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Strict; Path=/admin; Max-Age=${SESSION_TTL_MS / 1000}`);
        audit(user, "LOGIN", "success");
        res.json({ success: true });
    });

    router.post("/api/logout", (req, res) => {
        const sess = readSession(req.headers.cookie);
        if (sess) audit(sess.u, "LOGOUT", "");
        res.setHeader("Set-Cookie", `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/admin; Max-Age=0`);
        res.json({ success: true });
    });

    // everything below requires auth
    router.use(requireAuth);

    router.get("/", (req, res) => res.sendFile(path.join(__dirname, "html", "admin.html")));

    // ---- API: dashboard info + live server status ----
    function probeUDP(host, port) {
        return new Promise((resolve) => {
            const s = dgram.createSocket("udp4");
            let done = false;
            const finish = (up) => { if (done) return; done = true; try { s.close(); } catch (e) {} resolve(up); };
            s.on("error", () => finish(false));
            s.setTimeout(800);
            s.on("timeout", () => finish(false));
            try { s.connect(port, host, () => { s.send(Buffer.from([0, 1, 0, 0])); }); } catch (e) { return finish(false); }
            // we can't read a reply reliably; "reachable" = connect didn't error
            setTimeout(() => finish(true), 300);
        });
    }
    router.get("/api/info", async (req, res) => {
        const root = serverRoot();
        let subdirs = [];
        try { subdirs = fs.readdirSync(path.join(root, "database"), { withFileTypes: true }).filter(d => d.isDirectory()).map(d => d.name); } catch (e) {}
        const count = (p) => { try { return fs.readdirSync(path.join(root, p)).filter(f => f.endsWith(".json") || f.endsWith(".txt") || f.endsWith(".xaml")).length; } catch (e) { return 0; } };
        const cfg = adminCfg();
        const host = (getConfig().ip) || "127.0.0.1";
        const udp = Number(getConfig().port_udp) || 55000;
        let gameUp = false;
        try { gameUp = await probeUDP(host, udp); } catch (e) {}
        res.json({
            user: req.adminUser, server_path: root, database_subdirs: subdirs,
            counts: { players: count("database/players"), worlds: count("database/worlds"), json: count("database/json"), text: count("database/text") },
            status: { game_udp: { host, port: udp, up: gameUp }, http: { port: Number(getConfig().port_tcp) || 443 } }
        });
    });

    // ---- API: audit log ----
    router.get("/api/logs", (req, res) => {
        try {
            if (!fs.existsSync(AUDIT_FILE)) return res.json({ lines: [] });
            const lines = fs.readFileSync(AUDIT_FILE, "utf8").trim().split("\n").reverse().slice(0, 200);
            res.json({ lines });
        } catch (e) { res.status(500).json({ error: e.message }); }
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
                .filter(f => f.isFile())
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

    // ---- API: players (rich list) ----
    router.get("/api/players", (req, res) => {
        const full = safePath("database/players");
        if (!full) return res.status(400).json({ error: "Invalid path" });
        try {
            const players = fs.readdirSync(full).filter(f => f.endsWith(".json")).map(f => {
                const fp = path.join(full, f);
                let name = f.replace(/_?\.json$/, ""), gems = 0, role = "-", last = 0, banned = false, extra = {};
                try {
                    const data = JSON.parse(fs.readFileSync(fp, "utf8"));
                    // common GTPS fields
                    name = data.name || data.username || data.GrowID || name;
                    if (typeof data.gems === "number") gems = data.gems;
                    if (typeof data.role === "string") role = data.role;
                    if (data.baninfo && data.baninfo.banned) banned = true;
                    if (data.banned) banned = true;
                    if (typeof data.lastlogin === "number") last = data.lastlogin;
                    extra = data;
                } catch (e) {}
                return { file: f, name, gems, role, last, banned, keys: Object.keys(extra).length };
            });
            res.json({ players });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // ---- API: worlds (name + owner via JSON parse) ----
    router.get("/api/worlds", (req, res) => {
        const full = safePath("database/worlds");
        if (!full) return res.status(400).json({ error: "Invalid path" });
        try {
            const worlds = fs.readdirSync(full).filter(f => f.endsWith(".json")).map(f => {
                let owner = "-", name = f.replace(/_?\.json$/, "") || f, blocks = 0;
                try {
                    const data = JSON.parse(fs.readFileSync(path.join(full, f), "utf8"));
                    owner = data.owner || (data.world_owner) || "-";
                    if (typeof data.name === "string") name = data.name;
                    if (Array.isArray(data.blocks)) blocks = data.blocks.length;
                } catch (e) {}
                return { file: f, name, owner, blocks };
            });
            res.json({ worlds });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    return router;
};
