"use strict";

const path = require("path");

// ==========================================
//  PATH CORRECTION
// ==========================================
module.paths.push(path.resolve(__dirname, "../db/node_modules"));

const express = require("express");
const https = require("https");
const fs = require("fs");
const helmet = require("helmet");
const compression = require("compression");
const morgan = require("morgan");
const bodyParser = require("body-parser");
const geoip = require("geoip-lite");

const app = express();
const version_chttp = "4.18";

// =======================
//  Path Constants
// =======================
const ROOT_DIR = path.resolve(__dirname, "..");
const DB_DIR = path.join(ROOT_DIR, "db");
const CONFIG_FILE = path.join(ROOT_DIR, "config", "config.json");
const FAILED_DOWNLOADS_FILE = path.join(ROOT_DIR, "config", "failed_downloads.json");
const BLACKLIST_IP_FILE = path.join(ROOT_DIR, "config", "blacklistedIP.json");
const BLACKLIST_CR_FILE = path.join(ROOT_DIR, "config", "blacklistedcr.json");
const ADMIN_LOG_FILE = path.join(DB_DIR, "logs", "admin_log.txt"); 
const SSL_KEY = path.join(DB_DIR, "ssl", "server.key");
const SSL_CERT = path.join(DB_DIR, "ssl", "server.crt");
const CACHE_DIR = path.join(DB_DIR, "cache");

// Ensure logs directory exists
try {
    const logDir = path.dirname(ADMIN_LOG_FILE);
    if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
} catch (e) { console.error(e); }

// =======================
//  Console Colors
// =======================
const CLR = { RED: "\x1b[31m", GREEN: "\x1b[32m", YELLOW: "\x1b[33m", BLUE: "\x1b[34m", CYAN: "\x1b[36m", RESET: "\x1b[0m" };

// =======================
//  Global Configuration
// =======================
let serverConfig = {};
const CREATOR_IP = "178.135.20.156"; 

function loadConfig() {
    try {
        const data = fs.readFileSync(CONFIG_FILE, "utf8");
        const newConfig = JSON.parse(data);
        
        // Clear and update object to preserve reference
        for (const key in serverConfig) delete serverConfig[key];
        Object.assign(serverConfig, newConfig);

        if (typeof serverConfig.spoof_missing_files === 'undefined') serverConfig.spoof_missing_files = false;
        if (!Array.isArray(serverConfig.admin_ips)) serverConfig.admin_ips = [];
        
        serverConfig.admin_ips = serverConfig.admin_ips.map(entry => {
            if (typeof entry === 'string') return { ip: entry, name: "Admin" };
            return entry;
        });

        const creatorEntry = serverConfig.admin_ips.find(a => a.ip === CREATOR_IP);
        if (!creatorEntry) {
            serverConfig.admin_ips.push({ ip: CREATOR_IP, name: "👑 Creator" });
            console.log(`${CLR.GREEN}[SYSTEM] Creator IP auto-added to admin list.${CLR.RESET}`);
        } else { creatorEntry.name = "👑 Creator"; }
        
        return true;
    } catch (err) {
        console.log(`${CLR.RED}[CONFIG ERROR] ${err.message}${CLR.RESET}`);
        return false;
    }
}

if (!loadConfig()) process.exit(1);

fs.watchFile(CONFIG_FILE, () => {
    console.log(`${CLR.YELLOW}[SYSTEM] Config change detected. Reloading...${CLR.RESET}`);
    loadConfig();
});

// Auto-Clear Logs
setInterval(() => {
    console.clear();
    console.log(`${CLR.GREEN}[SYSTEM] Logs auto-cleared.${CLR.RESET}`);
    console.log(` HTTP v${version_chttp} | Port: ${serverConfig.port_tcp}`);
    console.log(` Dashboard: https://${serverConfig.ip}:${serverConfig.port_tcp}/dashboard`);
}, 5 * 60 * 1000); 

// =======================
//  Settings & Lists
// =======================
const UBI_CDN_HOST = "ubistatic-a.akamaihd.net";
const UBI_PATH = "0098/020112025/cache"; 
let blacklistedIPs = new Set();
let blacklistedCountries = new Set();
let failedDownloads = new Set(); 
let sessionLoggedFiles = new Set(); 

function loadBlacklists() {
    try {
        if (fs.existsSync(BLACKLIST_IP_FILE)) blacklistedIPs = new Set(JSON.parse(fs.readFileSync(BLACKLIST_IP_FILE, "utf8")).map(ip => String(ip).trim()));
    } catch (e) {}
    try {
        if (fs.existsSync(BLACKLIST_CR_FILE)) blacklistedCountries = new Set(JSON.parse(fs.readFileSync(BLACKLIST_CR_FILE, "utf8")).map(c => String(c).trim().toUpperCase()));
    } catch (e) {}
    sessionLoggedFiles.clear();
    try {
        if (fs.existsSync(FAILED_DOWNLOADS_FILE)) {
            failedDownloads = new Set(JSON.parse(fs.readFileSync(FAILED_DOWNLOADS_FILE, "utf8")));
            console.log(`${CLR.GREEN}[HTTP] System Ready. Cache Failures: ${failedDownloads.size}${CLR.RESET}`);
        } else { failedDownloads.clear(); }
    } catch (e) { failedDownloads.clear(); }
}
loadBlacklists();

function saveBlacklistedIPs() { fs.writeFile(BLACKLIST_IP_FILE, JSON.stringify([...blacklistedIPs], null, 4), () => {}); }
function saveBlacklistedCountries() { fs.writeFile(BLACKLIST_CR_FILE, JSON.stringify([...blacklistedCountries], null, 4), () => {}); }
function saveFailedDownload(pathItem) {
    if (!failedDownloads.has(pathItem)) {
        failedDownloads.add(pathItem);
        fs.writeFile(FAILED_DOWNLOADS_FILE, JSON.stringify([...failedDownloads]), () => {});
    }
}
function shouldSuppressLog(reqPath) {
    if (!reqPath.startsWith("/cache")) return false;
    let relPath = reqPath.replace(/^\/cache/, "");
    if (!relPath.startsWith('/')) relPath = '/' + relPath;
    return failedDownloads.has(relPath) && sessionLoggedFiles.has(relPath);
}
function logAdminEvent(ip, action, status, extra = "") {
    const timestamp = new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '');
    const logLine = `[${timestamp}] IP: ${ip} | Action: ${action} | Status: ${status} | ${extra}\n`;
    fs.appendFile(ADMIN_LOG_FILE, logLine, () => {});
}

// =======================
//  Gemini API
// =======================
function callGemini(prompt, callback) {
    if (!serverConfig.gemini_key) return callback("Gemini API Key missing");
    const data = JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] });
    const options = {
        hostname: 'generativelanguage.googleapis.com',
        path: `/v1beta/models/gemini-1.5-flash:generateContent?key=${serverConfig.gemini_key}`,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
    };
    const req = https.request(options, (res) => {
        let responseBody = '';
        res.on('data', (chunk) => responseBody += chunk);
        res.on('end', () => {
            try {
                const json = JSON.parse(responseBody);
                if (json.error) return callback("Gemini Error: " + json.error.message);
                const text = json.candidates?.[0]?.content?.parts?.[0]?.text || "No response.";
                callback(null, text);
            } catch (e) { callback("AI Error: " + e.message); }
        });
    });
    req.on('error', (e) => callback(e.message));
    req.write(data);
    req.end();
}

// =======================
//  Middleware
// =======================
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(morgan("tiny", {
    skip: (req, res) => {
        const fullPath = req.originalUrl || req.url;
        return shouldSuppressLog(fullPath.split('?')[0]) || fullPath.includes('/api/admin/stats');
    }
})); 
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const getClientIP = (req) => {
    let ip = (req.headers["cf-connecting-ip"] || req.connection.remoteAddress || "").split(",")[0];
    return ip.replace(/^::ffff:/, "");
};

const isAdmin = (req) => {
    const ip = getClientIP(req);
    return serverConfig.admin_ips.some(admin => admin.ip === ip);
};

const protectAdmin = (req, res, next) => {
    const ip = getClientIP(req);
    const ua = req.headers['user-agent'] || "Unknown UA";
    const adminEntry = serverConfig.admin_ips.find(a => a.ip === ip);
    
    if (adminEntry) {
        if (req.path !== '/api/admin/stats') {
            const action = req.path === '/dashboard' ? "Login" : req.path.replace('/api/admin/', '');
            logAdminEvent(ip, action, "SUCCESS", `User: ${adminEntry.name} | UA: ${ua}`);
        }
        return next();
    }

    logAdminEvent(ip, "Access Attempt", "FAILED", `UA: ${ua} | Path: ${req.path}`);
    console.log(`${CLR.RED}[AUTH FAIL] IP: ${ip} tried to access dashboard.${CLR.RESET}`);
    
    if (req.path.startsWith('/api/')) return res.status(403).json({ error: "Unauthorized" });
    return res.status(403).send(`<body style="background:#111;color:#fff;text-align:center;padding-top:50px;"><h1>Access Denied</h1><p>Your IP: ${ip}</p></body>`);
};

app.use((req, res, next) => {
    const ipAddress = getClientIP(req);
    const adminEntry = serverConfig.admin_ips.find(a => a.ip === ipAddress);

    if (adminEntry) {
        if (!req.path.startsWith("/api/admin")) {
             console.log(`${CLR.CYAN}---------------------------------------------------------------${CLR.RESET}`);
             console.log(`${CLR.GREEN}[ADMIN] ${req.method} ${req.path}${CLR.RESET} | User: ${adminEntry.name}`);
        }
        return next();
    }

    const geo = geoip.lookup(ipAddress);
    const country = geo ? String(geo.country || "UNKNOWN").toUpperCase() : "UNKNOWN";

    if ((country !== "UNKNOWN" && blacklistedCountries.has(country)) || blacklistedIPs.has(ipAddress)) {
        return res.status(403).send("Blocked");
    }
    
    if (!shouldSuppressLog(req.path) && !req.path.startsWith("/dashboard") && !req.path.startsWith("/api/admin")) {
        console.log(`${CLR.CYAN}---------------------------------------------------------------${CLR.RESET}`);
        console.log(`${CLR.CYAN}[REQ] ${req.method} ${req.path}${CLR.RESET} | IP: ${ipAddress} (${country})`);
    }
    next();
});

// =======================
//  Routes
// =======================

// --- GloryPs Admin Panel (password-protected file management) ---
const adminPanel = require("./admin")(CONFIG_FILE, () => serverConfig);
app.use("/admin", adminPanel);
// -----------------------------------------------------------------

app.get("/dashboard", protectAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, "html", "dashboard.html"));
});

// --- KEY CHANGE: MOUNT PLAYER ROUTER ---
// We pass a function () => serverConfig so the router always sees the latest config
const playerRouter = require('./routes/players')(ROOT_DIR, () => serverConfig);
app.use('/api/admin/player', protectAdmin, playerRouter);
// ---------------------------------------

app.get("/api/admin/stats", protectAdmin, (req, res) => {
    const mem = process.memoryUsage();
    res.json({
        uptime: process.uptime(),
        ram: Math.round(mem.rss / 1024 / 1024 * 100) / 100,
        config: serverConfig,
        cache_count: failedDownloads.size,
        ips_blocked: blacklistedIPs.size,
        countries_blocked: blacklistedCountries.size,
        blocked_ips_list: [...blacklistedIPs],
        blocked_countries_list: [...blacklistedCountries],
        has_gemini: !!serverConfig.gemini_key
    });
});

app.post("/api/admin/save_config", protectAdmin, (req, res) => {
    try {
        const newConfig = req.body;
        if (typeof newConfig !== 'object' || !newConfig.ip) return res.status(400).json({error: "Invalid"});
        const creatorIndex = newConfig.admin_ips.findIndex(a => a.ip === CREATOR_IP);
        if (creatorIndex === -1) newConfig.admin_ips.push({ ip: CREATOR_IP, name: "👑 Creator" });
        else newConfig.admin_ips[creatorIndex].name = "👑 Creator";
        
        fs.writeFileSync(CONFIG_FILE, JSON.stringify(newConfig, null, 4));
        loadConfig(); // Reload immediately
        res.json({success: true});
    } catch(e) { res.status(500).json({error: e.message}); }
});

app.post("/api/admin/clear_logs", protectAdmin, (req, res) => {
    console.clear();
    console.log(`${CLR.GREEN}[SYSTEM] Logs cleared manually.${CLR.RESET}`);
    res.json({success: true});
});

app.post("/api/admin/reload", protectAdmin, (req, res) => { loadConfig(); loadBlacklists(); res.json({success: true}); });
app.post("/api/admin/block_ip", protectAdmin, (req, res) => { blacklistedIPs.add(req.body.ip); saveBlacklistedIPs(); res.json({success: true}); });
app.post("/api/admin/unblock_ip", protectAdmin, (req, res) => { blacklistedIPs.delete(req.body.ip); saveBlacklistedIPs(); res.json({success: true}); });
app.post("/api/admin/block_country", protectAdmin, (req, res) => { blacklistedCountries.add(req.body.country.toUpperCase()); saveBlacklistedCountries(); res.json({success: true}); });
app.post("/api/admin/unblock_country", protectAdmin, (req, res) => { blacklistedCountries.delete(req.body.country.toUpperCase()); saveBlacklistedCountries(); res.json({success: true}); });

app.post("/api/admin/ai/report", protectAdmin, (req, res) => {
    const mem = process.memoryUsage();
    callGemini(`Report status. Uptime: ${Math.floor(process.uptime())}s. RAM: ${Math.round(mem.rss/1024/1024)}MB. CacheFail: ${failedDownloads.size}.`, (err, text) => {
        if (err) return res.status(500).json({error: err});
        res.json({text});
    });
});

app.post("/api/admin/ai/chat", protectAdmin, (req, res) => {
    callGemini(req.body.query, (err, text) => {
        if (err) return res.status(500).json({error: err});
        res.json({text});
    });
});

// Changed to app.all to allow GET requests in the browser
app.all("/growtopia/server_data.php", (req, res) => {
    res.setHeader("Content-Type", "text/plain");
    res.send(`server|${serverConfig.ip}\nport|${serverConfig.port_udp}\ntype|1\n#maint|Protected By Custom HTTP\n\nbeta_server|${serverConfig.ip}\nbeta_port|${serverConfig.port_udp}\nloginurl|${serverConfig.url_login}|\nbeta_type|1\nmeta|${serverConfig.meta}\nRTENDMARKERBS1001`);
});

function downloadFromCDN(relativePath, localDest, callback) {
    const safeRelPath = relativePath.startsWith('/') ? relativePath : '/' + relativePath;
    if (failedDownloads.has(safeRelPath)) {
        if (!sessionLoggedFiles.has(safeRelPath)) {
            console.log(`${CLR.RED}[CACHE] Known missing (Skipping fetch): ${safeRelPath}${CLR.RESET}`);
            sessionLoggedFiles.add(safeRelPath);
        }
        return callback(false);
    }
    const url = `https://${UBI_CDN_HOST}/${UBI_PATH}${safeRelPath}`;
    const dir = path.dirname(localDest);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const file = fs.createWriteStream(localDest);
    console.log(`${CLR.YELLOW}[FETCH] > ${safeRelPath}${CLR.RESET}`);
    https.get(url, (res) => {
        if (res.statusCode === 200) {
            res.pipe(file); file.on('finish', () => file.close(callback(true)));
        } else {
            saveFailedDownload(safeRelPath); sessionLoggedFiles.add(safeRelPath);
            fs.unlink(localDest, () => {});
            console.log(`${CLR.RED}[FETCH FAIL] ${res.statusCode}: ${safeRelPath}${CLR.RESET}`);
            callback(false);
        }
    }).on('error', () => {
        saveFailedDownload(safeRelPath); sessionLoggedFiles.add(safeRelPath);
        fs.unlink(localDest, () => {}); callback(false);
    });
}

app.use("/cache", (req, res, next) => {
    const safePath = path.normalize(req.path).replace(/^(\.\.[\/\\])+/, '').replace(/^\/+/, '');
    const filePath = path.join(CACHE_DIR, safePath);
    fs.stat(filePath, (err, stat) => {
        if (err || !stat.isFile()) {
            console.log(`${CLR.RED}[MISSING] /${safePath}${CLR.RESET}`);
            downloadFromCDN(req.path, filePath, (success) => {
                if (success) { console.log(`${CLR.GREEN}[SENT-CDN] /${safePath}${CLR.RESET}`); return res.sendFile(filePath); }
                if (serverConfig.spoof_missing_files) { console.log(`${CLR.YELLOW}[SPOOFED] /${safePath}${CLR.RESET}`); return res.status(200).send(""); }
                return res.status(404).send("File not found.");
            });
            return; 
        }
        console.log(`${CLR.GREEN}[SENT] /${safePath}${CLR.RESET}`);
        next();
    });
});


app.use("/cache", express.static(CACHE_DIR));

function startServer() {
    if (!fs.existsSync(SSL_KEY) || !fs.existsSync(SSL_CERT)) {
        console.log(`${CLR.RED}[ERROR] SSL files missing!${CLR.RESET}`); process.exit(1);
    }
    try {
        const server = https.createServer({ key: fs.readFileSync(SSL_KEY), cert: fs.readFileSync(SSL_CERT) }, app);
        server.listen(serverConfig.port_tcp, "0.0.0.0", () => {
            console.log("====================================");
            console.log(` HTTP v${version_chttp} | Status: ${CLR.GREEN}Online${CLR.RESET}`);
            console.log(` Port: ${serverConfig.port_tcp}`);
            console.log(` Dashboard: https://${serverConfig.ip}:${serverConfig.port_tcp}/dashboard`);
            console.log("====================================");
        });
    } catch (err) { console.log(`${CLR.RED}[STARTUP ERROR] ${err.message}${CLR.RESET}`); }
}
startServer();