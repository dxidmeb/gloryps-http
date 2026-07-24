"use strict";

const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

module.exports = (root_dir, getServerConfig) => {
    
    // Helper to get DB Path
    const getDbPath = () => {
        const config = getServerConfig();
        const rawPath = config.player_db_path || "../server/x64/Release/database/players";
        return path.resolve(root_dir, rawPath);
    };

    // API: List All Players & Count
    router.get("/list", (req, res) => {
        const dbPath = getDbPath();
        
        if (!fs.existsSync(dbPath)) {
            return res.json({ success: true, count: 0, players: [] }); 
        }

        fs.readdir(dbPath, (err, files) => {
            if (err) return res.status(500).json({ error: "Failed to read DB directory" });
            
            // Filter for json files and strip extension
            const players = files
                .filter(f => f.endsWith("_.json"))
                .map(f => f.replace("_.json", ""));
                
            res.json({ 
                success: true, 
                count: players.length, 
                players: players 
            });
        });
    });

    // API: Get Player Info (Editable Raw Data)
    router.post("/get", (req, res) => {
        const { name } = req.body;
        if (!name) return res.status(400).json({ error: "Player name is required" });

        const dbPath = getDbPath();
        const fileName = `${name.toLowerCase()}_.json`;
        const filePath = path.join(dbPath, fileName);

        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: `File not found: ${fileName}` });
        }

        try {
            const fileContent = fs.readFileSync(filePath, "utf8");
            const p = JSON.parse(fileContent);
            
            // Send specific raw fields for editing
            // We use the original keys from the JSON so we can save them back easily
            const editableData = {
                // Identity
                name: p.name,
                pass: p.pass,
                ip: p.ip,
                mac: p.mac,
                rid: p.rid,
                meta: p.meta,
                code: p.code,
                email: p.email,
                
                // Status
                lo: p.lo, // Last Online
                isActive: p.isActive,
                isActiveVerif: p.isActiveVerif,
                playtime: p.playtime,
                
                // Stats
                level: p.level,
                xp: p.xp,
                gems: p.gems,
                gtwl: p.gtwl,
                
                // Admin
                adminlevel: p.adminlevel,
                
                // Roles (Booleans)
                owner: p.owner,
                superdev: p.superdev,
                dev: p.dev,
                admin: p.admin,
                mod: p.mod,
                smod: p.smod,
                tmod: p.tmod,
                vip: p.vip,
                legend: p.legend,
                is_legend: p.is_legend,
                supp: p.supp,

                // Bank
                bank_wl: p.bank_wl,
                bank_dl: p.bank_dl,
                bank_bgl: p.bank_bgl,
                bank_ggl: p.bank_ggl,
                gems_bank: p.gems_bank,

                // Arrays (Editable as JSON strings if needed, or specific handling)
                worlds_owned: p.worlds_owned,
                la_wo: p.la_wo // Last worlds
            };

            // Calculate inventory count (Read Only)
            const inventoryCount = p.inventory ? p.inventory.length : 0;

            res.json({ 
                success: true, 
                data: editableData,
                meta: { inventory_count: inventoryCount }
            });
        } catch (e) {
            res.status(500).json({ error: "Failed to read player file: " + e.message });
        }
    });

    // API: Save Player Info
    router.post("/save", (req, res) => {
        const { name, data } = req.body;
        if (!name || !data) return res.status(400).json({ error: "Name and Data required" });

        const dbPath = getDbPath();
        const fileName = `${name.toLowerCase()}_.json`;
        const filePath = path.join(dbPath, fileName);

        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: "Player file does not exist." });
        }

        try {
            // 1. Read existing file to preserve fields we aren't editing (like inventory)
            const originalContent = fs.readFileSync(filePath, "utf8");
            let p = JSON.parse(originalContent);

            // 2. Merge new data
            // We loop through the incoming data and update the player object
            for (const [key, value] of Object.entries(data)) {
                // Security check: prevent overwriting critical structure if needed
                // For now, we allow editing everything sent
                p[key] = value;
            }

            // 3. Write back to disk
            fs.writeFileSync(filePath, JSON.stringify(p)); // Minified write
            
            res.json({ success: true });
        } catch (e) {
            res.status(500).json({ error: "Failed to save player file: " + e.message });
        }
    });

    return router;
};