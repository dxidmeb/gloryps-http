"use strict";
/**
 * items_codec.js — pure Node buffer logic for GTPS items.dat (v26).
 * Extracted from src/items_ref/converter_v26.js (browser converter) with all
 * DOM/FileReader/download bits removed. No side effects on require.
 *
 * Exports:
 *   decodeItems(buffer)  -> { version, item_count, items:[...] }
 *   encodeItems({version, item_count?, items}) -> Buffer
 *
 * Throws on unknown/unsupported version (>26) so callers can 400 gracefully.
 */

const ITEMS_SECRET_KEY = "PBG892FXX982ABC*";

const byteToHex = [];
for (let n = 0; n <= 0xff; ++n) byteToHex.push(n.toString(16).padStart(2, "0"));

function hex(u8) {
    const out = [];
    for (let i = 0; i < u8.length; ++i) out.push(byteToHex[u8[i]]);
    return out.join("").toUpperCase();
}

function read_buffer_number(buffer, pos, len) {
    let value = 0;
    for (let a = 0; a < len; a++) value += buffer[pos + a] << (a * 8);
    return value >>> 0; // unsigned
}

function read_buffer_string(buffer, pos, len, using_key, item_id) {
    let result = "";
    if (using_key) {
        for (let a = 0; a < len; a++)
            result += String.fromCharCode(buffer[a + pos] ^ ITEMS_SECRET_KEY.charCodeAt((item_id + a) % ITEMS_SECRET_KEY.length));
    } else {
        for (let a = 0; a < len; a++) result += String.fromCharCode(buffer[a + pos]);
    }
    return result;
}

// ---------------- decode ----------------
function decodeItems(bufIn) {
    const arrayBuffer = bufIn instanceof Uint8Array ? bufIn : new Uint8Array(bufIn);
    let mem_pos = 6;
    const version = read_buffer_number(arrayBuffer, 0, 2);
    const item_count = read_buffer_number(arrayBuffer, 2, 4);

    if (version > 26) {
        const err = new Error("Unsupported items.dat version: " + version);
        err.code = "UNSUPPORTED_VERSION";
        throw err;
    }

    const data_json = { version, item_count, items: [] };

    for (let a = 0; a < item_count; a++) {
        const item_id = read_buffer_number(arrayBuffer, mem_pos, 4); mem_pos += 4;
        const editable_type = arrayBuffer[mem_pos++];
        const item_category = arrayBuffer[mem_pos++];
        const action_type = arrayBuffer[mem_pos++];
        const hit_sound_type = arrayBuffer[mem_pos++];

        let len = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;
        const name = read_buffer_string(arrayBuffer, mem_pos, len, true, Number(item_id)); mem_pos += len;

        len = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;
        const texture = read_buffer_string(arrayBuffer, mem_pos, len); mem_pos += len;

        const texture_hash = read_buffer_number(arrayBuffer, mem_pos, 4); mem_pos += 4;
        const item_kind = arrayBuffer[mem_pos++];
        const val1 = read_buffer_number(arrayBuffer, mem_pos, 4); mem_pos += 4;
        const texture_x = arrayBuffer[mem_pos++];
        const texture_y = arrayBuffer[mem_pos++];
        const spread_type = arrayBuffer[mem_pos++];
        const is_stripey_wallpaper = arrayBuffer[mem_pos++];
        const collision_type = arrayBuffer[mem_pos++];
        let break_hits = arrayBuffer[mem_pos++];
        if ((break_hits % 6) !== 0) break_hits = break_hits + "r";
        else break_hits = break_hits / 6;

        const drop_chance = read_buffer_number(arrayBuffer, mem_pos, 4); mem_pos += 4;
        const clothing_type = arrayBuffer[mem_pos++];
        const rarity = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;
        const max_amount = arrayBuffer[mem_pos++];

        len = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;
        const extra_file = read_buffer_string(arrayBuffer, mem_pos, len); mem_pos += len;

        const extra_file_hash = read_buffer_number(arrayBuffer, mem_pos, 4); mem_pos += 4;
        const audio_volume = read_buffer_number(arrayBuffer, mem_pos, 4); mem_pos += 4;

        len = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;
        const pet_name = read_buffer_string(arrayBuffer, mem_pos, len); mem_pos += len;
        len = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;
        const pet_prefix = read_buffer_string(arrayBuffer, mem_pos, len); mem_pos += len;
        len = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;
        const pet_suffix = read_buffer_string(arrayBuffer, mem_pos, len); mem_pos += len;
        len = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;
        const pet_ability = read_buffer_string(arrayBuffer, mem_pos, len); mem_pos += len;

        const seed_base = arrayBuffer[mem_pos++];
        const seed_overlay = arrayBuffer[mem_pos++];
        const tree_base = arrayBuffer[mem_pos++];
        const tree_leaves = arrayBuffer[mem_pos++];

        const seed_color = {
            a: arrayBuffer[mem_pos++], r: arrayBuffer[mem_pos++],
            g: arrayBuffer[mem_pos++], b: arrayBuffer[mem_pos++]
        };
        const seed_overlay_color = {
            a: arrayBuffer[mem_pos++], r: arrayBuffer[mem_pos++],
            g: arrayBuffer[mem_pos++], b: arrayBuffer[mem_pos++]
        };

        mem_pos += 4; // skip ingredients

        const grow_time = read_buffer_number(arrayBuffer, mem_pos, 4); mem_pos += 4;
        const val2 = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;
        const is_rayman = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;

        len = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;
        const extra_options = read_buffer_string(arrayBuffer, mem_pos, len); mem_pos += len;
        len = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;
        const texture2 = read_buffer_string(arrayBuffer, mem_pos, len); mem_pos += len;
        len = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;
        const extra_options2 = read_buffer_string(arrayBuffer, mem_pos, len); mem_pos += len;

        const data_position_80 = hex(arrayBuffer.slice(mem_pos, mem_pos + 80)); mem_pos += 80;

        let punch_options = "", data_version_12 = "", int_version_13 = 0, int_version_14 = 0;
        let data_version_15 = "", str_version_15 = "", str_version_16 = "", int_version_17 = 0;
        let int_version_18 = 0, data_version_19 = "", int_version_21 = 0, str_version_22 = "";
        let int_version_23 = 0, byte_version_24 = 0, str_version_25 = "", int_version_26 = 0, byte_version_26 = 0;

        if (version >= 11) {
            len = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;
            punch_options = read_buffer_string(arrayBuffer, mem_pos, len); mem_pos += len;
        }
        if (version >= 12) { data_version_12 = hex(arrayBuffer.slice(mem_pos, mem_pos + 13)); mem_pos += 13; }
        if (version >= 13) { int_version_13 = read_buffer_number(arrayBuffer, mem_pos, 4); mem_pos += 4; }
        if (version >= 14) { int_version_14 = read_buffer_number(arrayBuffer, mem_pos, 4); mem_pos += 4; }
        if (version >= 15) {
            data_version_15 = hex(arrayBuffer.slice(mem_pos, mem_pos + 25)); mem_pos += 25;
            len = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;
            str_version_15 = read_buffer_string(arrayBuffer, mem_pos, len); mem_pos += len;
        }
        if (version >= 16) {
            len = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;
            str_version_16 = read_buffer_string(arrayBuffer, mem_pos, len); mem_pos += len;
        }
        if (version >= 17) { int_version_17 = read_buffer_number(arrayBuffer, mem_pos, 4); mem_pos += 4; }
        if (version >= 18) { int_version_18 = read_buffer_number(arrayBuffer, mem_pos, 4); mem_pos += 4; }
        if (version >= 19) { data_version_19 = hex(arrayBuffer.slice(mem_pos, mem_pos + 9)); mem_pos += 9; }
        if (version >= 21) { int_version_21 = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2; }
        if (version >= 22) {
            len = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;
            str_version_22 = read_buffer_string(arrayBuffer, mem_pos, len); mem_pos += len;
        }
        if (version >= 23) { int_version_23 = read_buffer_number(arrayBuffer, mem_pos, 4); mem_pos += 4; }
        if (version >= 24) { byte_version_24 = arrayBuffer[mem_pos++]; }
        if (version >= 25) {
            len = read_buffer_number(arrayBuffer, mem_pos, 2); mem_pos += 2;
            str_version_25 = read_buffer_string(arrayBuffer, mem_pos, len); mem_pos += len;
        }
        if (version >= 26) {
            int_version_26 = read_buffer_number(arrayBuffer, mem_pos, 4); mem_pos += 4;
            byte_version_26 = arrayBuffer[mem_pos++];
        }

        data_json.items[a] = {
            item_id, editable_type, item_category, action_type, hit_sound_type,
            name, texture, texture_hash, item_kind, val1, texture_x, texture_y,
            spread_type, is_stripey_wallpaper, collision_type, break_hits,
            drop_chance, clothing_type, rarity, max_amount, extra_file,
            extra_file_hash, audio_volume, pet_name, pet_prefix, pet_suffix,
            pet_ability, seed_base, seed_overlay, tree_base, tree_leaves,
            seed_color, seed_overlay_color, grow_time, val2, is_rayman,
            extra_options, texture2, extra_options2, data_position_80,
            punch_options, data_version_12, int_version_13, int_version_14,
            data_version_15, str_version_15, str_version_16, int_version_17,
            int_version_18, data_version_19, int_version_21, str_version_22,
            int_version_23, byte_version_24, str_version_25, int_version_26,
            byte_version_26
        };
    }
    return data_json;
}

// ---------------- encode ----------------
function encodeItems(result) {
    const buf = []; // sparse array of bytes, matches converter behavior
    const version = Number(result.version);
    const items = result.items || [];
    const item_count = (result.item_count != null) ? Number(result.item_count) : items.length;

    function wnum(pos, len, value) {
        value = Number(value) >>> 0;
        for (let a = 0; a < len; a++) buf[pos + a] = (value >> (a * 8)) & 255;
    }
    function wstr(pos, len, value, using_key, item_id) {
        for (let a = 0; a < len; a++) {
            if (using_key) buf[pos + a] = value.charCodeAt(a) ^ (ITEMS_SECRET_KEY.charCodeAt((a + item_id) % ITEMS_SECRET_KEY.length));
            else buf[pos + a] = value.charCodeAt(a);
        }
    }
    function whex(pos, hexString) {
        hexString = String(hexString || "").replace(/ /g, "");
        const m = hexString.match(/[\dA-F]{2}/gi) || [];
        for (const s of m) buf[pos++] = parseInt(s, 16);
    }

    let mem_pos = 6;
    wnum(0, 2, version);
    wnum(2, 4, item_count);

    for (let a = 0; a < item_count; a++) {
        const it = items[a];
        wnum(mem_pos, 4, it.item_id); mem_pos += 4;
        buf[mem_pos++] = it.editable_type;
        buf[mem_pos++] = it.item_category;
        buf[mem_pos++] = it.action_type;
        buf[mem_pos++] = it.hit_sound_type;

        wnum(mem_pos, 2, it.name.length); mem_pos += 2;
        wstr(mem_pos, it.name.length, it.name, 1, it.item_id); mem_pos += it.name.length;

        wnum(mem_pos, 2, it.texture.length); mem_pos += 2;
        wstr(mem_pos, it.texture.length, it.texture); mem_pos += it.texture.length;

        wnum(mem_pos, 4, it.texture_hash); mem_pos += 4;
        buf[mem_pos++] = it.item_kind;
        wnum(mem_pos, 4, it.val1); mem_pos += 4;
        buf[mem_pos++] = it.texture_x;
        buf[mem_pos++] = it.texture_y;
        buf[mem_pos++] = it.spread_type;
        buf[mem_pos++] = it.is_stripey_wallpaper;
        buf[mem_pos++] = it.collision_type;

        const bh = String(it.break_hits);
        if (bh[bh.length - 1] === "r") buf[mem_pos++] = Number(bh.slice(0, -1));
        else buf[mem_pos++] = Number(it.break_hits) * 6;

        wnum(mem_pos, 4, it.drop_chance); mem_pos += 4;
        buf[mem_pos++] = it.clothing_type;
        wnum(mem_pos, 2, it.rarity); mem_pos += 2;
        buf[mem_pos++] = it.max_amount;

        wnum(mem_pos, 2, it.extra_file.length); mem_pos += 2;
        wstr(mem_pos, it.extra_file.length, it.extra_file); mem_pos += it.extra_file.length;
        wnum(mem_pos, 4, it.extra_file_hash); mem_pos += 4;
        wnum(mem_pos, 4, it.audio_volume); mem_pos += 4;

        wnum(mem_pos, 2, it.pet_name.length); mem_pos += 2;
        wstr(mem_pos, it.pet_name.length, it.pet_name); mem_pos += it.pet_name.length;
        wnum(mem_pos, 2, it.pet_prefix.length); mem_pos += 2;
        wstr(mem_pos, it.pet_prefix.length, it.pet_prefix); mem_pos += it.pet_prefix.length;
        wnum(mem_pos, 2, it.pet_suffix.length); mem_pos += 2;
        wstr(mem_pos, it.pet_suffix.length, it.pet_suffix); mem_pos += it.pet_suffix.length;
        wnum(mem_pos, 2, it.pet_ability.length); mem_pos += 2;
        wstr(mem_pos, it.pet_ability.length, it.pet_ability); mem_pos += it.pet_ability.length;

        buf[mem_pos++] = it.seed_base;
        buf[mem_pos++] = it.seed_overlay;
        buf[mem_pos++] = it.tree_base;
        buf[mem_pos++] = it.tree_leaves;

        const sc = normColor(it.seed_color);
        buf[mem_pos++] = sc.a; buf[mem_pos++] = sc.r; buf[mem_pos++] = sc.g; buf[mem_pos++] = sc.b;
        const soc = normColor(it.seed_overlay_color);
        buf[mem_pos++] = soc.a; buf[mem_pos++] = soc.r; buf[mem_pos++] = soc.g; buf[mem_pos++] = soc.b;

        wnum(mem_pos, 4, 0); mem_pos += 4; // skip ingredients

        wnum(mem_pos, 4, it.grow_time); mem_pos += 4;
        wnum(mem_pos, 2, it.val2); mem_pos += 2;
        wnum(mem_pos, 2, it.is_rayman); mem_pos += 2;

        wnum(mem_pos, 2, it.extra_options.length); mem_pos += 2;
        wstr(mem_pos, it.extra_options.length, it.extra_options); mem_pos += it.extra_options.length;
        wnum(mem_pos, 2, it.texture2.length); mem_pos += 2;
        wstr(mem_pos, it.texture2.length, it.texture2); mem_pos += it.texture2.length;
        wnum(mem_pos, 2, it.extra_options2.length); mem_pos += 2;
        wstr(mem_pos, it.extra_options2.length, it.extra_options2); mem_pos += it.extra_options2.length;

        whex(mem_pos, it.data_position_80); mem_pos += 80;

        if (version >= 11) {
            wnum(mem_pos, 2, it.punch_options.length); mem_pos += 2;
            wstr(mem_pos, it.punch_options.length, it.punch_options); mem_pos += it.punch_options.length;
        }
        if (version >= 12) { whex(mem_pos, it.data_version_12); mem_pos += 13; }
        if (version >= 13) { wnum(mem_pos, 4, it.int_version_13); mem_pos += 4; }
        if (version >= 14) { wnum(mem_pos, 4, it.int_version_14); mem_pos += 4; }
        if (version >= 15) {
            whex(mem_pos, it.data_version_15); mem_pos += 25;
            wnum(mem_pos, 2, it.str_version_15.length); mem_pos += 2;
            wstr(mem_pos, it.str_version_15.length, it.str_version_15); mem_pos += it.str_version_15.length;
        }
        if (version >= 16) {
            wnum(mem_pos, 2, it.str_version_16.length); mem_pos += 2;
            wstr(mem_pos, it.str_version_16.length, it.str_version_16); mem_pos += it.str_version_16.length;
        }
        if (version >= 17) { wnum(mem_pos, 4, it.int_version_17); mem_pos += 4; }
        if (version >= 18) { wnum(mem_pos, 4, it.int_version_18); mem_pos += 4; }
        if (version >= 19) { whex(mem_pos, it.data_version_19); mem_pos += 9; }
        if (version >= 21) { wnum(mem_pos, 2, it.int_version_21); mem_pos += 2; }
        if (version >= 22) {
            wnum(mem_pos, 2, it.str_version_22.length); mem_pos += 2;
            wstr(mem_pos, it.str_version_22.length, it.str_version_22); mem_pos += it.str_version_22.length;
        }
        if (version >= 23) { wnum(mem_pos, 4, it.int_version_23); mem_pos += 4; }
        if (version >= 24) { buf[mem_pos++] = it.byte_version_24; }
        if (version >= 25) {
            wnum(mem_pos, 2, it.str_version_25.length); mem_pos += 2;
            wstr(mem_pos, it.str_version_25.length, it.str_version_25); mem_pos += it.str_version_25.length;
        }
        if (version >= 26) {
            wnum(mem_pos, 4, it.int_version_26); mem_pos += 4;
            buf[mem_pos++] = it.byte_version_26;
        }
    }

    // materialize sparse array to Buffer (undefined -> 0)
    const out = Buffer.alloc(mem_pos);
    for (let i = 0; i < mem_pos; i++) out[i] = buf[i] & 255 || 0;
    return out;
}

function normColor(c) {
    if (c && typeof c === "object") return { a: c.a & 255, r: c.r & 255, g: c.g & 255, b: c.b & 255 };
    if (typeof c === "string") {
        const p = c.split(",").map(Number);
        return { a: p[0] & 255, r: p[1] & 255, g: p[2] & 255, b: p[3] & 255 };
    }
    return { a: 0, r: 0, g: 0, b: 0 };
}

module.exports = { decodeItems, encodeItems, ITEMS_SECRET_KEY };
