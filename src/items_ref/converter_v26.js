var items_secret_key = "PBG892FXX982ABC*"
var data_json = {}
var encoded_buffer_file = [];

const byteToHex = [];

for (let n = 0; n <= 0xff; ++n) {
    const hexOctet = n.toString(16).padStart(2, "0");
    byteToHex.push(hexOctet);
}
const a = document.createElement("a");
var saveData = (function () {
    a.style = "display: none";
    return function (data, fileName) {
        blob = new Blob([data], { type: "octet/stream" }),
            url = window.URL.createObjectURL(blob);
        a.href = url;
        a.download = fileName;
        a.click();
        window.URL.revokeObjectURL(url);
    };
}());

var saveDataBuffer = (function () {
    a.style = "display: none";
    return function (data, fileName) {
        blob = new Blob([new Uint8Array(data)], { type: "octet/stream" }),
            url = window.URL.createObjectURL(blob);
        a.href = url;
        a.download = fileName;
        a.click();
        window.URL.revokeObjectURL(url);
    };
}());

function hex(arrayBuffer, is_without_space) {
    const buff = new Uint8Array(arrayBuffer);
    const hexOctets = [];
    for (let i = 0; i < buff.length; ++i) hexOctets.push(byteToHex[buff[i]]);
    return hexOctets.join(is_without_space ? "" : " ");
}

function read_buffer_number(buffer, pos, len) {
    let value = 0;
    for (let a = 0; a < len; a++) value += buffer[pos + a] << (a * 8)
    return value;
}

function write_buffer_number(pos, len, value) {
    for (let a = 0; a < len; a++) {
        encoded_buffer_file[pos + a] = (value >> (a * 8)) & 255;
    }
}

function write_buffer_string(pos, len, value, using_key, item_id) {
    for (let a = 0; a < len; a++) {
        if (using_key) encoded_buffer_file[pos + a] = value.charCodeAt(a) ^ (items_secret_key.charCodeAt((a + item_id) % items_secret_key.length))
        else encoded_buffer_file[pos + a] = value.charCodeAt(a)
    }
}

function hash_buffer(buffer, element, text) {
    var hash = 0x55555555;
    var toBuffer = new Uint8Array(buffer);
    for (let a = 0; a < toBuffer.length; a++) hash = (hash >>> 27) + (hash << 5) + toBuffer[a]
    document.getElementById(element).innerHTML = text + hash
}

function hexStringToArrayBuffer(pos, hexString) { 
    hexString = hexString.replace(/ /g, '');
    if (hexString.length % 2 != 0) console.log('WARNING: expecting an even number of characters in the hexString');
    var bad = hexString.match(/[G-Z\s]/i);
    if (bad) console.log('WARNING: found non-hex characters', bad);
    var integers = hexString.match(/[\dA-F]{2}/gi).map(function (s) {
        encoded_buffer_file[pos++] = parseInt(s, 16)
    });
    return integers
}

function read_buffer_string(buffer, pos, len, using_key, item_id) {
    var result = "";
    if (using_key) for (let a = 0; a < len; a++) result += String.fromCharCode(buffer[a + pos] ^ items_secret_key.charCodeAt((item_id + a) % items_secret_key.length))
    else for (let a = 0; a < len; a++) result += String.fromCharCode(buffer[a + pos])
    return result;
}

// Ensure elements exist before adding listeners to avoid null errors on generic pages
let decodeDatBtn = document.getElementById('decode_items_dat');
if (decodeDatBtn) decodeDatBtn.addEventListener('click', function () {
    var input = document.createElement('input');
    input.type = 'file';
    input.style.display = 'none';
    input.onchange = function (e) {
        var file = e.target.files[0];
        item_decoder(file);
    };
    document.body.appendChild(input);
    input.click();
});

let decodeDatEditorBtn = document.getElementById('decode_items_dat_editor');
if (decodeDatEditorBtn) decodeDatEditorBtn.addEventListener('click', function () {
    var input = document.createElement('input');
    input.type = 'file';
    input.style.display = 'none';
    input.onchange = function (e) {
        var file = e.target.files[0];
        item_decoder(file, true);
    };
    document.body.appendChild(input);
    input.click();
});

let encodeDatBtn = document.getElementById('encode_items_dat');
if (encodeDatBtn) encodeDatBtn.addEventListener('click', function () {
    var input = document.createElement('input');
    input.type = 'file';
    input.style.display = 'none';
    input.onchange = function (e) {
        var file = e.target.files[0];
        item_encoder(file);
    };
    document.body.appendChild(input);
    input.click();
});

function check_last_char(dest, src) {
    return dest[dest.length - 1] == src
}

function process_item_encoder(result, using_txt) {
    var mem_pos = 6;

    if (using_txt) {
        var version = 0;
        result = result.split("\n");

        for (let a = 0; a < result.length; a++) {
            var result1 = result[a].split("\\")
            if (result1[0] == "version") {
                version = Number(result1[1])
                write_buffer_number(0, 2, Number(result1[1]))
            }
            else if (result1[0] == "itemCount") write_buffer_number(2, 4, Number(result1[1]))
            else if (result1[0] == "add_item") {
                // item id
                write_buffer_number(mem_pos, 4, result1[1]);
                mem_pos += 4;

                encoded_buffer_file[mem_pos++] = Number(result1[2]); // editable type
                encoded_buffer_file[mem_pos++] = Number(result1[3]); // item category
                encoded_buffer_file[mem_pos++] = Number(result1[4]); // action type
                encoded_buffer_file[mem_pos++] = Number(result1[5]); // hit sound type

                // name
                write_buffer_number(mem_pos, 2, result1[6].length);
                mem_pos += 2;
                write_buffer_string(mem_pos, result1[6].length, result1[6], 1, Number(result1[1]))
                mem_pos += result1[6].length

                // texture
                write_buffer_number(mem_pos, 2, result1[7].length);
                mem_pos += 2;
                write_buffer_string(mem_pos, result1[7].length, result1[7])
                mem_pos += result1[7].length

                // texture hash
                write_buffer_number(mem_pos, 4, result1[8])
                mem_pos += 4;

                encoded_buffer_file[mem_pos++] = Number(result1[9]) // item kind

                // val1
                write_buffer_number(mem_pos, 4, result1[10])
                mem_pos += 4;

                encoded_buffer_file[mem_pos++] = Number(result1[11]) // texture x
                encoded_buffer_file[mem_pos++] = Number(result1[12]) // texture y
                encoded_buffer_file[mem_pos++] = Number(result1[13]) // spread type
                encoded_buffer_file[mem_pos++] = Number(result1[14]) // is stripey wallpaper
                encoded_buffer_file[mem_pos++] = Number(result1[15]) // collision type

                // break hits
                if (result1[16].includes("r")) encoded_buffer_file[mem_pos++] = Number(result1[16].slice(0, -1))
                else encoded_buffer_file[mem_pos++] = Number(result1[16]) * 6

                // drop chance
                write_buffer_number(mem_pos, 4, result1[17])
                mem_pos += 4;

                encoded_buffer_file[mem_pos++] = Number(result1[18]) // clothing type

                // rarity
                write_buffer_number(mem_pos, 2, result1[19])
                mem_pos += 2;

                encoded_buffer_file[mem_pos++] = Number(result1[20]) // max amount

                // extra file
                write_buffer_number(mem_pos, 2, result1[21].length);
                mem_pos += 2;
                write_buffer_string(mem_pos, result1[21].length, result1[21])
                mem_pos += result1[21].length

                // extra file hash
                write_buffer_number(mem_pos, 4, result1[22])
                mem_pos += 4;

                // audio volume
                write_buffer_number(mem_pos, 4, result1[23])
                mem_pos += 4;

                // pet name
                write_buffer_number(mem_pos, 2, result1[24].length);
                mem_pos += 2;
                write_buffer_string(mem_pos, result1[24].length, result1[24])
                mem_pos += result1[24].length

                // pet prefix
                write_buffer_number(mem_pos, 2, result1[25].length);
                mem_pos += 2;
                write_buffer_string(mem_pos, result1[25].length, result1[25])
                mem_pos += result1[25].length

                // pet suffix
                write_buffer_number(mem_pos, 2, result1[26].length);
                mem_pos += 2;
                write_buffer_string(mem_pos, result1[26].length, result1[26])
                mem_pos += result1[26].length

                // pet ability
                write_buffer_number(mem_pos, 2, result1[27].length);
                mem_pos += 2;
                write_buffer_string(mem_pos, result1[27].length, result1[27])
                mem_pos += result1[27].length

                encoded_buffer_file[mem_pos++] = Number(result1[28]) // seed base
                encoded_buffer_file[mem_pos++] = Number(result1[29]) // seed overlay
                encoded_buffer_file[mem_pos++] = Number(result1[30]) // tree base
                encoded_buffer_file[mem_pos++] = Number(result1[31]) // tree leaves

                // seed color (ARGB)
                var to_object = result1[32].split(",")
                encoded_buffer_file[mem_pos++] = to_object[0] // seed color (A)
                encoded_buffer_file[mem_pos++] = to_object[1] // seed color (R)
                encoded_buffer_file[mem_pos++] = to_object[2] // seed color (G)
                encoded_buffer_file[mem_pos++] = to_object[3] // seed color (B)

                // seed overlay color (ARGB)
                to_object = result1[33].split(",")
                encoded_buffer_file[mem_pos++] = to_object[0] // seed color overlay (A)
                encoded_buffer_file[mem_pos++] = to_object[1] // seed color overlay (A)
                encoded_buffer_file[mem_pos++] = to_object[2] // seed color overlay (A)
                encoded_buffer_file[mem_pos++] = to_object[3] // seed color overlay (A)

                // ingredients (Skip)
                write_buffer_number(mem_pos, 4, 0);
                mem_pos += 4;

                // grow time
                write_buffer_number(mem_pos, 4, result1[34]);
                mem_pos += 4;

                // val2
                write_buffer_number(mem_pos, 2, result1[35]);
                mem_pos += 2;

                // is rayman
                write_buffer_number(mem_pos, 2, result1[36]);
                mem_pos += 2;

                // extra options
                write_buffer_number(mem_pos, 2, result1[37].length);
                mem_pos += 2;
                write_buffer_string(mem_pos, result1[37].length, result1[37])
                mem_pos += result1[37].length

                // texture2
                write_buffer_number(mem_pos, 2, result1[38].length);
                mem_pos += 2;
                write_buffer_string(mem_pos, result1[38].length, result1[38])
                mem_pos += result1[38].length

                // extra options2
                write_buffer_number(mem_pos, 2, result1[39].length);
                mem_pos += 2;
                write_buffer_string(mem_pos, result1[39].length, result1[39])
                mem_pos += result1[39].length

                // Data (Position 80)
                hexStringToArrayBuffer(mem_pos, result1[40])
                mem_pos += 80;

                if (version >= 11) {
                    write_buffer_number(mem_pos, 2, result1[41].length);
                    mem_pos += 2;
                    write_buffer_string(mem_pos, result1[41].length, result1[41])
                    mem_pos += result1[41].length
                }
                if (version >= 12) {
                    hexStringToArrayBuffer(mem_pos, result1[42])
                    mem_pos += 13;
                }
                if (version >= 13) {
                    write_buffer_number(mem_pos, 4, result1[43])
                    mem_pos += 4;
                }
                if (version >= 14) {
                    write_buffer_number(mem_pos, 4, result1[44])
                    mem_pos += 4;
                }
                if (version >= 15) {
                    hexStringToArrayBuffer(mem_pos, result1[45])
                    mem_pos += 25;
                    write_buffer_number(mem_pos, 2, result1[46].length);
                    mem_pos += 2;
                    write_buffer_string(mem_pos, result1[46].length, result1[46])
                    mem_pos += result1[46].length
                }
                if (version >= 16) {
                    write_buffer_number(mem_pos, 2, result1[47].length);
                    mem_pos += 2;
                    write_buffer_string(mem_pos, result1[47].length, result1[47])
                    mem_pos += result1[47].length
                }
                if (version >= 17) {
                    write_buffer_number(mem_pos, 4, result1[48])
                    mem_pos += 4;
                }
                if (version >= 18) {
                    write_buffer_number(mem_pos, 4, result1[49])
                    mem_pos += 4;
                }
                if (version >= 19) {
                    hexStringToArrayBuffer(mem_pos, result1[50])
                    mem_pos += 9;
                }
                if (version >= 21) {
                    write_buffer_number(mem_pos, 2, result1[51])
                    mem_pos += 2;
                }
                if (version >= 22) {
                    write_buffer_number(mem_pos, 2, result1[52].length);
                    mem_pos += 2;
                    write_buffer_string(mem_pos, result1[52].length, result1[52])
                    mem_pos += result1[52].length
                }
                if (version >= 23) {
                    write_buffer_number(mem_pos, 4, result1[53])
                    mem_pos += 4;
                }
                if (version >= 24) {
                    encoded_buffer_file[mem_pos++] = Number(result1[54])
                }
                if (version >= 25) {
                    write_buffer_number(mem_pos, 2, result1[55].length);
                    mem_pos += 2;
                    write_buffer_string(mem_pos, result1[55].length, result1[55])
                    mem_pos += result1[55].length
                }
                if (version >= 26) {
                    write_buffer_number(mem_pos, 4, result1[56])
                    mem_pos += 4;
                    encoded_buffer_file[mem_pos++] = Number(result1[57])
                }
            }
        }
    } else {
        write_buffer_number(0, 2, result.version)
        write_buffer_number(2, 4, result.item_count)
        for (let a = 0; a < result.item_count; a++) {
            write_buffer_number(mem_pos, 4, result.items[a].item_id);
            mem_pos += 4;
            encoded_buffer_file[mem_pos++] = result.items[a].editable_type
            encoded_buffer_file[mem_pos++] = result.items[a].item_category
            encoded_buffer_file[mem_pos++] = result.items[a].action_type
            encoded_buffer_file[mem_pos++] = result.items[a].hit_sound_type
            write_buffer_number(mem_pos, 2, result.items[a].name.length);
            mem_pos += 2;
            write_buffer_string(mem_pos, result.items[a].name.length, result.items[a].name, 1, result.items[a].item_id)
            mem_pos += result.items[a].name.length
            write_buffer_number(mem_pos, 2, result.items[a].texture.length);
            mem_pos += 2;
            write_buffer_string(mem_pos, result.items[a].texture.length, result.items[a].texture)
            mem_pos += result.items[a].texture.length
            write_buffer_number(mem_pos, 4, result.items[a].texture_hash)
            mem_pos += 4;
            encoded_buffer_file[mem_pos++] = result.items[a].item_kind
            write_buffer_number(mem_pos, 4, result.items[a].val1)
            mem_pos += 4;
            encoded_buffer_file[mem_pos++] = result.items[a].texture_x
            encoded_buffer_file[mem_pos++] = result.items[a].texture_y
            encoded_buffer_file[mem_pos++] = result.items[a].spread_type
            encoded_buffer_file[mem_pos++] = result.items[a].is_stripey_wallpaper
            encoded_buffer_file[mem_pos++] = result.items[a].collision_type

            if (check_last_char(result.items[a].break_hits.toString(), "r")) encoded_buffer_file[mem_pos++] = Number(result.items[a].break_hits.toString().slice(0, -1))
            else encoded_buffer_file[mem_pos++] = Number(result.items[a].break_hits) * 6

            write_buffer_number(mem_pos, 4, result.items[a].drop_chance)
            mem_pos += 4;
            encoded_buffer_file[mem_pos++] = result.items[a].clothing_type
            write_buffer_number(mem_pos, 2, result.items[a].rarity)
            mem_pos += 2;

            encoded_buffer_file[mem_pos++] = result.items[a].max_amount
            write_buffer_number(mem_pos, 2, result.items[a].extra_file.length);
            mem_pos += 2;
            write_buffer_string(mem_pos, result.items[a].extra_file.length, result.items[a].extra_file)
            mem_pos += result.items[a].extra_file.length
            write_buffer_number(mem_pos, 4, result.items[a].extra_file_hash)
            mem_pos += 4;
            write_buffer_number(mem_pos, 4, result.items[a].audio_volume)
            mem_pos += 4;
            write_buffer_number(mem_pos, 2, result.items[a].pet_name.length);
            mem_pos += 2;
            write_buffer_string(mem_pos, result.items[a].pet_name.length, result.items[a].pet_name)
            mem_pos += result.items[a].pet_name.length
            write_buffer_number(mem_pos, 2, result.items[a].pet_prefix.length);
            mem_pos += 2;
            write_buffer_string(mem_pos, result.items[a].pet_prefix.length, result.items[a].pet_prefix)
            mem_pos += result.items[a].pet_prefix.length
            write_buffer_number(mem_pos, 2, result.items[a].pet_suffix.length);
            mem_pos += 2;
            write_buffer_string(mem_pos, result.items[a].pet_suffix.length, result.items[a].pet_suffix)
            mem_pos += result.items[a].pet_suffix.length
            write_buffer_number(mem_pos, 2, result.items[a].pet_ability.length);
            mem_pos += 2;
            write_buffer_string(mem_pos, result.items[a].pet_ability.length, result.items[a].pet_ability)
            mem_pos += result.items[a].pet_ability.length
            encoded_buffer_file[mem_pos++] = result.items[a].seed_base
            encoded_buffer_file[mem_pos++] = result.items[a].seed_overlay
            encoded_buffer_file[mem_pos++] = result.items[a].tree_base
            encoded_buffer_file[mem_pos++] = result.items[a].tree_leaves
            encoded_buffer_file[mem_pos++] = result.items[a].seed_color.a
            encoded_buffer_file[mem_pos++] = result.items[a].seed_color.r
            encoded_buffer_file[mem_pos++] = result.items[a].seed_color.g
            encoded_buffer_file[mem_pos++] = result.items[a].seed_color.b
            encoded_buffer_file[mem_pos++] = result.items[a].seed_overlay_color.a
            encoded_buffer_file[mem_pos++] = result.items[a].seed_overlay_color.r
            encoded_buffer_file[mem_pos++] = result.items[a].seed_overlay_color.g
            encoded_buffer_file[mem_pos++] = result.items[a].seed_overlay_color.b
            write_buffer_number(mem_pos, 4, 0); // skipping ingredients
            mem_pos += 4;
            write_buffer_number(mem_pos, 4, result.items[a].grow_time);
            mem_pos += 4;
            write_buffer_number(mem_pos, 2, result.items[a].val2);
            mem_pos += 2;
            write_buffer_number(mem_pos, 2, result.items[a].is_rayman);
            mem_pos += 2;
            write_buffer_number(mem_pos, 2, result.items[a].extra_options.length);
            mem_pos += 2;
            write_buffer_string(mem_pos, result.items[a].extra_options.length, result.items[a].extra_options)
            mem_pos += result.items[a].extra_options.length
            write_buffer_number(mem_pos, 2, result.items[a].texture2.length);
            mem_pos += 2;
            write_buffer_string(mem_pos, result.items[a].texture2.length, result.items[a].texture2)
            mem_pos += result.items[a].texture2.length
            write_buffer_number(mem_pos, 2, result.items[a].extra_options2.length);
            mem_pos += 2;
            write_buffer_string(mem_pos, result.items[a].extra_options2.length, result.items[a].extra_options2)
            mem_pos += result.items[a].extra_options2.length
            hexStringToArrayBuffer(mem_pos, result.items[a].data_position_80)
            mem_pos += 80;
            
            if (result.version >= 11) {
                write_buffer_number(mem_pos, 2, result.items[a].punch_options.length);
                mem_pos += 2;
                write_buffer_string(mem_pos, result.items[a].punch_options.length, result.items[a].punch_options)
                mem_pos += result.items[a].punch_options.length
            }
            if (result.version >= 12) {
                hexStringToArrayBuffer(mem_pos, result.items[a].data_version_12)
                mem_pos += 13;
            }
            if (result.version >= 13) {
                write_buffer_number(mem_pos, 4, result.items[a].int_version_13)
                mem_pos += 4;
            }
            if (result.version >= 14) {
                write_buffer_number(mem_pos, 4, result.items[a].int_version_14)
                mem_pos += 4;
            }
            if (result.version >= 15) {
                hexStringToArrayBuffer(mem_pos, result.items[a].data_version_15)
                mem_pos += 25;
                write_buffer_number(mem_pos, 2, result.items[a].str_version_15.length);
                mem_pos += 2;
                write_buffer_string(mem_pos, result.items[a].str_version_15.length, result.items[a].str_version_15)
                mem_pos += result.items[a].str_version_15.length
            }
            if (result.version >= 16) {
                write_buffer_number(mem_pos, 2, result.items[a].str_version_16.length);
                mem_pos += 2;
                write_buffer_string(mem_pos, result.items[a].str_version_16.length, result.items[a].str_version_16)
                mem_pos += result.items[a].str_version_16.length
            }
            if (result.version >= 17) {
                write_buffer_number(mem_pos, 4, result.items[a].int_version_17)
                mem_pos += 4;
            }
            if (result.version >= 18) {
                write_buffer_number(mem_pos, 4, result.items[a].int_version_18)
                mem_pos += 4;
            }
            if (result.version >= 19) {
                hexStringToArrayBuffer(mem_pos, result.items[a].data_version_19)
                mem_pos += 9;
            }
            if (result.version >= 21) {
                write_buffer_number(mem_pos, 2, result.items[a].int_version_21)
                mem_pos += 2;
            }
            if (result.version >= 22) {
                write_buffer_number(mem_pos, 2, result.items[a].str_version_22.length);
                mem_pos += 2;
                write_buffer_string(mem_pos, result.items[a].str_version_22.length, result.items[a].str_version_22)
                mem_pos += result.items[a].str_version_22.length
            }
            if (result.version >= 23) {
                write_buffer_number(mem_pos, 4, result.items[a].int_version_23)
                mem_pos += 4;
            }
            if (result.version >= 24) {
                encoded_buffer_file[mem_pos++] = result.items[a].byte_version_24
            }
            if (result.version >= 25) {
                write_buffer_number(mem_pos, 2, result.items[a].str_version_25.length);
                mem_pos += 2;
                write_buffer_string(mem_pos, result.items[a].str_version_25.length, result.items[a].str_version_25)
                mem_pos += result.items[a].str_version_25.length
            }
            if (result.version >= 26) {
                write_buffer_number(mem_pos, 4, result.items[a].int_version_26)
                mem_pos += 4;
                encoded_buffer_file[mem_pos++] = result.items[a].byte_version_26
            }
        }
    }
}

function item_encoder(file, using_editor) {
    if (using_editor) {
        process_item_encoder(data_json, 0);
        saveDataBuffer(encoded_buffer_file, "items.dat")
        hash_buffer(encoded_buffer_file, "items_dat_hash_2", "Encoded Items dat Hash: ")
        return encoded_buffer_file = []
    } else {
        var reader = new FileReader();
        reader.readAsText(file);

        reader.onload = function (e) {
            try {
                let using_txt_mode = document.getElementById("using_txt_mode");
                if (using_txt_mode && using_txt_mode.checked) process_item_encoder(e.target.result, 1)
                else process_item_encoder(JSON.parse(e.target.result), 0)
                saveDataBuffer(encoded_buffer_file, "items.dat")

                hash_buffer(encoded_buffer_file, "items_dat_hash_1", "Encoded Items dat Hash: ")
                return encoded_buffer_file = []
            } catch (error) {
                console.error('Error parsing JSON/TXT:', error);
            }
        }
    }

}

function item_decoder(file, using_editor) {
    data_json = {}
    let mem_pos = 6;
    var reader = new FileReader()
    reader.readAsArrayBuffer(file);

    reader.onload = function (e) {
        var arrayBuffer = new Uint8Array(e.target.result);
        var version = read_buffer_number(arrayBuffer, 0, 2);
        var item_count = read_buffer_number(arrayBuffer, 2, 4);

        if (version > 26) {
            if(window.Swal) {
                return Swal.mixin({
                    toast: true,
                    position: 'top-end',
                    showConfirmButton: false,
                    timer: 3000
                }).fire({
                    icon: 'error',
                    title: "Your items.dat version is " + version + ", and This decoder doesnt support that version!"
                })
            } else {
                return alert("Your items.dat version is " + version + ", and This decoder doesnt support that version!");
            }
        }
        data_json.version = version
        data_json.item_count = item_count
        data_json.items = []

        for (let a = 0; a < item_count; a++) {
            var item_id = read_buffer_number(arrayBuffer, mem_pos, 4);
            mem_pos += 4;

            var editable_type = arrayBuffer[mem_pos++];
            var item_category = arrayBuffer[mem_pos++];
            var action_type = arrayBuffer[mem_pos++];
            var hit_sound_type = arrayBuffer[mem_pos++];

            var len = read_buffer_number(arrayBuffer, mem_pos, 2)
            mem_pos += 2;
            var name = read_buffer_string(arrayBuffer, mem_pos, len, true, Number(item_id));
            mem_pos += len;

            len = read_buffer_number(arrayBuffer, mem_pos, 2)
            mem_pos += 2;
            var texture = read_buffer_string(arrayBuffer, mem_pos, len);
            mem_pos += len;

            var texture_hash = read_buffer_number(arrayBuffer, mem_pos, 4);
            mem_pos += 4;

            var item_kind = arrayBuffer[mem_pos++];

            var val1 = read_buffer_number(arrayBuffer, mem_pos, 4);
            mem_pos += 4;

            var texture_x = arrayBuffer[mem_pos++];
            var texture_y = arrayBuffer[mem_pos++];
            var spread_type = arrayBuffer[mem_pos++];
            var is_stripey_wallpaper = arrayBuffer[mem_pos++];
            var collision_type = arrayBuffer[mem_pos++];
            var break_hits = arrayBuffer[mem_pos++];

            if ((break_hits % 6) !== 0) break_hits = break_hits + "r"
            else break_hits = break_hits / 6

            var drop_chance = read_buffer_number(arrayBuffer, mem_pos, 4);
            mem_pos += 4;

            var clothing_type = arrayBuffer[mem_pos++];

            var rarity = read_buffer_number(arrayBuffer, mem_pos, 2);
            mem_pos += 2;

            var max_amount = arrayBuffer[mem_pos++];

            len = read_buffer_number(arrayBuffer, mem_pos, 2)
            mem_pos += 2;
            var extra_file = read_buffer_string(arrayBuffer, mem_pos, len);
            mem_pos += len;

            var extra_file_hash = read_buffer_number(arrayBuffer, mem_pos, 4);
            mem_pos += 4;

            var audio_volume = read_buffer_number(arrayBuffer, mem_pos, 4);
            mem_pos += 4;

            len = read_buffer_number(arrayBuffer, mem_pos, 2)
            mem_pos += 2;
            var pet_name = read_buffer_string(arrayBuffer, mem_pos, len);
            mem_pos += len;

            len = read_buffer_number(arrayBuffer, mem_pos, 2)
            mem_pos += 2;
            var pet_prefix = read_buffer_string(arrayBuffer, mem_pos, len);
            mem_pos += len;

            len = read_buffer_number(arrayBuffer, mem_pos, 2)
            mem_pos += 2;
            var pet_suffix = read_buffer_string(arrayBuffer, mem_pos, len);
            mem_pos += len;

            len = read_buffer_number(arrayBuffer, mem_pos, 2);
            mem_pos += 2;
            var pet_ability = read_buffer_string(arrayBuffer, mem_pos, len);
            mem_pos += len;

            var seed_base = arrayBuffer[mem_pos++];
            var seed_overlay = arrayBuffer[mem_pos++];
            var tree_base = arrayBuffer[mem_pos++];
            var tree_leaves = arrayBuffer[mem_pos++];

            var seed_color_a = arrayBuffer[mem_pos++];
            var seed_color_r = arrayBuffer[mem_pos++];
            var seed_color_g = arrayBuffer[mem_pos++];
            var seed_color_b = arrayBuffer[mem_pos++];
            var seed_overlay_color_a = arrayBuffer[mem_pos++];
            var seed_overlay_color_r = arrayBuffer[mem_pos++];
            var seed_overlay_color_g = arrayBuffer[mem_pos++];
            var seed_overlay_color_b = arrayBuffer[mem_pos++];

            mem_pos += 4; // skipping ingredients

            var grow_time = read_buffer_number(arrayBuffer, mem_pos, 4);
            mem_pos += 4;

            var val2 = read_buffer_number(arrayBuffer, mem_pos, 2);
            mem_pos += 2;
            var is_rayman = read_buffer_number(arrayBuffer, mem_pos, 2);
            mem_pos += 2;

            len = read_buffer_number(arrayBuffer, mem_pos, 2)
            mem_pos += 2;
            var extra_options = read_buffer_string(arrayBuffer, mem_pos, len);
            mem_pos += len;

            len = read_buffer_number(arrayBuffer, mem_pos, 2)
            mem_pos += 2;
            var texture2 = read_buffer_string(arrayBuffer, mem_pos, len);
            mem_pos += len;

            len = read_buffer_number(arrayBuffer, mem_pos, 2)
            mem_pos += 2;
            var extra_options2 = read_buffer_string(arrayBuffer, mem_pos, len);
            mem_pos += len;

            let is_txt_mode = false;
            let using_txt_el = document.getElementById("using_txt_mode");
            if (using_txt_el && using_txt_el.checked) is_txt_mode = true;

            var data_position_80 = hex(arrayBuffer.slice(mem_pos, mem_pos + 80), true).toUpperCase()
            mem_pos += 80;

            var punch_options = "", data_version_12 = "", int_version_13 = 0, int_version_14 = 0;
            var data_version_15 = "", str_version_15 = "", str_version_16 = "", int_version_17 = 0;
            var int_version_18 = 0, data_version_19 = "", int_version_21 = 0, str_version_22 = "";
            var int_version_23 = 0, byte_version_24 = 0, str_version_25 = "", int_version_26 = 0, byte_version_26 = 0;

            if (version >= 11) {
                len = read_buffer_number(arrayBuffer, mem_pos, 2)
                mem_pos += 2;
                punch_options = read_buffer_string(arrayBuffer, mem_pos, len);
                mem_pos += len;
            }
            if (version >= 12) {
                data_version_12 = hex(arrayBuffer.slice(mem_pos, mem_pos + 13), true).toUpperCase()
                mem_pos += 13;
            }
            if (version >= 13) {
                int_version_13 = read_buffer_number(arrayBuffer, mem_pos, 4)
                mem_pos += 4;
            }
            if (version >= 14) {
                int_version_14 = read_buffer_number(arrayBuffer, mem_pos, 4)
                mem_pos += 4;
            }
            if (version >= 15) {
                data_version_15 = hex(arrayBuffer.slice(mem_pos, mem_pos + 25), true).toUpperCase()
                mem_pos += 25;

                len = read_buffer_number(arrayBuffer, mem_pos, 2);
                mem_pos += 2;
                str_version_15 = read_buffer_string(arrayBuffer, mem_pos, len);
                mem_pos += len
            }
            if (version >= 16) {
                len = read_buffer_number(arrayBuffer, mem_pos, 2)
                mem_pos += 2;
                str_version_16 = read_buffer_string(arrayBuffer, mem_pos, len);
                mem_pos += len
            }
            if (version >= 17) {
                int_version_17 = read_buffer_number(arrayBuffer, mem_pos, 4)
                mem_pos += 4;
            }
            if (version >= 18) {
                int_version_18 = read_buffer_number(arrayBuffer, mem_pos, 4)
                mem_pos += 4;
            }
            if (version >= 19) {
                data_version_19 = hex(arrayBuffer.slice(mem_pos, mem_pos + 9), true).toUpperCase()
                mem_pos += 9;
            }
            if (version >= 21) {
                int_version_21 = read_buffer_number(arrayBuffer, mem_pos, 2)
                mem_pos += 2;
            }
            if (version >= 22) {
                len = read_buffer_number(arrayBuffer, mem_pos, 2)
                mem_pos += 2;
                str_version_22 = read_buffer_string(arrayBuffer, mem_pos, len);
                mem_pos += len
            }
            if (version >= 23) {
                int_version_23 = read_buffer_number(arrayBuffer, mem_pos, 4)
                mem_pos += 4;
            }
            if (version >= 24) {
                byte_version_24 = arrayBuffer[mem_pos++];
            }
            if (version >= 25) {
                len = read_buffer_number(arrayBuffer, mem_pos, 2)
                mem_pos += 2;
                str_version_25 = read_buffer_string(arrayBuffer, mem_pos, len);
                mem_pos += len
            }
            if (version >= 26) {
                int_version_26 = read_buffer_number(arrayBuffer, mem_pos, 4)
                mem_pos += 4;
                byte_version_26 = arrayBuffer[mem_pos++];
            }

            if (item_id != a) console.log(`Unordered Items at ${a}`)

            data_json.items[a] = {}
            data_json.items[a].item_id = item_id
            data_json.items[a].editable_type = editable_type
            data_json.items[a].item_category = item_category
            data_json.items[a].action_type = action_type
            data_json.items[a].hit_sound_type = hit_sound_type
            data_json.items[a].name = name
            data_json.items[a].texture = texture
            data_json.items[a].texture_hash = texture_hash
            data_json.items[a].item_kind = item_kind
            data_json.items[a].val1 = val1
            data_json.items[a].texture_x = texture_x
            data_json.items[a].texture_y = texture_y
            data_json.items[a].spread_type = spread_type
            data_json.items[a].is_stripey_wallpaper = is_stripey_wallpaper
            data_json.items[a].collision_type = collision_type
            data_json.items[a].break_hits = break_hits
            data_json.items[a].drop_chance = drop_chance
            data_json.items[a].clothing_type = clothing_type
            data_json.items[a].rarity = rarity
            data_json.items[a].max_amount = max_amount
            data_json.items[a].extra_file = extra_file
            data_json.items[a].extra_file_hash = extra_file_hash
            data_json.items[a].audio_volume = audio_volume
            data_json.items[a].pet_name = pet_name
            data_json.items[a].pet_prefix = pet_prefix
            data_json.items[a].pet_suffix = pet_suffix
            data_json.items[a].pet_ability = pet_ability
            data_json.items[a].seed_base = seed_base
            data_json.items[a].seed_overlay = seed_overlay
            data_json.items[a].tree_base = tree_base
            data_json.items[a].tree_leaves = tree_leaves

            if (is_txt_mode) {
                data_json.items[a].seed_color = `${seed_color_a},${seed_color_r},${seed_color_g},${seed_color_b}`
                data_json.items[a].seed_overlay_color = `${seed_overlay_color_a},${seed_overlay_color_r},${seed_overlay_color_g},${seed_overlay_color_b}`
            } else {
                data_json.items[a].seed_color = {}
                data_json.items[a].seed_color.a = seed_color_a
                data_json.items[a].seed_color.r = seed_color_r
                data_json.items[a].seed_color.g = seed_color_g
                data_json.items[a].seed_color.b = seed_color_b

                data_json.items[a].seed_overlay_color = {}
                data_json.items[a].seed_overlay_color.a = seed_overlay_color_a
                data_json.items[a].seed_overlay_color.r = seed_overlay_color_r
                data_json.items[a].seed_overlay_color.g = seed_overlay_color_g
                data_json.items[a].seed_overlay_color.b = seed_overlay_color_b
            }

            data_json.items[a].grow_time = grow_time
            data_json.items[a].val2 = val2
            data_json.items[a].is_rayman = is_rayman
            data_json.items[a].extra_options = extra_options
            data_json.items[a].texture2 = texture2
            data_json.items[a].extra_options2 = extra_options2
            data_json.items[a].data_position_80 = data_position_80
            data_json.items[a].punch_options = punch_options
            data_json.items[a].data_version_12 = data_version_12
            data_json.items[a].int_version_13 = int_version_13
            data_json.items[a].int_version_14 = int_version_14
            data_json.items[a].data_version_15 = data_version_15
            data_json.items[a].str_version_15 = str_version_15
            data_json.items[a].str_version_16 = str_version_16
            data_json.items[a].int_version_17 = int_version_17
            data_json.items[a].int_version_18 = int_version_18
            data_json.items[a].data_version_19 = data_version_19
            data_json.items[a].int_version_21 = int_version_21
            data_json.items[a].str_version_22 = str_version_22
            data_json.items[a].int_version_23 = int_version_23
            data_json.items[a].byte_version_24 = byte_version_24
            data_json.items[a].str_version_25 = str_version_25
            data_json.items[a].int_version_26 = int_version_26
            data_json.items[a].byte_version_26 = byte_version_26
        }
        if (using_editor) {
            let itemsListEl = document.getElementById("itemsList");
            let saveDiv = document.getElementById("save_items_dat_div");
            if (itemsListEl && typeof $ !== 'undefined' && $.fn && $.fn.dataTable) {
                if (!$.fn.dataTable.isDataTable("#itemsList")) {
                    itemsListEl.classList.remove("d-none")
                    if(saveDiv) saveDiv.classList.remove("d-none")
                    $("#itemsList").DataTable({
                        scrollY: "500px",
                        scrollX: true,
                        scrollCollapse: true,
                        paging: true,
                        fixedColumns: {
                            left: 1,
                            right: 1
                        }, "lengthChange": false, "autoWidth": false,
                        "columnDefs": [
                            {
                                "targets": [0],
                                "render": function (data, type, full, meta) {
                                    return type === 'display' && typeof data === 'string' ?
                                        data.replace(/</g, '&lt;').replace(/>/g, '&gt;') : data;
                                }
                            }
                        ]
                    }).buttons().container().appendTo('#itemsList_wrapper .col-md-6:eq(0)');
                    $('#itemsList').DataTable().columns.adjust()
                    $(window).resize(function () {
                        $('#itemsList').DataTable().columns.adjust()
                    });
                }
                var result = []
                for (let a = 0; a < item_count; a++) {
                    result[a] = []
                    result[a][0] = data_json.items[a].item_id
                    result[a][1] = data_json.items[a].name
                    result[a][2] = `<center><button class="btn btn-primary" onclick="editItems(${a})">Edit/Info</button></center>`
                }
                $("#itemsList").DataTable().rows.add(result).draw()
                result = []
            } else {
                console.warn("Editor UI elements or jQuery DataTables not loaded.");
            }
        } else {
            if (window.is_assets_explorer) {
                // Do not download or clear data_json when used as an API
                if (window.onItemsLoaded) window.onItemsLoaded(data_json.items);
                return;
            }
            
            let is_txt_mode = false;
            let using_txt_el = document.getElementById("using_txt_mode");
            if (using_txt_el && using_txt_el.checked) is_txt_mode = true;
            
            if (is_txt_mode) {
                var to_txt_result = `//Credit: IProgramInCPP & GrowtopiaNoobs\n//Format: add_item\\${Object.keys(data_json.items[0]).join("\\")}\n//NOTE: There are several items, for the breakhits part, add 'r'.\n//Example: 184r\n//What does it mean? So, adding 'r' to breakhits makes it raw breakhits, meaning, if you add 'r' to breakhits, when encoding items.dat, the encoder won't multiply it by 6.\n\nversion\\${data_json.version}\nitemCount\\${data_json.item_count}\n\n`;
                for (let a = 0; a < item_count; a++) to_txt_result += "add_item\\" + Object.values(data_json.items[a]).join("\\") + "\n"
                saveData(to_txt_result, "items.txt")
            } else saveData(JSON.stringify(data_json, null, 4), "items.json");
            data_json = {}
        }
    };
};
