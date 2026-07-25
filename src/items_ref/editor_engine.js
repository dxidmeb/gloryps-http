let editorItems = [];
let activeItemId = null;
let activeTab = 'General';

// Define categories for the ~60 fields of v26 items
const fieldCategories = {
    'General': [
        'item_id', 'name', 'editable_type', 'item_category', 'action_type', 'item_kind', 
        'flags', 'flags2', 'flags3', 'flags4', 'flags5', 'extra_options', 'extra_options2'
    ],
    'Visuals': [
        'texture', 'texture_hash', 'texture_x', 'texture_y', 'clothing_type', 
        'extra_file', 'extra_file_hash', 'texture_x2', 'texture_y2', 'is_stripey_wallpaper'
    ],
    'Audio & Physics': [
        'hit_sound_type', 'punch_audio', 'punch_audio_hash', 'collision_type', 
        'break_hits', 'drop_chance', 'step_multiplier', 'time', 'val1'
    ],
    'Pets & Custom': [
        'pet_name', 'pet_name_hash', 'pet_prefix', 'pet_prefix_hash', 
        'pet_suffix', 'pet_suffix_hash', 'anim_string', 'anim_string_hash'
    ],
    'Version Specific': [
        'data_version_19', 'int_version_21', 'byte_version_22', 'byte_version_22_2',
        'int_version_23', 'byte_version_24', 'str_version_25', 'str_version_25_hash',
        'int_version_26', 'byte_version_26'
    ]
};

// Which fields should have a "Clear" button that zeros their hash counterpart?
const hashLinkedFields = {
    'texture': 'texture_hash',
    'extra_file': 'extra_file_hash',
    'punch_audio': 'punch_audio_hash',
    'pet_name': 'pet_name_hash',
    'pet_prefix': 'pet_prefix_hash',
    'pet_suffix': 'pet_suffix_hash',
    'anim_string': 'anim_string_hash',
    'str_version_25': 'str_version_25_hash'
};

window.is_assets_explorer = true; // Use API mode for converter_v26.js

// Setup File Loading
document.getElementById('upload_items').addEventListener('change', function(e) {
    const file = e.target.files[0];
    if (!file) return;

    if (file.name.endsWith('.dat')) {
        window.onItemsLoaded = function(items) {
            editorItems = items || [];
            initEditor();
        };
        item_decoder(file, false);
    } else if (file.name.endsWith('.json')) {
        const reader = new FileReader();
        reader.onload = function(evt) {
            try {
                const parsed = JSON.parse(evt.target.result);
                // converter_v26.js expects data_json globally
                window.data_json = parsed; 
                editorItems = parsed.items || [];
                initEditor();
            } catch (err) {
                Swal.fire("Error", "Invalid JSON file.", "error");
            }
        };
        reader.readAsText(file);
    } else if (file.name.endsWith('.txt')) {
        // Txt parsing is more complex, fallback for now
        Swal.fire("Note", "Please use .dat or .json for the editor for best stability.", "info");
    }
});

function initEditor() {
    document.getElementById('setup_pane').style.display = 'none';
    document.getElementById('editor_panel').style.display = 'flex';
    document.getElementById('btn_export_json').style.display = 'block';
    document.getElementById('btn_export_dat').style.display = 'block';
    
    document.getElementById('items_count').innerText = editorItems.length;
    renderSidebar('');
}

let searchTimer = null;
document.getElementById('search_items').addEventListener('input', function(e) {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
        renderSidebar(e.target.value.toLowerCase());
    }, 200);
});

function renderSidebar(searchQuery) {
    const list = document.getElementById('item_list');
    list.innerHTML = '';
    
    const fragment = document.createDocumentFragment();
    
    let filtered = editorItems.filter(item => {
        if (searchQuery) {
            return (item.name || '').toLowerCase().includes(searchQuery) || item.item_id.toString() === searchQuery;
        }
        return true;
    });

    // Virtualize cap to 500 to prevent browser lag on 16k elements
    const itemsToRender = filtered.slice(0, 500);

    for (let item of itemsToRender) {
        const div = document.createElement('div');
        div.className = 'list-item';
        if (activeItemId === item.item_id) {
            div.classList.add('selected');
        }
        
        const title = document.createElement('span');
        title.className = 'list-item-title';
        title.innerText = item.name || 'Unknown';
        
        const subtitle = document.createElement('span');
        subtitle.className = 'list-item-sub';
        subtitle.innerText = `ID: ${item.item_id}`;
        
        div.appendChild(title);
        div.appendChild(subtitle);

        div.addEventListener('click', () => {
            document.querySelectorAll('.list-item').forEach(el => el.classList.remove('selected'));
            div.classList.add('selected');
            loadItemForm(item.item_id);
        });

        fragment.appendChild(div);
    }
    
    if (filtered.length > 500) {
        const more = document.createElement('div');
        more.style = "padding: 1rem; text-align: center; color: var(--text-muted); font-size: 0.8rem;";
        more.innerText = `Showing 500 of ${filtered.length} matches... Use search to narrow down.`;
        fragment.appendChild(more);
    }
    
    list.appendChild(fragment);
}

function loadItemForm(itemId) {
    activeItemId = itemId;
    const item = editorItems[itemId];
    
    document.getElementById('empty_state').style.display = 'none';
    document.getElementById('form_header').style.display = 'flex';
    document.getElementById('form_tabs').style.display = 'flex';
    
    document.getElementById('form_item_id').innerText = `#${item.item_id}`;
    document.getElementById('form_item_name').innerText = item.name;
    
    renderTabs();
    renderFormContent(item);
}

function renderTabs() {
    const tabsContainer = document.getElementById('form_tabs');
    tabsContainer.innerHTML = '';
    
    Object.keys(fieldCategories).forEach(cat => {
        const tab = document.createElement('div');
        tab.className = `tab ${activeTab === cat ? 'active' : ''}`;
        tab.innerText = cat;
        tab.addEventListener('click', () => {
            activeTab = cat;
            loadItemForm(activeItemId);
        });
        tabsContainer.appendChild(tab);
    });
}

function renderFormContent(item) {
    const content = document.getElementById('form_content');
    // Clear old fields but keep empty state hidden
    Array.from(content.children).forEach(child => {
        if (child.id !== 'empty_state') content.removeChild(child);
    });

    const fieldsToShow = fieldCategories[activeTab] || [];
    
    // Some fields might exist in the item but aren't categorized, let's put them in a "Misc" tab dynamically if we wanted to.
    // For now, we just show mapped ones.
    
    fieldsToShow.forEach(key => {
        if (item[key] === undefined) return; // Field doesn't exist on this item format
        
        const group = document.createElement('div');
        group.className = 'form-group';
        
        const label = document.createElement('label');
        label.innerText = key;
        
        let inputArea;
        
        if (hashLinkedFields[key]) {
            // This is a file string that has a paired hash
            group.classList.add('full-width');
            inputArea = document.createElement('div');
            inputArea.className = 'input-with-clear';
            
            const input = document.createElement('input');
            input.type = 'text';
            input.className = 'form-control';
            input.value = item[key];
            input.addEventListener('input', (e) => {
                item[key] = e.target.value;
                document.getElementById('form_item_name').innerText = item.name; // update header if name changed
            });
            
            const clearBtn = document.createElement('button');
            clearBtn.className = 'btn-clear';
            clearBtn.innerText = 'Clear File & Hash';
            clearBtn.addEventListener('click', () => {
                input.value = "";
                item[key] = "";
                item[hashLinkedFields[key]] = 0; // ZERO OUT THE HASH
                
                // If the hash field is currently visible, update its UI input too
                const hashInput = document.getElementById(`input_${hashLinkedFields[key]}`);
                if (hashInput) hashInput.value = 0;
                
                Swal.mixin({ toast: true, position: 'top-end', showConfirmButton: false, timer: 2000 }).fire({
                    icon: 'success', title: `Cleared ${key} and Hash`
                });
            });
            
            inputArea.appendChild(input);
            inputArea.appendChild(clearBtn);
        } else {
            // Standard field
            const isLong = key === 'name' || key === 'data_version_19';
            if (isLong) group.classList.add('full-width');
            
            inputArea = document.createElement('input');
            inputArea.type = typeof item[key] === 'number' ? 'number' : 'text';
            inputArea.className = 'form-control';
            inputArea.id = `input_${key}`;
            inputArea.value = item[key];
            if (key === 'item_id') inputArea.disabled = true; // Protect ID sequence
            
            inputArea.addEventListener('input', (e) => {
                const val = inputArea.type === 'number' ? Number(e.target.value) : e.target.value;
                item[key] = val;
                if (key === 'name') document.getElementById('form_item_name').innerText = item.name;
            });
        }
        
        group.appendChild(label);
        group.appendChild(inputArea);
        content.appendChild(group);
    });
}

// --- ACTIONS ---

document.getElementById('btn_remove_item').addEventListener('click', () => {
    if (activeItemId === null) return;
    
    Swal.fire({
        title: 'Blank Out Item?',
        text: "This will clear all data for this item and rename it to 'Blank'. This safely removes the item from the game without breaking the item_id sequence.",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#ef4444',
        confirmButtonText: 'Yes, blank it out!'
    }).then((result) => {
        if (result.isConfirmed) {
            const item = editorItems[activeItemId];
            // Clear string fields
            Object.keys(item).forEach(k => {
                if (typeof item[k] === 'string') item[k] = "";
                else if (typeof item[k] === 'number' && k !== 'item_id') item[k] = 0;
            });
            item.name = "Blank";
            item.action_type = 0;
            item.editable_type = 0;
            
            loadItemForm(activeItemId);
            renderSidebar(document.getElementById('search_items').value.toLowerCase());
            
            Swal.fire('Blanked!', 'The item has been safely blanked out.', 'success');
        }
    });
});

document.getElementById('btn_add_item').addEventListener('click', () => {
    if (editorItems.length === 0) {
        return Swal.fire("Error", "Load an items.dat first.", "error");
    }
    
    Swal.fire({
        title: 'Add New Item',
        html: `
            <div style="margin-bottom: 1rem;">Do you want to create a blank item or clone an existing one?</div>
            <input type="text" id="clone_search" class="swal2-input" placeholder="Search item to clone (Name or ID)..." style="margin-bottom: 10px;">
            <div id="clone_results" style="max-height: 150px; overflow-y: auto; text-align: left; border: 1px solid var(--border-color); border-radius: 4px; background: var(--bg-color);">
                <div style="padding: 10px; color: var(--text-muted); text-align: center;">Start typing to search...</div>
            </div>
        `,
        showCancelButton: true,
        confirmButtonText: 'Create Blank',
        confirmButtonColor: '#3b82f6',
        cancelButtonText: 'Cancel',
        didOpen: () => {
            const searchInput = document.getElementById('clone_search');
            const resultsDiv = document.getElementById('clone_results');
            
            // Add a "Clone Selected" button to the swal actions manually or just use the confirm button?
            // Let's change the confirm button text dynamically if an item is selected.
            let selectedItemToClone = null;

            searchInput.addEventListener('input', (e) => {
                const query = e.target.value.toLowerCase();
                if (!query) {
                    resultsDiv.innerHTML = '<div style="padding: 10px; color: var(--text-muted); text-align: center;">Start typing to search...</div>';
                    selectedItemToClone = null;
                    Swal.getConfirmButton().innerText = 'Create Blank';
                    return;
                }
                
                const matches = editorItems.filter(item => 
                    (item.name || '').toLowerCase().includes(query) || 
                    item.item_id.toString() === query
                ).slice(0, 50); // limit to 50 results
                
                resultsDiv.innerHTML = '';
                if (matches.length === 0) {
                    resultsDiv.innerHTML = '<div style="padding: 10px; color: var(--text-muted); text-align: center;">No matches found</div>';
                    return;
                }
                
                matches.forEach(item => {
                    const row = document.createElement('div');
                    row.style = "padding: 8px 10px; cursor: pointer; border-bottom: 1px solid var(--border-color); font-size: 0.9rem; color: var(--text-color);";
                    row.innerText = `ID: ${item.item_id} | ${item.name}`;
                    
                    row.addEventListener('mouseover', () => row.style.background = 'rgba(255,255,255,0.05)');
                    row.addEventListener('mouseout', () => {
                        if (selectedItemToClone !== item) row.style.background = 'transparent';
                    });
                    
                    row.addEventListener('click', () => {
                        // clear previous selection
                        Array.from(resultsDiv.children).forEach(c => c.style.background = 'transparent');
                        row.style.background = 'rgba(59, 130, 246, 0.2)';
                        selectedItemToClone = item;
                        Swal.getConfirmButton().innerText = `Clone Item #${item.item_id}`;
                    });
                    
                    resultsDiv.appendChild(row);
                });
            });

            // Store the selection in the popup so preConfirm can access it
            Swal.getPopup().selectedItemToClone = () => selectedItemToClone;
        },
        preConfirm: () => {
            return Swal.getPopup().selectedItemToClone();
        }
    }).then((result) => {
        if (result.isDismissed) return;

        let template;
        if (result.value) {
            // Clone the selected item
            template = JSON.parse(JSON.stringify(result.value));
            template.name = template.name + " (Copy)";
        } else {
            // Create a blank item (clone last and blank it)
            template = JSON.parse(JSON.stringify(editorItems[editorItems.length - 1]));
            Object.keys(template).forEach(k => {
                if (typeof template[k] === 'string') template[k] = "";
                else if (typeof template[k] === 'number') template[k] = 0;
            });
            template.name = "New Item";
        }
        
        template.item_id = editorItems.length; // Assign next ID
        
        editorItems.push(template);
        if (window.data_json) window.data_json.item_count = editorItems.length;
        
        document.getElementById('items_count').innerText = editorItems.length;
        document.getElementById('search_items').value = ""; // clear search
        renderSidebar('');
        
        loadItemForm(template.item_id);
        
        Swal.mixin({ toast: true, position: 'bottom-end', showConfirmButton: false, timer: 3000 }).fire({
            icon: 'success', title: `Created New Item #${template.item_id}`
        });
    });
});

// --- EXPORTING ---

var saveData = (function () {
    const a = document.createElement("a");
    a.style = "display: none";
    return function (data, fileName) {
        const blob = new Blob([data], {type: "octet/stream"});
        const url = window.URL.createObjectURL(blob);
        a.href = url;
        a.download = fileName;
        a.click();
        window.URL.revokeObjectURL(url);
    };
}());

document.getElementById('btn_export_json').addEventListener('click', () => {
    if (!window.data_json) return;
    const jsonStr = JSON.stringify(window.data_json, null, 4);
    saveData(jsonStr, "items_edited.json");
});

document.getElementById('btn_export_dat').addEventListener('click', () => {
    if (!window.data_json) return;
    // We can rely on converter_v26.js's process_item_encoder function!
    try {
        window.encoded_buffer_file = []; // Reset global buffer from converter
        process_item_encoder(window.data_json, 0); // 0 = json mode
        
        const blob = new Blob([new Uint8Array(window.encoded_buffer_file)], {type: "octet/stream"});
        const a = document.createElement("a");
        const url = window.URL.createObjectURL(blob);
        a.href = url;
        a.download = "items_edited.dat";
        a.click();
        window.URL.revokeObjectURL(url);
        
        Swal.fire("Success", "Encoded and downloaded items_edited.dat", "success");
    } catch (e) {
        console.error(e);
        Swal.fire("Encoding Error", "Failed to compile the .dat file. Check console.", "error");
    }
});

// --- BULK ACTIONS ---

document.getElementById('btn_bulk_actions').addEventListener('click', () => {
    if (editorItems.length === 0) {
        return Swal.fire("Error", "Load an items.dat first.", "error");
    }

    const currentSearch = document.getElementById('search_items').value.toLowerCase();
    
    // Build field options
    let fieldOptions = `<option value="ALL">All File Fields (texture, extra_file, audio, etc)</option>`;
    Object.keys(hashLinkedFields).forEach(field => {
        fieldOptions += `<option value="${field}">${field}</option>`;
    });

    // Build target options
    let targetOptions = `<option value="ALL">All 16,000+ Items</option>`;
    if (currentSearch) {
        targetOptions += `<option value="SEARCH" selected>Current Search Results ("${currentSearch}")</option>`;
    }
    targetOptions += `<option value="RANGE">Custom ID Range</option>`;

    Swal.fire({
        title: '⚡ Bulk Clear Files & Hashes',
        html: `
            <div style="text-align: left; font-size: 0.9rem;">
                <label style="display: block; margin-bottom: 5px; color: var(--text-muted);">Field to Clear</label>
                <select id="bulk_field" class="swal2-select" style="width: 100%; max-width: 100%; margin: 0 0 15px 0; display: block;">
                    ${fieldOptions}
                </select>

                <label style="display: block; margin-bottom: 5px; color: var(--text-muted);">Target Items</label>
                <select id="bulk_target" class="swal2-select" style="width: 100%; max-width: 100%; margin: 0 0 15px 0; display: block;">
                    ${targetOptions}
                </select>

                <div id="bulk_range_container" style="display: none; gap: 10px;">
                    <div style="flex: 1;">
                        <label style="display: block; margin-bottom: 5px; color: var(--text-muted);">From ID</label>
                        <input type="number" id="bulk_from" class="swal2-input" style="margin: 0; width: 100%;">
                    </div>
                    <div style="flex: 1;">
                        <label style="display: block; margin-bottom: 5px; color: var(--text-muted);">To ID</label>
                        <input type="number" id="bulk_to" class="swal2-input" style="margin: 0; width: 100%;">
                    </div>
                </div>
            </div>
        `,
        showCancelButton: true,
        confirmButtonText: 'Run Bulk Clear',
        confirmButtonColor: '#ef4444',
        didOpen: () => {
            const targetSelect = document.getElementById('bulk_target');
            const rangeContainer = document.getElementById('bulk_range_container');
            
            // Toggle range inputs based on selection
            targetSelect.addEventListener('change', (e) => {
                if (e.target.value === 'RANGE') {
                    rangeContainer.style.display = 'flex';
                } else {
                    rangeContainer.style.display = 'none';
                }
            });
            // trigger once to set initial state
            targetSelect.dispatchEvent(new Event('change'));
        },
        preConfirm: () => {
            const field = document.getElementById('bulk_field').value;
            const target = document.getElementById('bulk_target').value;
            const fromId = parseInt(document.getElementById('bulk_from').value) || 0;
            const toId = parseInt(document.getElementById('bulk_to').value) || editorItems.length - 1;

            return { field, target, fromId, toId, currentSearch };
        }
    }).then((result) => {
        if (!result.isConfirmed) return;
        
        const { field, target, fromId, toId, currentSearch } = result.value;
        let itemsToProcess = [];

        // Determine which items to process
        if (target === 'ALL') {
            itemsToProcess = editorItems;
        } else if (target === 'SEARCH') {
            itemsToProcess = editorItems.filter(item => 
                (item.name || '').toLowerCase().includes(currentSearch) || 
                item.item_id.toString() === currentSearch
            );
        } else if (target === 'RANGE') {
            itemsToProcess = editorItems.filter(item => item.item_id >= fromId && item.item_id <= toId);
        }

        if (itemsToProcess.length === 0) {
            return Swal.fire("Warning", "No items matched your criteria.", "warning");
        }

        // Determine which fields to clear
        let fieldsToClear = [];
        if (field === 'ALL') {
            fieldsToClear = Object.keys(hashLinkedFields);
        } else {
            fieldsToClear = [field];
        }

        // Execute the bulk clear
        let clearedCount = 0;
        itemsToProcess.forEach(item => {
            let modified = false;
            fieldsToClear.forEach(f => {
                if (item[f] !== "" || item[hashLinkedFields[f]] !== 0) {
                    item[f] = "";
                    item[hashLinkedFields[f]] = 0;
                    modified = true;
                }
            });
            if (modified) clearedCount++;
        });

        // Re-render if necessary
        if (activeItemId !== null) loadItemForm(activeItemId);

        Swal.fire(
            "Bulk Clear Complete",
            `Successfully cleared files and hashes for ${clearedCount} items.`,
            "success"
        );
    });
});
