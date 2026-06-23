/**
 * MomoRedAll-Native WebUI - Configuration Manager
 * Reads/writes /data/adb/modules/MomoRedAll-Native/config.json
 * via Magisk mmrl_exec shell interface.
 */

const CONFIG_PATH = '/data/adb/modules/MomoRedAll-Native/config.json';

// ---- Target detector keys (matches C++ load_config) ----
const TARGET_KEYS = [
    'momo', 'native_test', 'applist_detector', 'ruru', 'detect_magisk_hide',
    'momo_strong', 'safetynet', 'safetynet_playstore', 'cat_and_mouse',
    'android_cts', 'rootbeer', 'rootbeer_fresh'
];

const TARGET_LABELS = [
    'Momo', 'NativeTest', 'Applist Detector', 'Ruru', 'Detect Magisk Hide',
    'Momo Strong', 'SafetyNet', 'SafetyNet Play Store', 'Cat & Mouse',
    'Android CTS', 'RootBeer', 'RootBeer Fresh'
];

// ---- Hook keys (matches C++ load_config) ----
const HOOK_KEYS = [
    'fopen', 'open', 'stat', 'access', 'opendir',
    'popen_system', 'readlink', 'ptrace', 'getenv',
    'property', 'proc', 'mounts', 'extra'
];

const HOOK_LABELS = [
    'fopen', 'open / open64 / __open_2', 'stat / lstat / fstatat / __xstat',
    'access / faccessat', 'opendir / fdopendir',
    'popen / system', 'readlink / readlinkat', 'ptrace',
    'getenv / secure_getenv', '__system_property_get',
    '/proc/self/*', '/proc/mounts', 'kill / extra'
];

// ---- State ----
let config = {
    targets: {},
    hooks: {}
};

// ---- DOM refs ----
const targetsGrid = document.getElementById('targets-grid');
const hooksGrid = document.getElementById('hooks-grid');
const statusBar = document.getElementById('status-bar');
const footerStatus = document.getElementById('footer-status');
const btnSave = document.getElementById('btn-save');
const btnReload = document.getElementById('btn-reload');

// ---- Shell execution via Magisk mmrl_exec ----
async function execShell(cmd) {
    // Magisk WebUI injects mmrl_exec (or ksu_exec) into the page.
    // Try multiple known interfaces.
    const execFn = window.mmrl_exec || window.ksu_exec || window._mmrl_exec;
    if (!execFn) {
        // Fallback: try fetch-based exec if available
        if (typeof mmrl !== 'undefined' && mmrl.exec) {
            return await mmrl.exec(cmd);
        }
        throw new Error('No shell execution interface available (mmrl_exec not found)');
    }
    return await execFn(cmd);
}

// ---- Read config file ----
async function readConfig() {
    try {
        const raw = await execShell(`cat '${CONFIG_PATH}' 2>/dev/null || echo "{}"`);
        return JSON.parse(raw.trim() || '{}');
    } catch (e) {
        console.error('Failed to read config:', e);
        return {};
    }
}

// ---- Write config file ----
async function writeConfig(json) {
    const content = JSON.stringify(json, null, 2);
    // Write via shell: escape single quotes
    const escaped = content.replace(/'/g, "'\\''");
    const cmd = `mkdir -p /data/adb/modules/MomoRedAll-Native && echo '${escaped}' > '${CONFIG_PATH}'`;
    const result = await execShell(cmd);
    return result;
}

// ---- Default config ----
function getDefaultConfig() {
    const targets = {};
    TARGET_KEYS.forEach(k => { targets[k] = true; });
    const hooks = {};
    HOOK_KEYS.forEach(k => { hooks[k] = true; });
    return { targets, hooks };
}

// ---- Load and merge config ----
async function loadConfig() {
    setStatus('Loading...', 'loading');
    try {
        const fileCfg = await readConfig();
        const defaults = getDefaultConfig();
        config.targets = { ...defaults.targets, ...(fileCfg.targets || {}) };
        config.hooks = { ...defaults.hooks, ...(fileCfg.hooks || {}) };
        renderAll();
        setStatus('Configuration loaded', 'success');
        footerStatus.textContent = `Last loaded: ${new Date().toLocaleTimeString()}`;
    } catch (e) {
        setStatus('Failed to load: ' + e.message, 'error');
    }
}

// ---- Save config ----
async function saveConfig() {
    setStatus('Saving...', 'loading');
    btnSave.disabled = true;
    try {
        await writeConfig({ targets: config.targets, hooks: config.hooks });
        setStatus('Configuration saved successfully', 'success');
        footerStatus.textContent = `Last saved: ${new Date().toLocaleTimeString()}`;
    } catch (e) {
        setStatus('Failed to save: ' + e.message, 'error');
    } finally {
        btnSave.disabled = false;
    }
}

// ---- Render ----
function createSwitchRow(key, label, enabled, group, idx) {
    const row = document.createElement('div');
    row.className = 'switch-row';

    const labelEl = document.createElement('span');
    labelEl.className = 'switch-label';
    labelEl.textContent = label;

    const toggle = document.createElement('label');
    toggle.className = 'toggle';

    const input = document.createElement('input');
    input.type = 'checkbox';
    input.checked = enabled;
    input.addEventListener('change', function () {
        if (group === 'targets') {
            config.targets[key] = this.checked;
        } else {
            config.hooks[key] = this.checked;
        }
    });

    const slider = document.createElement('span');
    slider.className = 'slider';

    toggle.appendChild(input);
    toggle.appendChild(slider);
    row.appendChild(labelEl);
    row.appendChild(toggle);

    return row;
}

function renderAll() {
    // Targets
    targetsGrid.innerHTML = '';
    TARGET_KEYS.forEach((key, i) => {
        targetsGrid.appendChild(
            createSwitchRow(key, TARGET_LABELS[i], config.targets[key], 'targets', i)
        );
    });

    // Hooks
    hooksGrid.innerHTML = '';
    HOOK_KEYS.forEach((key, i) => {
        hooksGrid.appendChild(
            createSwitchRow(key, HOOK_LABELS[i], config.hooks[key], 'hooks', i)
        );
    });
}

function setStatus(msg, type) {
    statusBar.textContent = msg;
    statusBar.className = 'status-bar ' + type;
}

// ---- Init ----
btnSave.addEventListener('click', saveConfig);
btnReload.addEventListener('click', loadConfig);

document.addEventListener('DOMContentLoaded', loadConfig);
