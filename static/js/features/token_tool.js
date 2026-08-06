// ==================== Token 工具 ====================

const t = window.translateAppText || ((text) => text);

// ===== 新手指引配置 =====
// 教程链接列表 — 在此维护外部教程链接，HTML 中 guide-links 区域会自动渲染
const GUIDE_TUTORIAL_LINKS = [
    // { title: '标题', url: 'https://example.com/tutorial' },
    // 在此添加教程链接...
];

const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.content || '';
const SCOPE_PRESETS = {
    graph: ['offline_access', 'https://graph.microsoft.com/.default'],
    imap: ['offline_access', 'https://outlook.office.com/IMAP.AccessAsUser.All'],
};
const DEFAULT_COMPAT_SCOPE = SCOPE_PRESETS.graph.join(' ');

let scopeTokens = ['offline_access', 'https://graph.microsoft.com/.default'];
let currentTokenResult = null;
let autoImportResults = [];
let autoImportExpectedCount = 0;
let autoImportPopup = null;

async function tokenToolFetch(url, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        'X-CSRFToken': CSRF_TOKEN,
        ...(options.headers || {}),
    };
    const response = await fetch(url, { ...options, headers });
    const data = await response.json().catch(() => ({
        success: false,
        error: { message: t('响应解析失败') },
    }));
    if (!response.ok && data.success === undefined) {
        data.success = false;
    }
    return data;
}

function escapeHtml(value) {
    return String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function buildDefaultRedirectUri() {
    return `${window.location.origin}/token-tool/callback`;
}

function showStatus(message, type = 'info', detail = '') {
    const statusNode = document.getElementById('statusMessage');
    if (!statusNode) {
        return;
    }
    statusNode.className = `token-status ${type}`;
    statusNode.innerHTML = `
        <div class="token-status-title">${escapeHtml(message)}</div>
        ${detail ? `<div class="token-status-detail">${escapeHtml(detail)}</div>` : ''}
    `;
}

function clearStatus() {
    const statusNode = document.getElementById('statusMessage');
    if (!statusNode) {
        return;
    }
    statusNode.className = 'token-status hidden';
    statusNode.innerHTML = '';
}

function showSaveDialogStatus(message, type = 'info', detail = '') {
    const statusNode = document.getElementById('saveDialogStatus');
    if (!statusNode) {
        showStatus(message, type, detail);
        return;
    }
    statusNode.className = `token-status token-dialog-status ${type}`;
    statusNode.innerHTML = `
        <div class="token-status-title">${escapeHtml(message)}</div>
        ${detail ? `<div class="token-status-detail">${escapeHtml(detail)}</div>` : ''}
    `;
}

function clearSaveDialogStatus() {
    const statusNode = document.getElementById('saveDialogStatus');
    if (!statusNode) {
        return;
    }
    statusNode.className = 'token-status token-dialog-status hidden';
    statusNode.innerHTML = '';
}

function parseScopeInput(raw) {
    return String(raw || '')
        .split(/[\s,;]+/)
        .map(item => item.trim())
        .filter(Boolean);
}

function updateScopeValue() {
    const scopeValue = document.getElementById('scopeValue');
    if (scopeValue) {
        scopeValue.value = scopeTokens.join(' ');
    }
}

function buildScopeChip(token) {
    const locked = token === 'offline_access';
    const chip = document.createElement('span');
    chip.className = locked ? 'scope-chip scope-chip-locked' : 'scope-chip';

    const label = document.createElement('span');
    label.textContent = token;
    chip.appendChild(label);

    if (locked) {
        const lock = document.createElement('span');
        lock.className = 'scope-chip-lock';
        lock.textContent = '🔒';
        chip.appendChild(lock);
        return chip;
    }

    const removeButton = document.createElement('button');
    removeButton.type = 'button';
    removeButton.dataset.scope = token;
    removeButton.setAttribute('aria-label', t('移除 scope') + ' ' + token);
    removeButton.textContent = '×';
    chip.appendChild(removeButton);
    return chip;
}

function renderScopeChips(scopeValue) {
    const tokens = parseScopeInput(scopeValue);
    const unique = new Set(tokens);
    unique.add('offline_access');
    scopeTokens = Array.from(unique);
    updateScopeValue();

    const chipsNode = document.getElementById('scopeChips');
    if (!chipsNode) {
        return;
    }
    chipsNode.innerHTML = '';
    scopeTokens.forEach(token => {
        chipsNode.appendChild(buildScopeChip(token));
    });
}

function addScopeTokens(tokens) {
    if (!Array.isArray(tokens) || tokens.length === 0) {
        return;
    }
    renderScopeChips([...scopeTokens, ...tokens].join(' '));
}

function addScopeFromInput() {
    const scopeEntry = document.getElementById('scopeEntry');
    if (!scopeEntry) {
        return;
    }
    const tokens = parseScopeInput(scopeEntry.value);
    if (!tokens.length) {
        showStatus(t('请输入要添加的 scope'), 'error');
        return;
    }
    addScopeTokens(tokens);
    scopeEntry.value = '';
    clearStatus();
}

function removeScope(scope) {
    if (scope === 'offline_access') {
        return;
    }
    scopeTokens = scopeTokens.filter(item => item !== scope);
    renderScopeChips(scopeTokens.join(' '));
}

function handleScopeChipClick(event) {
    if (!(event.target instanceof Element)) {
        return;
    }
    const removeButton = event.target.closest('button[data-scope]');
    if (!removeButton) {
        return;
    }
    removeScope(removeButton.dataset.scope || '');
}

function setScopePreset(type) {
    const preset = SCOPE_PRESETS[type];
    if (!preset) {
        return;
    }
    renderScopeChips(preset.join(' '));
    clearStatus();
}

function handleTenantChange() {
    // No-op: tenant is hardcoded to 'consumers' on the backend.
}

function collectFormConfig() {
    return {
        client_id: document.getElementById('clientId')?.value.trim() || '',
        client_secret: '',
        redirect_uri: document.getElementById('redirectUri')?.value.trim() || '',
        scope: document.getElementById('scopeValue')?.value.trim() || '',
        tenant: 'consumers',
        prompt_consent: Boolean(document.getElementById('promptConsent')?.checked),
    };
}

async function loadOAuthConfig() {
    const data = await tokenToolFetch('/api/token-tool/config');
    if (!data.success) {
        showStatus(data.error?.message || t('加载配置失败'), 'error');
        return;
    }

    const config = data.data || {};
    document.getElementById('clientId').value = config.client_id || '';
    document.getElementById('redirectUri').value = config.redirect_uri || buildDefaultRedirectUri();
    document.getElementById('promptConsent').checked = Boolean(config.prompt_consent);

    handleTenantChange();
    renderScopeChips(config.scope || DEFAULT_COMPAT_SCOPE);
    clearStatus();
}

async function startOAuth() {
    clearStatus();
    const config = collectFormConfig();
    const data = await tokenToolFetch('/api/token-tool/prepare', {
        method: 'POST',
        body: JSON.stringify(config),
    });
    if (!data.success) {
        showStatus(data.error?.message || t('生成授权 URL 失败'), 'error');
        return;
    }

    const authorizeUrl = data.data?.authorize_url;
    if (!authorizeUrl) {
        showStatus(t('授权地址为空'), 'error');
        return;
    }

    // Display the authorize link in the panel
    const linkInput = document.getElementById('authorizeUrl');
    if (linkInput) {
        linkInput.value = authorizeUrl;
    }
    const panel = document.getElementById('authorize-link-panel');
    if (panel) {
        panel.classList.remove('hidden');
    }
    document.getElementById('manual-exchange').open = true;
    showStatus(t('授权链接已生成，请复制并在浏览器中打开'), 'success');
}

function setAutoImportButtonBusy(busy) {
    const button = document.getElementById('startAutoImportButton');
    if (button) {
        button.disabled = busy;
    }
}

function renderAutoImportProgress(message = '') {
    const progress = document.getElementById('autoImportProgress');
    const progressText = document.getElementById('autoImportProgressText');
    const lines = document.getElementById('autoImportLines');
    if (!progress || !progressText || !lines) {
        return;
    }

    progress.classList.remove('hidden');
    const succeeded = autoImportResults.filter(result => result.status === 'success').length;
    const failed = autoImportResults.filter(result => result.status === 'error').length;
    const total = autoImportExpectedCount || 0;
    const summary = `已完成 ${succeeded}/${total} 个账号${failed ? `，失败 ${failed} 个` : ''}`;
    progressText.textContent = message ? `${summary}：${message}` : summary;
    lines.value = autoImportResults
        .filter(result => result.status === 'success' && result.import_line)
        .map(result => result.import_line)
        .join('\n');
}

function copyAutoImportLines() {
    const lines = document.getElementById('autoImportLines');
    if (!lines?.value) {
        showStatus(t('当前没有可复制的导入行'), 'error');
        return;
    }
    copyText(lines.value);
}

async function startAutoImportBatch() {
    clearStatus();
    if (autoImportPopup && !autoImportPopup.closed) {
        showStatus(t('已有连续授权窗口在运行，请先完成或关闭它'), 'error');
        return;
    }

    const count = Number(document.getElementById('autoImportCount')?.value || 0);
    if (!Number.isInteger(count) || count < 1 || count > 500) {
        showStatus(t('本批次账号数必须是 1 到 500 之间的整数'), 'error');
        return;
    }

    // 先打开空弹窗，保留用户点击带来的浏览器授权，避免异步请求后被弹窗拦截。
    const popup = window.open('', 'outlook-oauth-auto-import', 'popup=yes,width=560,height=620');
    if (!popup) {
        showStatus(t('浏览器拦截了授权弹窗，请允许本站弹窗后重试'), 'error');
        return;
    }

    autoImportResults = [];
    autoImportExpectedCount = count;
    autoImportPopup = popup;
    setAutoImportButtonBusy(true);
    renderAutoImportProgress(t('正在创建第一条授权请求…'));

    const config = collectFormConfig();
    config.auto_import = {
        enabled: true,
        count,
        force_login: Boolean(document.getElementById('autoImportForceLogin')?.checked),
    };

    const data = await tokenToolFetch('/api/token-tool/prepare', {
        method: 'POST',
        body: JSON.stringify(config),
    });
    if (!data.success) {
        popup.close();
        autoImportPopup = null;
        setAutoImportButtonBusy(false);
        renderAutoImportProgress(data.error?.message || t('创建连续授权失败'));
        showStatus(data.error?.message || t('创建连续授权失败'), 'error', data.error?.details || '');
        return;
    }

    const authorizeUrl = data.data?.authorize_url;
    if (!authorizeUrl) {
        popup.close();
        autoImportPopup = null;
        setAutoImportButtonBusy(false);
        renderAutoImportProgress(t('授权地址为空'));
        showStatus(t('授权地址为空'), 'error');
        return;
    }

    popup.location.replace(authorizeUrl);
    renderAutoImportProgress(t('请在弹窗中登录并授权第 1 个 Outlook 账号'));
    showStatus(t('连续授权已开始；每次成功后会自动进入下一个账号'), 'success');
}

function handleAutoImportMessage(event) {
    if (event.origin !== window.location.origin) {
        return;
    }
    const payload = event.data || {};
    if (payload.source !== 'outlook-email-plus-auto-import' || !payload.result) {
        return;
    }

    const result = payload.result;
    autoImportResults.push(result);
    if (result.status === 'error') {
        autoImportPopup = null;
        setAutoImportButtonBusy(false);
        renderAutoImportProgress(result.message || t('当前账号自动导入失败'));
        showStatus(result.message || t('当前账号自动导入失败'), 'error');
        return;
    }

    const warning = result.warning || '';
    if (result.remaining > 0 && !warning) {
        renderAutoImportProgress(t(`第 ${result.current} 个账号已导入，正在退出当前 Microsoft 会话并进入第 ${result.current + 1} 个账号…`));
        return;
    }

    autoImportPopup = null;
    setAutoImportButtonBusy(false);
    renderAutoImportProgress(warning || t('本批次已完成'));
    showStatus(
        warning || t(`连续授权完成，已自动导入 ${autoImportResults.filter(item => item.status === 'success').length} 个账号`),
        warning ? 'info' : 'success',
    );
}

function copyAuthorizeLink() {
    const linkInput = document.getElementById('authorizeUrl');
    if (!linkInput || !linkInput.value) {
        showStatus(t('没有可复制的授权链接'), 'error');
        return;
    }
    copyText(linkInput.value);
}

function openAuthorizeLink() {
    const linkInput = document.getElementById('authorizeUrl');
    if (!linkInput || !linkInput.value) {
        showStatus(t('没有可打开的授权链接'), 'error');
        return;
    }
    window.open(linkInput.value, '_blank');
}

function fillResultField(id, value) {
    const node = document.getElementById(id);
    if (node) {
        node.value = value || '';
    }
}

function renderTokenResult(result) {
    currentTokenResult = result || {};
    document.getElementById('result-panel').classList.remove('hidden');
    document.getElementById('resultSuccessBanner').classList.remove('hidden');

    fillResultField('refreshTokenResult', result.refresh_token || '');
    fillResultField('accessTokenResult', result.access_token || '');
    fillResultField('clientIdResult', result.client_id || '');
    fillResultField('redirectUriResult', result.redirect_uri || '');
    fillResultField('requestedScopeResult', result.requested_scope || '');
    fillResultField('grantedScopeResult', result.granted_scope || '');
    fillResultField('audienceResult', result.audience || '');
    fillResultField('scopeClaimResult', result.scope_claim || '');
    fillResultField('rolesClaimResult', result.roles_claim || '');
    fillResultField('expiresInResult', String(result.expires_in || ''));

    showStatus(t('Token 已成功换取，可以复制或写入账号'), 'success');
}

function getCurrentTokenResult() {
    return currentTokenResult || {};
}

async function exchangeToken() {
    clearStatus();
    const callbackUrl = document.getElementById('callbackUrl')?.value.trim() || '';
    if (!callbackUrl) {
        showStatus(t('请粘贴回调 URL'), 'error');
        return;
    }

    const data = await tokenToolFetch('/api/token-tool/exchange', {
        method: 'POST',
        body: JSON.stringify({ callback_url: callbackUrl }),
    });
    if (!data.success) {
        showStatus(data.error?.message || t('换取 Token 失败'), 'error', data.error?.details || '');
        return;
    }
    renderTokenResult(data.data || {});
}

async function saveConfig() {
    clearStatus();
    const config = collectFormConfig();
    const data = await tokenToolFetch('/api/token-tool/config', {
        method: 'POST',
        body: JSON.stringify(config),
    });
    if (!data.success) {
        showStatus(data.error?.message || t('保存配置失败'), 'error');
        return;
    }
    showStatus(data.message || t('配置已保存'), 'success');
}

function copyResultField(id) {
    const node = document.getElementById(id);
    if (!node) {
        return;
    }
    copyText(node.value || '');
}

function copyAllResults() {
    const result = getCurrentTokenResult();
    const lines = [
        `refresh_token=${result.refresh_token || ''}`,
        `access_token=${result.access_token || ''}`,
        `client_id=${result.client_id || ''}`,
        `redirect_uri=${result.redirect_uri || ''}`,
        `requested_scope=${result.requested_scope || ''}`,
        `granted_scope=${result.granted_scope || ''}`,
        `audience=${result.audience || ''}`,
        `scope_claim=${result.scope_claim || ''}`,
        `roles_claim=${result.roles_claim || ''}`,
        `expires_in=${result.expires_in || ''}`,
    ];
    copyText(lines.join('\n'));
}

function copyText(text) {
    navigator.clipboard.writeText(text || '').then(() => {
        showStatus(t('内容已复制到剪贴板'), 'success');
    }).catch(() => {
        showStatus(t('复制失败，请手动复制'), 'error');
    });
}

function toggleSaveMode() {
    const selected = document.querySelector('input[name="saveMode"]:checked')?.value || 'update';
    document.getElementById('updateModeSection')?.classList.toggle('hidden', selected !== 'update');
    document.getElementById('createModeSection')?.classList.toggle('hidden', selected !== 'create');
    clearSaveDialogStatus();
}

async function loadAccountOptions() {
    const data = await tokenToolFetch('/api/token-tool/accounts');
    const select = document.getElementById('accountSelect');
    if (!select) {
        return;
    }
    if (!data.success) {
        select.innerHTML = `<option value="">${t('加载账号失败')}</option>`;
        showSaveDialogStatus(data.error?.message || t('加载账号失败'), 'error');
        return;
    }

    const accounts = data.data || [];
    if (!accounts.length) {
        select.innerHTML = `<option value="">${t('暂无可更新账号')}</option>`;
        showSaveDialogStatus(t('当前没有可更新账号，可切换到“创建新账号”模式'), 'info');
        return;
    }
    clearSaveDialogStatus();
    select.innerHTML = accounts.map(account => `
        <option value="${escapeHtml(String(account.id))}">
            ${escapeHtml(account.email)} (${escapeHtml(account.status || 'active')})
        </option>
    `).join('');
}

async function openSaveDialog() {
    if (!getCurrentTokenResult().refresh_token) {
        showStatus(t('请先成功换取 Token'), 'error');
        return;
    }
    clearSaveDialogStatus();
    toggleSaveMode();
    await loadAccountOptions();
    document.getElementById('save-dialog')?.showModal();
}

function closeSaveDialog() {
    clearSaveDialogStatus();
    document.getElementById('save-dialog')?.close();
}

async function confirmSaveToAccount() {
    clearStatus();
    clearSaveDialogStatus();
    const mode = document.querySelector('input[name="saveMode"]:checked')?.value || 'update';
    const resultData = getCurrentTokenResult();
    const payload = {
        mode,
        refresh_token: resultData.refresh_token,
        client_id: resultData.client_id,
        scope: resultData.requested_scope || resultData.granted_scope || '',
    };

    if (mode === 'update') {
        payload.account_id = document.getElementById('accountSelect')?.value || '';
        if (!payload.account_id) {
            showSaveDialogStatus(t('请选择要更新的账号'), 'error');
            return;
        }
    } else {
        payload.email = document.getElementById('newAccountEmail')?.value.trim() || '';
        if (!payload.email) {
            showSaveDialogStatus(t('请输入新账号邮箱地址'), 'error');
            return;
        }
    }

    const data = await tokenToolFetch('/api/token-tool/save', {
        method: 'POST',
        body: JSON.stringify(payload),
    });
    if (!data.success) {
        showSaveDialogStatus(data.error?.message || t('写入失败'), 'error', data.error?.details || '');
        return;
    }

    closeSaveDialog();
    showStatus(t('Token 已写入账号'), 'success');
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('scopeChips')?.addEventListener('click', handleScopeChipClick);
    window.addEventListener('message', handleAutoImportMessage);
    document.getElementById('redirectUri').value = buildDefaultRedirectUri();
    renderScopeChips(SCOPE_PRESETS.graph.join(' '));
    loadOAuthConfig();
    toggleSaveMode();
    handleTenantChange();

    // 指引折叠状态记忆
    const guideCard = document.getElementById('guide-card');
    if (guideCard) {
        const guideDismissed = localStorage.getItem('token_tool_guide_dismissed');
        if (guideDismissed === 'true') {
            guideCard.removeAttribute('open');
        }
        guideCard.addEventListener('toggle', () => {
            localStorage.setItem('token_tool_guide_dismissed', guideCard.open ? '' : 'true');
        });
    }

    // 自动渲染教程链接到 guide-links 区域
    const guideLinksContainer = document.querySelector('.guide-links');
    if (guideLinksContainer && GUIDE_TUTORIAL_LINKS.length > 0) {
        GUIDE_TUTORIAL_LINKS.forEach((link) => {
            const a = document.createElement('a');
            a.href = link.url;
            a.target = '_blank';
            a.rel = 'noopener';
            a.textContent = link.title;
            guideLinksContainer.appendChild(a);
        });
    }
});
