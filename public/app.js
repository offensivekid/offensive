// ============= GLOBAL STATE =============

let currentUser = null;
let currentLanguage = localStorage.getItem('forum_language') || 'en';
let allThreads = [];

// ============= TRANSLATIONS =============

const translations = {
    en: {
        'login': 'Login',
        'register': 'Register',
        'logout': 'Logout',
        'login_success': 'Login successful!',
        'register_success': 'Registration successful! Please login.',
        'thread_created': 'Thread created successfully!',
        'reply_added': 'Reply added!',
        'keys_generated': 'keys generated',
        'no_public_threads': 'No public threads',
        'no_private_threads': 'No private threads',
        'no_replies': 'No replies yet',
        'loading': 'Loading...',
        'author': 'Author',
        'replies': 'Replies',
        'views': 'Views',
        'just_now': 'just now',
        'min_ago': 'min ago',
        'hour_ago': 'h ago'
    },
    ru: {
        'login': 'Войти',
        'register': 'Регистрация',
        'logout': 'Выйти',
        'login_success': 'Вход выполнен!',
        'register_success': 'Регистрация успешна! Войдите в систему.',
        'thread_created': 'Тема создана!',
        'reply_added': 'Ответ добавлен!',
        'keys_generated': 'ключей сгенерировано',
        'no_public_threads': 'Нет публичных тем',
        'no_private_threads': 'Нет приватных тем',
        'no_replies': 'Нет ответов',
        'loading': 'Загрузка...',
        'author': 'Автор',
        'replies': 'Ответов',
        'views': 'Просмотров',
        'just_now': 'только что',
        'min_ago': 'мин назад',
        'hour_ago': 'ч назад'
    }
};

function t(key) {
    return translations[currentLanguage][key] || key;
}

function toggleLanguage() {
    currentLanguage = currentLanguage === 'en' ? 'ru' : 'en';
    localStorage.setItem('forum_language', currentLanguage);
    document.getElementById('langBtn').textContent = currentLanguage === 'en' ? 'RU' : 'EN';
    loadThreads(); // Reload to update UI
}

// ============= UI FUNCTIONS =============

const cursorGlow = document.querySelector('.cursor-glow');
document.addEventListener('mousemove', (e) => {
    cursorGlow.style.transform = `translate(${e.clientX - 300}px, ${e.clientY - 300}px)`;
});

setTimeout(() => {
    document.getElementById('loadingScreen').classList.add('hidden');
}, 800);

function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('hiding');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function showModal(modalId) {
    document.getElementById(modalId).classList.add('active');
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
}

function showSection(section) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    
    document.getElementById(`${section}Section`).classList.add('active');
    
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        if ((section === 'public' && item.textContent.includes('Public')) ||
            (section === 'private' && item.textContent.includes('Private')) ||
            (section === 'admin' && item.textContent.includes('Admin'))) {
            item.classList.add('active');
        }
    });
}

function formatDate(timestamp) {
    const date = new Date(timestamp);
    const now = Date.now();
    const diff = now - timestamp;
    
    if (diff < 60000) return t('just_now');
    if (diff < 3600000) return `${Math.floor(diff / 60000)} ${t('min_ago')}`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)} ${t('hour_ago')}`;
    
    return date.toLocaleDateString(currentLanguage === 'en' ? 'en-US' : 'ru-RU');
}

function escapeHtml(text) {
    if (typeof text !== 'string') return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============= API CALLS =============

async function apiCall(endpoint, options = {}) {
    try {
        const response = await fetch(`/api${endpoint}`, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            credentials: 'include'
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Request failed');
        }
        
        return data;
    } catch (error) {
        console.error('API error:', error);
        throw error;
    }
}

// ============= AUTH FUNCTIONS =============

async function register(e) {
    e.preventDefault();
    
    const username = document.getElementById('registerUsername').value.trim();
    const email = document.getElementById('registerEmail').value.trim();
    const password = document.getElementById('registerPassword').value;
    
    try {
        await apiCall('/auth/register', {
            method: 'POST',
            body: JSON.stringify({ username, email, password })
        });
        
        showToast(t('register_success'), 'success');
        closeModal('registerModal');
        showModal('loginModal');
        
        // Pre-fill login username
        document.getElementById('loginUsername').value = username;
        
    } catch (error) {
        showToast(error.message, 'error');
    }
}

async function login(e) {
    e.preventDefault();
    
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    const accessKey = document.getElementById('loginAccessKey').value.trim().toUpperCase();
    
    try {
        const data = await apiCall('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password, accessKey })
        });
        
        currentUser = data.user;
        showToast(t('login_success'), 'success');
        closeModal('loginModal');
        updateUI();
        loadThreads();
        
        if (currentUser.isAdmin) {
            loadAdminData();
        }
        
    } catch (error) {
        showToast(error.message, 'error');
    }
}

async function logout() {
    try {
        await apiCall('/auth/logout', { method: 'POST' });
        currentUser = null;
        location.reload();
    } catch (error) {
        showToast(error.message, 'error');
    }
}

async function checkAuth() {
    try {
        const data = await apiCall('/auth/me');
        currentUser = data;
        updateUI();
        if (currentUser.isAdmin) {
            loadAdminData();
        }
    } catch (error) {
        // Not logged in
    }
}

function updateUI() {
    const headerButtons = document.getElementById('headerButtons');
    const langBtn = document.getElementById('langBtn');
    
    if (currentUser) {
        headerButtons.innerHTML = `
            ${langBtn.outerHTML}
            <span style="color: #4ade80; margin-right: 15px;">${escapeHtml(currentUser.username)}${currentUser.isAdmin ? ' 👑' : ''}</span>
            <button class="btn" onclick="logout()">Logout</button>
        `;
        
        document.getElementById('langBtn').onclick = toggleLanguage;
        document.getElementById('createThreadBtn').style.display = 'block';
        
        if (currentUser.hasPrivateAccess || currentUser.isAdmin) {
            document.getElementById('privateNav').style.display = 'flex';
        }
        
        if (currentUser.isAdmin) {
            document.getElementById('adminNav').style.display = 'flex';
            document.getElementById('privateCheckboxContainer').style.display = 'block';
        }
    }
}

// ============= THREADS =============

async function loadThreads() {
    try {
        allThreads = await apiCall('/threads');
        renderPublicThreads();
        if (currentUser && (currentUser.hasPrivateAccess || currentUser.isAdmin)) {
            renderPrivateThreads();
        }
        updateStats();
    } catch (error) {
        console.error('Load threads error:', error);
    }
}

function renderPublicThreads() {
    const container = document.getElementById('publicThreads');
    const threads = allThreads.filter(t => !t.is_private);
    
    if (threads.length === 0) {
        container.innerHTML = `<div class="empty-state">${t('no_public_threads')}</div>`;
        return;
    }
    
    container.innerHTML = threads.map((thread, index) => `
        <div class="thread-item" onclick="viewThread(${thread.id})" style="animation-delay: ${index * 0.05}s;">
            <div class="thread-header">
                <div class="thread-title">${escapeHtml(thread.title)}</div>
            </div>
            <div class="thread-meta">
                <span>${t('author')}: ${escapeHtml(thread.author_username)}</span>
                <span>•</span>
                <span>${formatDate(thread.created_at)}</span>
                <span>•</span>
                <span>${t('replies')}: ${thread.reply_count || 0}</span>
                <span>•</span>
                <span>${t('views')}: ${thread.views || 0}</span>
            </div>
        </div>
    `).join('');
}

function renderPrivateThreads() {
    const container = document.getElementById('privateThreads');
    const threads = allThreads.filter(t => t.is_private);
    
    if (threads.length === 0) {
        container.innerHTML = `<div class="empty-state">${t('no_private_threads')}</div>`;
        return;
    }
    
    container.innerHTML = threads.map((thread, index) => `
        <div class="thread-item" onclick="viewThread(${thread.id})" style="animation-delay: ${index * 0.05}s;">
            <div class="thread-header">
                <div class="thread-title">
                    ${escapeHtml(thread.title)}
                    <span class="thread-badge private">PRIVATE</span>
                </div>
            </div>
            <div class="thread-meta">
                <span>${t('author')}: ${escapeHtml(thread.author_username)}</span>
                <span>•</span>
                <span>${formatDate(thread.created_at)}</span>
                <span>•</span>
                <span>${t('replies')}: ${thread.reply_count || 0}</span>
                <span>•</span>
                <span>${t('views')}: ${thread.views || 0}</span>
            </div>
        </div>
    `).join('');
}

async function viewThread(threadId) {
    try {
        const thread = await apiCall(`/threads/${threadId}`);
        const replies = await apiCall(`/threads/${threadId}/replies`);
        
        document.getElementById('threadView').classList.add('active');
        
        const threadContent = document.getElementById('threadContent');
        threadContent.innerHTML = `
            <div class="thread-full">
                <div class="thread-header-full">
                    <h1 class="thread-title-full">
                        ${escapeHtml(thread.title)}
                        ${thread.is_private ? '<span class="thread-badge private">PRIVATE</span>' : ''}
                    </h1>
                    <div class="thread-meta">
                        <span>${t('author')}: ${escapeHtml(thread.author_username)}</span>
                        <span>•</span>
                        <span>${formatDate(thread.created_at)}</span>
                        <span>•</span>
                        <span>${t('views')}: ${thread.views || 0}</span>
                    </div>
                </div>
                <div class="thread-body-full">${escapeHtml(thread.body)}</div>
            </div>
            
            <div class="replies-section">
                <h3>${t('replies')} (${replies.length})</h3>
                <div id="repliesList">
                    ${replies.length === 0 ? `<div class="empty-state">${t('no_replies')}</div>` : 
                      replies.map((reply, index) => `
                        <div class="reply-item" style="animation-delay: ${index * 0.1}s;">
                            <div class="reply-header">
                                <span class="reply-author">${escapeHtml(reply.author_username)}</span>
                                <span class="reply-time">${formatDate(reply.created_at)}</span>
                            </div>
                            <div class="reply-body">${escapeHtml(reply.text)}</div>
                        </div>
                      `).join('')
                    }
                </div>
                
                ${currentUser ? `
                    <form onsubmit="addReply(event, ${threadId})" class="reply-form">
                        <textarea id="replyText" placeholder="Your reply..." required minlength="5" maxlength="2000"></textarea>
                        <button type="submit" class="btn btn-primary">Add Reply</button>
                    </form>
                ` : `
                    <div class="empty-state">Login to reply</div>
                `}
            </div>
        `;
        
    } catch (error) {
        showToast(error.message, 'error');
    }
}

async function createThread(e) {
    e.preventDefault();
    
    if (!currentUser) {
        showToast('Please login first', 'error');
        return;
    }
    
    const title = document.getElementById('threadTitle').value.trim();
    const body = document.getElementById('threadBody').value.trim();
    const isPrivate = document.getElementById('isPrivate').checked;
    
    try {
        await apiCall('/threads', {
            method: 'POST',
            body: JSON.stringify({ title, body, isPrivate })
        });
        
        showToast(t('thread_created'), 'success');
        closeModal('createThreadModal');
        
        document.getElementById('threadTitle').value = '';
        document.getElementById('threadBody').value = '';
        document.getElementById('isPrivate').checked = false;
        
        loadThreads();
        
    } catch (error) {
        showToast(error.message, 'error');
    }
}

async function addReply(e, threadId) {
    e.preventDefault();
    
    const text = document.getElementById('replyText').value.trim();
    
    try {
        await apiCall(`/threads/${threadId}/replies`, {
            method: 'POST',
            body: JSON.stringify({ text })
        });
        
        showToast(t('reply_added'), 'success');
        document.getElementById('replyText').value = '';
        
        // Reload thread
        viewThread(threadId);
        
    } catch (error) {
        showToast(error.message, 'error');
    }
}

function backToList() {
    document.getElementById('threadView').classList.remove('active');
    if (currentUser && (currentUser.hasPrivateAccess || currentUser.isAdmin)) {
        showSection('private');
    } else {
        showSection('public');
    }
}

// ============= ADMIN FUNCTIONS =============

async function loadAdminData() {
    try {
        const [stats, keys] = await Promise.all([
            apiCall('/admin/stats'),
            apiCall('/admin/keys')
        ]);
        
        document.getElementById('totalKeys').textContent = stats.totalKeys;
        document.getElementById('activeKeys').textContent = stats.activeKeys;
        document.getElementById('usedKeys').textContent = stats.usedKeys;
        
        renderKeys(keys);
        
    } catch (error) {
        console.error('Load admin data error:', error);
    }
}

function renderKeys(keys) {
    const container = document.getElementById('keyList');
    
    if (keys.length === 0) {
        container.innerHTML = '<div class="empty-state">No keys</div>';
        return;
    }
    
    container.innerHTML = keys.map((key, index) => `
        <div class="key-item" style="animation-delay: ${index * 0.03}s;">
            <div>
                <div class="key-code">${escapeHtml(key.key_code)}</div>
                <div class="key-status ${key.is_active ? 'active' : ''}">
                    ${key.is_active ? 'Active' : `Used by: ${escapeHtml(key.used_by_username || 'Unknown')}`}
                </div>
            </div>
            <span>${formatDate(key.created_at)}</span>
        </div>
    `).join('');
}

async function generateKeys() {
    const count = parseInt(document.getElementById('keyCount').value);
    
    if (count < 1 || count > 50) {
        showToast('Count must be 1-50', 'error');
        return;
    }
    
    try {
        const data = await apiCall('/admin/keys/generate', {
            method: 'POST',
            body: JSON.stringify({ count })
        });
        
        showToast(`${count} ${t('keys_generated')}`, 'success');
        loadAdminData();
        
    } catch (error) {
        showToast(error.message, 'error');
    }
}

// ============= UTILITY =============

function updateStats() {
    document.getElementById('totalThreads').textContent = allThreads.length;
}

// Close modal on outside click
document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.remove('active');
        }
    });
});

// ============= INIT =============

document.getElementById('langBtn').textContent = currentLanguage === 'en' ? 'RU' : 'EN';

checkAuth();
loadThreads();
