// offensive-forum v2.1 - Complete Frontend
console.log('🔥 offensive-forum loaded');

const app = {
  user: null,
  lang: localStorage.getItem('lang') || 'en',
  threads: [],
  
  // ============= TRANSLATIONS =============
  
  i18n: {
    en: {
      loading: 'Loading...',
      login: 'Login',
      register: 'Register',
      logout: 'Logout',
      username: 'Username',
      password: 'Password',
      email: 'Email',
      title: 'Title',
      description: 'Description',
      create: 'Create',
      back: 'Back',
      navigation: 'Navigation',
      stats: 'Statistics',
      public_threads: 'Public Threads',
      private_threads: 'Private Threads',
      admin_panel: 'Admin Panel',
      total_threads: 'Total threads',
      create_thread: '+ Create Thread',
      access_key_opt: 'Access Key (optional)',
      key_help: 'Use access key to unlock private threads',
      no_account: "Don't have an account? Register",
      have_account: 'Already have an account? Login',
      private_thread_label: 'Private thread (admin only)',
      total_keys: 'Total Keys',
      active_keys: 'Active Keys',
      used_keys: 'Used Keys',
      generate_keys: 'Generate Keys',
      key_count: 'Number of keys',
      generate: 'Generate',
      keys_list: 'Keys List',
      author: 'Author',
      replies: 'Replies',
      views: 'Views',
      no_public: 'No public threads',
      no_private: 'No private threads',
      no_replies: 'No replies yet',
      add_reply: 'Add Reply',
      your_reply: 'Your reply...',
      login_to_reply: 'Login to reply',
      just_now: 'just now',
      min_ago: 'min ago',
      hour_ago: 'h ago',
      active: 'Active',
      used_by: 'Used by',
      login_success: 'Login successful!',
      register_success: 'Registration successful! Please login.',
      thread_created: 'Thread created!',
      reply_added: 'Reply added!',
      keys_generated: 'keys generated',
      logout_success: 'Logged out'
    },
    ru: {
      loading: 'Загрузка...',
      login: 'Войти',
      register: 'Регистрация',
      logout: 'Выйти',
      username: 'Имя пользователя',
      password: 'Пароль',
      email: 'Email',
      title: 'Заголовок',
      description: 'Описание',
      create: 'Создать',
      back: 'Назад',
      navigation: 'Навигация',
      stats: 'Статистика',
      public_threads: 'Публичные темы',
      private_threads: 'Приватные темы',
      admin_panel: 'Админ-панель',
      total_threads: 'Всего тем',
      create_thread: '+ Создать тему',
      access_key_opt: 'Ключ доступа (опц.)',
      key_help: 'Используй ключ для доступа к приватным темам',
      no_account: 'Нет аккаунта? Зарегистрируйся',
      have_account: 'Уже есть аккаунт? Войди',
      private_thread_label: 'Приватная тема (только админ)',
      total_keys: 'Всего ключей',
      active_keys: 'Активных ключей',
      used_keys: 'Использованных ключей',
      generate_keys: 'Генерация ключей',
      key_count: 'Количество ключей',
      generate: 'Сгенерировать',
      keys_list: 'Список ключей',
      author: 'Автор',
      replies: 'Ответов',
      views: 'Просмотров',
      no_public: 'Нет публичных тем',
      no_private: 'Нет приватных тем',
      no_replies: 'Нет ответов',
      add_reply: 'Добавить ответ',
      your_reply: 'Ваш ответ...',
      login_to_reply: 'Войдите чтобы ответить',
      just_now: 'только что',
      min_ago: 'мин назад',
      hour_ago: 'ч назад',
      active: 'Активен',
      used_by: 'Использован',
      login_success: 'Вход выполнен!',
      register_success: 'Регистрация успешна! Войдите.',
      thread_created: 'Тема создана!',
      reply_added: 'Ответ добавлен!',
      keys_generated: 'ключей сгенерировано',
      logout_success: 'Вы вышли'
    }
  },
  
  t(key) {
    return this.i18n[this.lang][key] || key;
  },
  
  updateI18n() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const text = this.t(key);
      if (el.tagName === 'INPUT' && el.placeholder) {
        el.placeholder = text;
      } else {
        el.textContent = text;
      }
    });
    document.getElementById('langBtn').textContent = this.lang === 'en' ? 'RU' : 'EN';
  },
  
  toggleLang() {
    this.lang = this.lang === 'en' ? 'ru' : 'en';
    localStorage.setItem('lang', this.lang);
    this.updateI18n();
    this.loadThreads();
  },
  
  // ============= UI =============
  
  showToast(msg, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => {
      toast.classList.add('hiding');
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  },
  
  showModal(id) {
    document.getElementById(id).classList.add('active');
  },
  
  closeModal(id) {
    document.getElementById(id).classList.remove('active');
  },
  
  showSection(section) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.getElementById(`${section}Section`).classList.add('active');
    document.querySelectorAll('.nav-item').forEach(item => {
      const text = item.textContent.toLowerCase();
      if ((section === 'public' && text.includes('public')) ||
          (section === 'private' && text.includes('private')) ||
          (section === 'admin' && text.includes('admin'))) {
        item.classList.add('active');
      }
    });
  },
  
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  },
  
  formatDate(timestamp) {
    const now = Date.now();
    const diff = now - timestamp;
    if (diff < 60000) return this.t('just_now');
    if (diff < 3600000) return Math.floor(diff / 60000) + ' ' + this.t('min_ago');
    if (diff < 86400000) return Math.floor(diff / 3600000) + ' ' + this.t('hour_ago');
    return new Date(timestamp).toLocaleDateString(this.lang === 'en' ? 'en-US' : 'ru-RU');
  },
  
  updateUI() {
    const btns = document.getElementById('headerButtons');
    const langBtn = document.getElementById('langBtn');
    
    if (this.user) {
      btns.innerHTML = `
        ${langBtn.outerHTML}
        <span style="color: #4ade80; margin-right: 15px;">${this.escapeHtml(this.user.username)}${this.user.isAdmin ? ' 👑' : ''}</span>
        <button class="btn" onclick="app.logout()"><span data-i18n="logout">${this.t('logout')}</span></button>
      `;
      document.getElementById('langBtn').onclick = () => this.toggleLang();
      document.getElementById('createThreadBtn').style.display = 'block';
      
      if (this.user.hasPrivateAccess || this.user.isAdmin) {
        document.getElementById('privateNav').style.display = 'flex';
      }
      
      if (this.user.isAdmin) {
        document.getElementById('adminNav').style.display = 'flex';
        document.getElementById('privateCheckbox').style.display = 'block';
      }
    }
    this.updateI18n();
  },
  
  // ============= API =============
  
  async api(endpoint, options = {}) {
    const res = await fetch(`/api${endpoint}`, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...options.headers },
      credentials: 'include'
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
  },
  
  // ============= AUTH =============
  
  async register(e) {
    e.preventDefault();
    try {
      await this.api('/auth/register', {
        method: 'POST',
        body: JSON.stringify({
          username: document.getElementById('registerUsername').value.trim(),
          email: document.getElementById('registerEmail').value.trim(),
          password: document.getElementById('registerPassword').value
        })
      });
      this.showToast(this.t('register_success'));
      this.closeModal('registerModal');
      this.showModal('loginModal');
    } catch (err) {
      this.showToast(err.message, 'error');
    }
  },
  
  async login(e) {
    e.preventDefault();
    try {
      const data = await this.api('/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          username: document.getElementById('loginUsername').value.trim(),
          password: document.getElementById('loginPassword').value,
          accessKey: document.getElementById('loginAccessKey').value.trim()
        })
      });
      this.user = data.user;
      this.showToast(this.t('login_success'));
      this.closeModal('loginModal');
      this.updateUI();
      this.loadThreads();
      if (this.user.isAdmin) this.loadAdminData();
    } catch (err) {
      this.showToast(err.message, 'error');
    }
  },
  
  async logout() {
    try {
      await this.api('/auth/logout', { method: 'POST' });
      this.user = null;
      location.reload();
    } catch (err) {
      this.showToast(err.message, 'error');
    }
  },
  
  async checkAuth() {
    try {
      this.user = await this.api('/auth/me');
      this.updateUI();
      if (this.user.isAdmin) this.loadAdminData();
    } catch (err) {
      // Not logged in
    }
  },
  
  // ============= THREADS =============
  
  async loadThreads() {
    try {
      this.threads = await this.api('/threads');
      this.renderPublic();
      if (this.user && (this.user.hasPrivateAccess || this.user.isAdmin)) {
        this.renderPrivate();
      }
      document.getElementById('totalThreads').textContent = this.threads.length;
    } catch (err) {
      console.error('Load threads error:', err);
    }
  },
  
  renderPublic() {
    const container = document.getElementById('publicThreads');
    const threads = this.threads.filter(t => !t.is_private);
    
    if (threads.length === 0) {
      container.innerHTML = `<div class="empty-state">${this.t('no_public')}</div>`;
      return;
    }
    
    container.innerHTML = threads.map((t, i) => `
      <div class="thread-item" onclick="app.viewThread(${t.id})" style="animation-delay: ${i * 0.05}s;">
        <div class="thread-header"><div class="thread-title">${this.escapeHtml(t.title)}</div></div>
        <div class="thread-meta">
          <span>${this.t('author')}: ${this.escapeHtml(t.author_username)}</span>
          <span>•</span>
          <span>${this.formatDate(t.created_at)}</span>
          <span>•</span>
          <span>${this.t('replies')}: ${t.reply_count || 0}</span>
          <span>•</span>
          <span>${this.t('views')}: ${t.views || 0}</span>
        </div>
      </div>
    `).join('');
  },
  
  renderPrivate() {
    const container = document.getElementById('privateThreads');
    const threads = this.threads.filter(t => t.is_private);
    
    if (threads.length === 0) {
      container.innerHTML = `<div class="empty-state">${this.t('no_private')}</div>`;
      return;
    }
    
    container.innerHTML = threads.map((t, i) => `
      <div class="thread-item" onclick="app.viewThread(${t.id})" style="animation-delay: ${i * 0.05}s;">
        <div class="thread-header">
          <div class="thread-title">
            ${this.escapeHtml(t.title)}
            <span class="thread-badge private">PRIVATE</span>
          </div>
        </div>
        <div class="thread-meta">
          <span>${this.t('author')}: ${this.escapeHtml(t.author_username)}</span>
          <span>•</span>
          <span>${this.formatDate(t.created_at)}</span>
          <span>•</span>
          <span>${this.t('replies')}: ${t.reply_count || 0}</span>
          <span>•</span>
          <span>${this.t('views')}: ${t.views || 0}</span>
        </div>
      </div>
    `).join('');
  },
  
  async viewThread(id) {
    try {
      const thread = await this.api(`/threads/${id}`);
      const replies = await this.api(`/threads/${id}/replies`);
      
      document.getElementById('threadView').classList.add('active');
      document.getElementById('threadContent').innerHTML = `
        <div class="thread-full">
          <div class="thread-header-full">
            <h1 class="thread-title-full">
              ${this.escapeHtml(thread.title)}
              ${thread.is_private ? '<span class="thread-badge private">PRIVATE</span>' : ''}
            </h1>
            <div class="thread-meta">
              <span>${this.t('author')}: ${this.escapeHtml(thread.author_username)}</span>
              <span>•</span>
              <span>${this.formatDate(thread.created_at)}</span>
              <span>•</span>
              <span>${this.t('views')}: ${thread.views || 0}</span>
            </div>
          </div>
          <div class="thread-body-full">${this.escapeHtml(thread.body)}</div>
        </div>
        
        <div class="replies-section">
          <h3>${this.t('replies')} (${replies.length})</h3>
          <div id="repliesList">
            ${replies.length === 0 ? `<div class="empty-state">${this.t('no_replies')}</div>` : 
              replies.map((r, i) => `
                <div class="reply-item" style="animation-delay: ${i * 0.1}s;">
                  <div class="reply-header">
                    <span class="reply-author">${this.escapeHtml(r.author_username)}</span>
                    <span class="reply-time">${this.formatDate(r.created_at)}</span>
                  </div>
                  <div class="reply-body">${this.escapeHtml(r.text)}</div>
                </div>
              `).join('')
            }
          </div>
          
          ${this.user ? `
            <form onsubmit="app.addReply(event, ${id})" class="reply-form">
              <textarea id="replyText" placeholder="${this.t('your_reply')}" required minlength="5" maxlength="2000"></textarea>
              <button type="submit" class="btn btn-primary">${this.t('add_reply')}</button>
            </form>
          ` : `
            <div class="empty-state">${this.t('login_to_reply')}</div>
          `}
        </div>
      `;
    } catch (err) {
      this.showToast(err.message, 'error');
    }
  },
  
  async createThread(e) {
    e.preventDefault();
    try {
      await this.api('/threads', {
        method: 'POST',
        body: JSON.stringify({
          title: document.getElementById('threadTitle').value.trim(),
          body: document.getElementById('threadBody').value.trim(),
          isPrivate: document.getElementById('isPrivate').checked
        })
      });
      this.showToast(this.t('thread_created'));
      this.closeModal('createThreadModal');
      document.getElementById('threadTitle').value = '';
      document.getElementById('threadBody').value = '';
      document.getElementById('isPrivate').checked = false;
      this.loadThreads();
    } catch (err) {
      this.showToast(err.message, 'error');
    }
  },
  
  async addReply(e, threadId) {
    e.preventDefault();
    try {
      await this.api(`/threads/${threadId}/replies`, {
        method: 'POST',
        body: JSON.stringify({
          text: document.getElementById('replyText').value.trim()
        })
      });
      this.showToast(this.t('reply_added'));
      this.viewThread(threadId);
    } catch (err) {
      this.showToast(err.message, 'error');
    }
  },
  
  backToList() {
    document.getElementById('threadView').classList.remove('active');
    if (this.user && (this.user.hasPrivateAccess || this.user.isAdmin)) {
      this.showSection('private');
    } else {
      this.showSection('public');
    }
  },
  
  // ============= ADMIN =============
  
  async loadAdminData() {
    try {
      const [stats, keys] = await Promise.all([
        this.api('/admin/stats'),
        this.api('/admin/keys')
      ]);
      
      document.getElementById('totalKeys').textContent = stats.totalKeys;
      document.getElementById('activeKeys').textContent = stats.activeKeys;
      document.getElementById('usedKeys').textContent = stats.usedKeys;
      
      this.renderKeys(keys);
    } catch (err) {
      console.error('Load admin error:', err);
    }
  },
  
  renderKeys(keys) {
    const container = document.getElementById('keyList');
    if (keys.length === 0) {
      container.innerHTML = `<div class="empty-state">${this.t('loading')}</div>`;
      return;
    }
    container.innerHTML = keys.map((k, i) => `
      <div class="key-item" style="animation-delay: ${i * 0.03}s;">
        <div>
          <div class="key-code">${this.escapeHtml(k.key_code)}</div>
          <div class="key-status ${k.is_active ? 'active' : ''}">
            ${k.is_active ? this.t('active') : `${this.t('used_by')}: ${this.escapeHtml(k.used_by_username || 'Unknown')}`}
          </div>
        </div>
        <span>${this.formatDate(k.created_at)}</span>
      </div>
    `).join('');
  },
  
  async generateKeys() {
    const count = parseInt(document.getElementById('keyCount').value);
    if (count < 1 || count > 50) {
      this.showToast('Count: 1-50', 'error');
      return;
    }
    try {
      await this.api('/admin/keys/generate', {
        method: 'POST',
        body: JSON.stringify({ count })
      });
      this.showToast(`${count} ${this.t('keys_generated')}`);
      this.loadAdminData();
    } catch (err) {
      this.showToast(err.message, 'error');
    }
  }
};

// ============= INIT =============

document.addEventListener('DOMContentLoaded', () => {
  const glow = document.querySelector('.cursor-glow');
  document.addEventListener('mousemove', e => {
    glow.style.transform = `translate(${e.clientX - 300}px, ${e.clientY - 300}px)`;
  });
  
  setTimeout(() => {
    document.getElementById('loadingScreen').classList.add('hidden');
  }, 800);
  
  document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', e => {
      if (e.target === modal) modal.classList.remove('active');
    });
  });
  
  app.updateI18n();
  app.checkAuth();
  app.loadThreads();
});
