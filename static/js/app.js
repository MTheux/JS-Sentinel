// JS-Sentinel Frontend
// Desenvolvido por: mftheux

let currentResults = null;
let activeFilter = 'all';
let currentSessionId = null;
let allFilesData = [];

// Tab switching
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        if (btn.id === 'clearAllBtn') return; 
        const tab = btn.dataset.tab;
        document.querySelectorAll('.tab-btn').forEach(b => {
            if (b.id !== 'clearAllBtn') b.classList.remove('active');
        });
        document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
        btn.classList.add('active');
        document.getElementById(`${tab}-tab`).classList.remove('hidden');
    });
});

// Listener do Botão "Limpar Tudo"
document.getElementById('clearAllBtn').addEventListener('click', clearAll);

// Single URL analysis
document.getElementById('analyzeBtn').addEventListener('click', () => analyzeSingle());
document.getElementById('jsUrl').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') analyzeSingle();
});

// Multiple URLs analysis
document.getElementById('analyzeMultipleBtn').addEventListener('click', analyzeMultiple);

// File upload
document.getElementById('urlFile').addEventListener('change', handleFileSelect);
document.getElementById('analyzeFileBtn').addEventListener('click', analyzeFile);

// Back to files button
document.getElementById('backToFiles').addEventListener('click', () => {
    document.getElementById('results').classList.add('hidden');
    document.getElementById('files-section').classList.remove('hidden');
    document.getElementById('backToFiles').classList.add('hidden');
});

// Filter buttons
document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeFilter = btn.dataset.filter;
        if (currentResults) {
            displayResults(currentResults);
        }
    });
});

function handleFileSelect(e) {
    const file = e.target.files[0];
    if (file) {
        document.getElementById('fileName').textContent = `Selecionado: ${file.name}`;
        document.getElementById('fileName').classList.remove('hidden');
        document.getElementById('analyzeFileBtn').disabled = false;
    }
}

function clearAll() {
    document.getElementById('jsUrl').value = '';
    document.getElementById('multipleUrls').value = '';
    document.getElementById('urlFile').value = ''; 
    document.getElementById('fileName').textContent = '';
    document.getElementById('fileName').classList.add('hidden');
    document.getElementById('analyzeFileBtn').disabled = true;
    document.getElementById('results').classList.add('hidden');
    document.getElementById('files-section').classList.add('hidden');
    document.getElementById('error').classList.add('hidden');
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('backToFiles').classList.add('hidden');
    currentResults = null;
    currentSessionId = null;
    allFilesData = [];
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    document.querySelector('[data-filter="all"]').classList.add('active');
    activeFilter = 'all';
    const singleTabBtn = document.querySelector('[data-tab="single"]');
    if(singleTabBtn) singleTabBtn.click();
}

async function analyzeSingle() {
    const url = document.getElementById('jsUrl').value.trim();
    if (!url) {
        showError('Por favor, insira uma URL');
        return;
    }
    try { new URL(url); } catch (e) {
        showError('Por favor, insira uma URL válida');
        return;
    }
    let finalUrl = url;
    if (url.includes('0.0.0.0')) {
        if (!confirm('0.0.0.0 não é um endereço válido. Usar localhost?')) return;
        finalUrl = url.replace('0.0.0.0', 'localhost');
        document.getElementById('jsUrl').value = finalUrl;
    }
    await analyzeUrls([finalUrl]);
}

async function analyzeMultiple() {
    const textarea = document.getElementById('multipleUrls');
    const urls = textarea.value.split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));
    
    if (urls.length === 0) {
        showError('Por favor, insira pelo menos uma URL');
        return;
    }
    const fixedUrls = urls.map(url => url.includes('0.0.0.0') ? url.replace('0.0.0.0', 'localhost') : url);
    await analyzeUrls(fixedUrls);
}

async function analyzeFile() {
    const fileInput = document.getElementById('urlFile');
    const file = fileInput.files[0];
    if (!file) {
        showError('Por favor, selecione um arquivo');
        return;
    }
    const formData = new FormData();
    formData.append('file', file);
    await analyzeUrls(null, formData);
}

async function analyzeUrls(urls, formData = null) {
    const loading = document.getElementById('loading');
    const loadingText = document.getElementById('loading-text');
    const error = document.getElementById('error');
    const results = document.getElementById('results');
    const filesSection = document.getElementById('files-section');
    
    error.classList.add('hidden');
    results.classList.add('hidden');
    filesSection.classList.add('hidden');
    loading.classList.remove('hidden');
    
    try {
        let response;
        if (formData) {
            loadingText.textContent = 'Enviando e analisando no servidor...';
            response = await fetch('/api/analyze', {
                method: 'POST',
                body: formData
            });
        } else {
            loadingText.textContent = `Servidor analisando...`;
            response = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ urls })
            });
        }
        
        if (!response.ok) {
            const errorText = await response.text();
            let errorMsg = 'Falha na análise';
            try { errorMsg = JSON.parse(errorText).error || errorMsg; } catch (e) {}
            throw new Error(errorMsg);
        }
        
        const data = await response.json();
        if (!data || !data.results) throw new Error('Resposta inválida');
        
        currentSessionId = data.session_id;
        allFilesData = data.results;
        
        if (data.results.length === 1) {
            currentResults = data.results[0];
            displayResults(currentResults);
            results.classList.remove('hidden');
        } else {
            displayFileCards(data.results);
            filesSection.classList.remove('hidden');
        }
        
    } catch (err) {
        showError(err.message || 'Falha ao analisar');
    } finally {
        loading.classList.add('hidden');
    }
}

function displayFileCards(files) {
    const grid = document.getElementById('files-grid');
    grid.innerHTML = '';
    files.forEach((file) => {
        const card = document.createElement('div');
        card.className = 'file-card';
        card.dataset.fileId = file.file_id;
        card.onclick = () => showFileResults(file);
        
        const hasErrors = file.errors && file.errors.length > 0;
        card.innerHTML = `
            <div class="file-card-header">
                <div class="file-number">Arquivo ${file.file_id}</div>
                <div class="file-status ${hasErrors ? 'error' : 'completed'}">${hasErrors ? 'Erro' : 'Concluído'}</div>
            </div>
            <div class="file-url" title="${file.url}">${file.url}</div>
            <div class="file-stats">
                <div class="file-stat"><i class="fas fa-key"></i> <span>${file.api_keys?.length || 0} Chaves</span></div>
                <div class="file-stat"><i class="fas fa-exclamation-triangle"></i> <span>${file.xss_vulnerabilities?.length || 0} XSS</span></div>
            </div>
            ${hasErrors ? `<div style="margin-top: 10px; color: var(--danger); font-size: 0.85rem;">${file.errors[0]}</div>` : ''}
        `;
        grid.appendChild(card);
    });
}

function showFileResults(file) {
    currentResults = file;
    displayResults(file);
    document.getElementById('files-section').classList.add('hidden');
    document.getElementById('results').classList.remove('hidden');
    document.getElementById('backToFiles').classList.remove('hidden');
    document.getElementById('results-title').textContent = `Resultados - Arquivo ${file.file_id}`;
    document.querySelectorAll('.file-card').forEach(card => {
        card.classList.remove('active');
        if (card.dataset.fileId == file.file_id) card.classList.add('active');
    });
}

function showError(message) {
    const error = document.getElementById('error');
    error.textContent = message;
    error.classList.remove('hidden');
}

function updateStats(data) {
    // Função auxiliar para evitar erro se o elemento não existir no HTML
    const setIfExists = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    };

    setIfExists('stat-api-keys', data.api_keys?.length || 0);
    setIfExists('stat-credentials', data.credentials?.length || 0);
    setIfExists('stat-entropy', data.high_entropy_strings?.length || 0);
    setIfExists('stat-emails', data.emails?.length || 0);
    setIfExists('stat-xss', (data.xss_vulnerabilities?.length || 0) + (data.xss_functions?.length || 0));
    setIfExists('stat-endpoints', data.api_endpoints?.length || 0);
}

function displayResults(data) {
    const container = document.getElementById('findings-content');
    container.innerHTML = '';
    
    updateStats(data);

    // Alerta Source Map
    if (data.source_map_detected) {
        const smAlert = document.createElement('div');
        smAlert.className = 'error';
        smAlert.style.borderColor = 'var(--warning)';
        smAlert.style.color = 'var(--warning)';
        smAlert.style.background = 'rgba(245, 158, 11, 0.1)';
        smAlert.innerHTML = `<i class="fas fa-map"></i> <strong>Source Map Detectado!</strong> O código fonte original pode estar exposto em: <a href="${data.source_map_url}" target="_blank" style="color: inherit; text-decoration: underline;">${data.source_map_url}</a>`;
        container.appendChild(smAlert);
    }
    
    const sections = [
        { key: 'api_keys', title: 'Chaves API', icon: 'fa-key' },
        { key: 'credentials', title: 'Credenciais', icon: 'fa-lock' },
        { key: 'high_entropy_strings', title: 'Alta Entropia', icon: 'fa-random' },
        { key: 'xss_vulnerabilities', title: 'Vuln. XSS', icon: 'fa-exclamation-triangle' },
        { key: 'xss_functions', title: 'Funções de Risco', icon: 'fa-code' },
        { key: 'emails', title: 'Emails', icon: 'fa-envelope' },
        { key: 'api_endpoints', title: 'Endpoints', icon: 'fa-code-branch' },
        { key: 'parameters', title: 'Parâmetros', icon: 'fa-list' },
        { key: 'paths_directories', title: 'Caminhos', icon: 'fa-folder' },
        { key: 'interesting_comments', title: 'Comentários', icon: 'fa-comment' },
    ];
    
    let allItems = [];
    sections.forEach(section => {
        if(data[section.key]) {
            data[section.key].forEach(item => {
                item._sectionTitle = section.title;
                item._icon = section.icon;
                item._category = section.key;
                if (!item.severity) item.severity = 'info';
                if (section.key === 'api_keys' || section.key === 'credentials') item.severity = 'critical';
                if (section.key === 'high_entropy_strings') item.severity = 'high';
                allItems.push(item);
            });
        }
    });

    // Filtros
    if (activeFilter === 'critical_only') {
        allItems = allItems.filter(i => i.severity === 'critical' || i.severity === 'high');
        if (allItems.length === 0) {
            container.innerHTML = '<div style="text-align: center; padding: 40px; color: var(--text-muted);">Nenhum item Crítico ou Alto encontrado.</div>';
            return;
        }
    } else if (activeFilter !== 'all') {
        allItems = allItems.filter(i => i._category === activeFilter);
    }

    // ORDENAÇÃO: Crítico > Alto > Médio > Baixo > Info
    const severityWeight = { 'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1, 'unknown': 0 };
    
    // CORREÇÃO: Função segura para obter o peso, convertendo para String explicitamente
    const getWeight = (item) => {
        if (!item || !item.severity) return 0;
        // Força conversão para string para evitar erro "toLowerCase is not a function"
        const severityStr = String(item.severity).toLowerCase();
        return severityWeight[severityStr] || 0;
    };

    allItems.sort((a, b) => {
        return getWeight(b) - getWeight(a); 
    });

    if (allItems.length > 0) {
        allItems.forEach(item => {
            const el = createFindingItem(item, { title: item._sectionTitle, icon: item._icon, key: item._category });
            container.appendChild(el);
        });
    } else if (!data.source_map_detected) {
        container.innerHTML = '<div style="text-align: center; padding: 40px; color: var(--text-muted);">Nenhum resultado para este filtro.</div>';
    }
}

function createFindingItem(item, section) {
    const div = document.createElement('div');
    div.className = 'finding-item';
    
    const header = document.createElement('div');
    header.className = 'finding-header';
    
    const left = document.createElement('div');
    const type = document.createElement('div');
    type.className = 'finding-type';
    
    if (section.key === 'parameters' && item.param_name) {
        type.innerHTML = `${item.type || section.title} <span style="color: var(--primary); font-weight: 600;">${escapeHtml(item.param_name)}</span>`;
    } else if (section.key === 'high_entropy_strings') {
        type.innerHTML = `Entropia: ${item.entropy} <span style="font-size: 0.8em; color: var(--text-muted)">(Limiar > 4.5)</span>`;
    } else {
        type.textContent = item.type || section.title;
    }
    
    const line = document.createElement('div');
    line.className = 'finding-line';
    line.textContent = `Linha ${item.line}`;
    
    left.appendChild(type);
    left.appendChild(line);
    
    const right = document.createElement('div');
    if (item.severity) {
        const severity = document.createElement('span');
        severity.className = `severity ${item.severity}`;
        severity.textContent = item.severity;
        right.appendChild(severity);
    }
    
    header.appendChild(left);
    header.appendChild(right);
    div.appendChild(header);
    
    if (section.key === 'parameters') {
        if (item.param_name && item.param_value) {
            const paramInfo = document.createElement('div');
            paramInfo.className = 'finding-match';
            paramInfo.style.background = 'var(--bg-card)';
            paramInfo.style.padding = '10px';
            paramInfo.innerHTML = `<div style="margin-bottom: 5px;"><strong>Parâmetro:</strong> <code style="color: var(--primary);">${escapeHtml(item.param_name)}</code></div><div><strong>Valor:</strong> <code style="color: var(--text-muted);">${escapeHtml(item.param_value)}</code></div>`;
            div.appendChild(paramInfo);
        }
    }
    
    if (item.match || item.parameter) {
        const match = document.createElement('div');
        match.className = 'finding-match';
        match.textContent = item.match || item.parameter || item.full_match;
        div.appendChild(match);
    }
    
    if (item.line_content) {
        const lineContent = document.createElement('div');
        lineContent.className = 'finding-match';
        lineContent.style.fontSize = '0.85rem';
        lineContent.style.marginTop = '10px';
        lineContent.textContent = item.line_content;
        div.appendChild(lineContent);
    }
    
    if (item.context || item.line_content) {
        const showCodeBtn = document.createElement('button');
        showCodeBtn.className = 'show-code-btn';
        showCodeBtn.textContent = 'Ver Código';
        showCodeBtn.onclick = () => toggleCode(showCodeBtn, item);
        div.appendChild(showCodeBtn);
        
        const codeContext = document.createElement('div');
        codeContext.className = 'code-context hidden';
        codeContext.appendChild(createCodeBlock(item));
        div.appendChild(codeContext);
    }
    
    return div;
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function createCodeBlock(item) {
    const pre = document.createElement('pre');
    if (item.context) {
        const lines = item.context.split('\n');
        const startLine = item.context_start_line || (item.line - 2);
        lines.forEach((line, index) => {
            const lineNum = startLine + index;
            const codeLine = document.createElement('span');
            codeLine.className = `code-line ${lineNum === item.line ? 'highlight' : ''}`;
            const lineNumber = document.createElement('span');
            lineNumber.className = 'line-number';
            lineNumber.textContent = String(lineNum).padStart(4, ' ') + ': ';
            codeLine.appendChild(lineNumber);
            codeLine.appendChild(document.createTextNode(line || ' '));
            pre.appendChild(codeLine);
        });
    } else if (item.line_content) {
        const codeLine = document.createElement('span');
        codeLine.className = 'code-line highlight';
        const lineNumber = document.createElement('span');
        lineNumber.className = 'line-number';
        lineNumber.textContent = String(item.line).padStart(4, ' ') + ': ';
        codeLine.appendChild(lineNumber);
        codeLine.appendChild(document.createTextNode(item.line_content));
        pre.appendChild(codeLine);
    }
    return pre;
}

function toggleCode(btn, item) {
    const codeContext = btn.nextElementSibling;
    if (codeContext.classList.contains('hidden')) {
        codeContext.classList.remove('hidden');
        btn.textContent = 'Ocultar Código';
    } else {
        codeContext.classList.add('hidden');
        btn.textContent = 'Ver Código';
    }
}