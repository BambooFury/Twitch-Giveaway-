const express = require('express');
const cors = require('cors');
const fs = require('fs');
const fsPromises = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

// Генерация UUID без внешней библиотеки
function generateUUID() {
    return crypto.randomUUID ? crypto.randomUUID() : 
           'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
               const r = Math.random() * 16 | 0;
               const v = c === 'x' ? r : (r & 0x3 | 0x8);
               return v.toString(16);
           });
}

const app = express();
// Render использует переменную PORT из окружения
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');

// Middleware
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Логирование всех запросов
app.use((req, res, next) => {
    const timestamp = new Date().toLocaleTimeString();
    console.log(`[${timestamp}] ${req.method} ${req.url}`);
    if (req.body && Object.keys(req.body).length > 0) {
        console.log(`  Body:`, JSON.stringify(req.body));
    }
    next();
});

// Обработка ошибок
app.use((err, req, res, next) => {
    console.error(`[ERROR] ${req.method} ${req.url}:`, err);
    res.status(500).json({ error: err.message });
});

// Создаем директорию для данных, если её нет
async function ensureDataDir() {
    // В Vercel файловая система read-only, пропускаем создание директории
    if (process.env.VERCEL) {
        console.log('[VERCEL] Пропуск создания директории данных (read-only файловая система)');
        return;
    }
    
    try {
        await fsPromises.mkdir(DATA_DIR, { recursive: true });
    } catch (error) {
        // Если ошибка read-only, просто игнорируем
        if (error.code === 'EROFS' || error.code === 'EACCES') {
            console.log('[WARN] Пропуск создания директории данных (read-only файловая система)');
            return;
        }
        console.error('Ошибка создания директории данных:', error);
    }
}

// Получение реального IP адреса клиента
function getClientIP(req) {
    // Проверяем заголовки прокси
    let ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
             req.headers['x-real-ip'] ||
             req.headers['cf-connecting-ip'] || // Cloudflare
             req.headers['true-client-ip']; // Cloudflare Enterprise
    
    // Если IP не найден в заголовках, берем из соединения
    if (!ip) {
        ip = req.connection?.remoteAddress ||
             req.socket?.remoteAddress ||
             (req.connection?.socket ? req.connection.socket.remoteAddress : null) ||
             req.ip;
    }
    
    // Конвертируем IPv6 localhost в IPv4
    if (ip === '::1' || ip === '::ffff:127.0.0.1') {
        ip = '127.0.0.1';
    }
    
    // Убираем префикс IPv6-mapped IPv4
    if (ip && ip.startsWith('::ffff:')) {
        ip = ip.replace('::ffff:', '');
    }
    
    return ip || '127.0.0.1';
}

// Получение User Agent
function getUserAgent(req) {
    return req.headers['user-agent'] || 'Unknown';
}

// Загрузка данных из файла
async function loadData(filename) {
    // В Vercel файловая система read-only, возвращаем пустые данные
    if (process.env.VERCEL) {
        console.log(`[VERCEL] Пропуск загрузки ${filename} (read-only файловая система)`);
        return [];
    }
    
    try {
        const filePath = path.join(DATA_DIR, filename);
        const data = await fsPromises.readFile(filePath, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            return [];
        }
        // Если ошибка read-only, возвращаем пустые данные
        if (error.code === 'EROFS' || error.code === 'EACCES') {
            console.log(`[WARN] Пропуск загрузки ${filename} (read-only файловая система)`);
            return [];
        }
        console.error(`Ошибка загрузки ${filename}:`, error);
        return [];
    }
}

// Сохранение данных в файл
async function saveData(filename, data) {
    // В Vercel файловая система read-only, пропускаем сохранение
    if (process.env.VERCEL) {
        console.log(`[VERCEL] Пропуск сохранения ${filename} (read-only файловая система)`);
        return; // Возвращаем успех, но не сохраняем
    }
    
    try {
        const filePath = path.join(DATA_DIR, filename);
        await fsPromises.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8');
    } catch (error) {
        // Если ошибка read-only (например, в других serverless окружениях)
        if (error.code === 'EROFS' || error.code === 'EACCES') {
            console.log(`[WARN] Пропуск сохранения ${filename} (read-only файловая система)`);
            return; // Возвращаем успех, но не сохраняем
        }
        console.error(`Ошибка сохранения ${filename}:`, error);
        throw error;
    }
}

// API: Получение реального IP адреса
app.get('/api/ip', (req, res) => {
    try {
        const clientIP = getClientIP(req);
        const userAgent = getUserAgent(req);
        
        console.log(`[API] GET /api/ip - IP: ${clientIP}`);
        
        res.json({
            ip: clientIP,
            userAgent: userAgent,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('[ERROR] /api/ip:', error);
        res.status(500).json({ error: error.message });
    }
});

// API: Регистрация посетителя
app.post('/api/visitors', async (req, res) => {
    try {
        const clientIP = getClientIP(req);
        const userAgent = getUserAgent(req);
        const { username, userId, channel, action, publicIP, browserInfo } = req.body;
        
        // Используем публичный IP от клиента, если он есть, иначе используем IP с сервера
        // Публичный IP имеет приоритет, так как он реальный внешний IP пользователя
        let finalIP = publicIP;
        
        // Если публичный IP не передан или это localhost, используем IP с сервера
        if (!finalIP || finalIP === '127.0.0.1' || finalIP === '::1' || finalIP.startsWith('192.168.') || 
            finalIP.startsWith('10.') || (finalIP.startsWith('172.') && parseInt(finalIP.split('.')[1]) >= 16 && parseInt(finalIP.split('.')[1]) <= 31)) {
            finalIP = clientIP;
        }
        
        console.log(`[API] POST /api/visitors - User: ${username}, Channel: ${channel}, Action: ${action}, Local IP: ${clientIP}, Public IP: ${publicIP || 'N/A'}, Final IP: ${finalIP}`);
        
        const visitors = await loadData('visitors.json');
        
        const visitor = {
            id: generateUUID(),
            username: username || 'anonymous',
            userId: userId || null,
            ip: finalIP, // Используем финальный IP (публичный или локальный)
            publicIP: publicIP || null, // Сохраняем также публичный IP отдельно
            localIP: clientIP, // Сохраняем локальный IP для справки
            userAgent: userAgent,
            browserInfo: browserInfo || null, // Сохраняем информацию о браузере (старый формат)
            stats: req.body.stats || null, // Сохраняем глобальную статистику (новый формат)
            channel: channel || null,
            action: action || 'visit',
            timestamp: new Date().toISOString(),
            date: new Date().toISOString().split('T')[0]
        };
        
        visitors.push(visitor);
        
        // Сохраняем только последние 10000 записей
        if (visitors.length > 10000) {
            visitors.splice(0, visitors.length - 10000);
        }
        
        await saveData('visitors.json', visitors);
        
        console.log(`[API] Посетитель зарегистрирован: ${visitor.id}`);
        res.json({ success: true, visitor });
    } catch (error) {
        console.error('[ERROR] Ошибка регистрации посетителя:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: Получение всех посетителей
app.get('/api/visitors', async (req, res) => {
    try {
        const { channel, date, limit = 1000 } = req.query;
        let visitors = await loadData('visitors.json');
        
        // Фильтрация по каналу
        if (channel) {
            visitors = visitors.filter(v => v.channel === channel);
        }
        
        // Фильтрация по дате
        if (date) {
            visitors = visitors.filter(v => v.date === date);
        }
        
        // Сортировка по времени (новые первые)
        visitors.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        
        // Лимит
        visitors = visitors.slice(0, parseInt(limit));
        
        res.json({ success: true, visitors, count: visitors.length });
    } catch (error) {
        console.error('Ошибка получения посетителей:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: Получение статистики по IP
app.get('/api/visitors/ip/:ip', async (req, res) => {
    try {
        const { ip } = req.params;
        const visitors = await loadData('visitors.json');
        
        const ipVisitors = visitors.filter(v => v.ip === ip);
        const uniqueUsers = [...new Set(ipVisitors.map(v => v.username))];
        
        res.json({
            success: true,
            ip,
            visits: ipVisitors.length,
            uniqueUsers: uniqueUsers.length,
            users: uniqueUsers,
            visits: ipVisitors
        });
    } catch (error) {
        console.error('Ошибка получения статистики IP:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: Получение IP адреса пользователя по username или userId
app.get('/api/user-ip/:identifier', async (req, res) => {
    try {
        const { identifier } = req.params;
        const visitors = await loadData('visitors.json');
        
        // Ищем последний IP адрес для этого пользователя
        const userVisits = visitors.filter(v => 
            v.username === identifier || 
            v.username?.toLowerCase() === identifier.toLowerCase() ||
            v.userId === identifier
        );
        
        if (userVisits.length > 0) {
            // Берем последний IP адрес (самый свежий)
            // Приоритет: publicIP > ip (если ip не локальный)
            const lastVisit = userVisits[userVisits.length - 1];
            let finalIP = lastVisit.publicIP || lastVisit.ip;
            
            // Если IP локальный, но есть публичный в других записях, ищем его
            if (finalIP && (finalIP.startsWith('192.168.') || finalIP.startsWith('10.') || 
                finalIP === '127.0.0.1' || finalIP === '::1')) {
                const publicIPVisit = userVisits.find(v => v.publicIP && 
                    !v.publicIP.startsWith('192.168.') && 
                    !v.publicIP.startsWith('10.') && 
                    v.publicIP !== '127.0.0.1' && 
                    v.publicIP !== '::1');
                if (publicIPVisit) {
                    finalIP = publicIPVisit.publicIP;
                }
            }
            
            res.json({
                success: true,
                username: identifier,
                ip: finalIP,
                lastSeen: lastVisit.timestamp
            });
        } else {
            res.json({
                success: false,
                message: 'User not found'
            });
        }
    } catch (error) {
        console.error('Ошибка получения IP пользователя:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: Получение всех IP адресов пользователей (маппинг username -> IP)
app.get('/api/users-ip', async (req, res) => {
    try {
        const visitors = await loadData('visitors.json');
        const ipMap = {};
        
        // Создаем маппинг: username -> последний IP адрес
        visitors.forEach(visitor => {
            if (visitor.username) {
                const username = visitor.username.toLowerCase();
                // Приоритет: publicIP > ip (если ip не локальный)
                let ipToUse = visitor.publicIP || visitor.ip;
                
                // Пропускаем локальные IP, если есть публичный
                if (ipToUse && (ipToUse.startsWith('192.168.') || ipToUse.startsWith('10.') || 
                    ipToUse === '127.0.0.1' || ipToUse === '::1')) {
                    // Если это локальный IP, но есть публичный в других записях, используем его
                    if (!ipMap[username] || 
                        (ipMap[username].ip && (ipMap[username].ip.startsWith('192.168.') || 
                         ipMap[username].ip.startsWith('10.') || 
                         ipMap[username].ip === '127.0.0.1' || 
                         ipMap[username].ip === '::1'))) {
                        // Ищем публичный IP в других записях этого пользователя
                        const publicIPVisit = visitors.find(v => 
                            v.username?.toLowerCase() === username && 
                            v.publicIP && 
                            !v.publicIP.startsWith('192.168.') && 
                            !v.publicIP.startsWith('10.') && 
                            v.publicIP !== '127.0.0.1' && 
                            v.publicIP !== '::1'
                        );
                        if (publicIPVisit) {
                            ipToUse = publicIPVisit.publicIP;
                        }
                    }
                }
                
                // Берем последний IP адрес для каждого пользователя
                if (ipToUse && (!ipMap[username] || new Date(visitor.timestamp) > new Date(ipMap[username].timestamp))) {
                    ipMap[username] = {
                        ip: ipToUse,
                        timestamp: visitor.timestamp,
                        userId: visitor.userId
                    };
                }
            }
        });
        
        res.json({
            success: true,
            ipMap: ipMap
        });
    } catch (error) {
        console.error('Ошибка получения IP адресов пользователей:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: Сохранение данных пользователей
app.post('/api/users', async (req, res) => {
    try {
        const clientIP = getClientIP(req);
        const { users, streamers, authLog, notifications, settings } = req.body;
        
        if (users) {
            await saveData('users.json', users);
        }
        if (streamers) {
            await saveData('streamers.json', streamers);
        }
        if (authLog) {
            await saveData('auth_log.json', authLog);
        }
        if (notifications) {
            await saveData('notifications.json', notifications);
        }
        if (settings) {
            await saveData('user_management_settings.json', settings);
        }
        
        res.json({ success: true, message: 'Данные сохранены' });
    } catch (error) {
        console.error('Ошибка сохранения данных:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: Загрузка данных пользователей
app.get('/api/users', async (req, res) => {
    try {
        const users = await loadData('users.json');
        const streamers = await loadData('streamers.json');
        const authLog = await loadData('auth_log.json');
        const notifications = await loadData('notifications.json');
        const settings = await loadData('user_management_settings.json');
        
        res.json({
            success: true,
            users,
            streamers,
            authLog,
            notifications,
            settings
        });
    } catch (error) {
        console.error('Ошибка загрузки данных:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: Сохранение розыгрышей
app.post('/api/giveaways', async (req, res) => {
    try {
        const { giveaways, participants, winners } = req.body;
        
        if (giveaways) {
            await saveData('giveaways.json', giveaways);
        }
        if (participants) {
            await saveData('giveaway_participants.json', participants);
        }
        if (winners) {
            await saveData('winners.json', winners);
        }
        
        res.json({ success: true, message: 'Данные розыгрышей сохранены' });
    } catch (error) {
        console.error('Ошибка сохранения розыгрышей:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: Загрузка розыгрышей
app.get('/api/giveaways', async (req, res) => {
    try {
        const { channel } = req.query;
        
        const giveaways = await loadData('giveaways.json');
        const participants = await loadData('giveaway_participants.json');
        const winners = await loadData('winners.json');
        
        let filteredGiveaways = giveaways;
        if (channel) {
            filteredGiveaways = giveaways.filter(g => g.channel === channel);
        }
        
        res.json({
            success: true,
            giveaways: filteredGiveaways,
            participants,
            winners
        });
    } catch (error) {
        console.error('Ошибка загрузки розыгрышей:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: Сохранение истории чата
app.post('/api/chat-history', async (req, res) => {
    try {
        const { username, history, meta } = req.body;
        
        const chatHistory = await loadData('chat_history.json');
        const chatMeta = await loadData('chat_meta.json');
        
        if (username && history) {
            const existingIndex = chatHistory.findIndex(h => h.username === username);
            if (existingIndex >= 0) {
                chatHistory[existingIndex] = { username, history };
            } else {
                chatHistory.push({ username, history });
            }
        }
        
        if (username && meta) {
            const existingMetaIndex = chatMeta.findIndex(m => m.username === username);
            if (existingMetaIndex >= 0) {
                chatMeta[existingMetaIndex] = { username, ...meta };
            } else {
                chatMeta.push({ username, ...meta });
            }
        }
        
        await saveData('chat_history.json', chatHistory);
        await saveData('chat_meta.json', chatMeta);
        
        res.json({ success: true });
    } catch (error) {
        console.error('Ошибка сохранения истории чата:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: Загрузка истории чата
app.get('/api/chat-history/:username', async (req, res) => {
    try {
        const { username } = req.params;
        const chatHistory = await loadData('chat_history.json');
        const chatMeta = await loadData('chat_meta.json');
        
        const userHistory = chatHistory.find(h => h.username === username);
        const userMeta = chatMeta.find(m => m.username === username);
        
        res.json({
            success: true,
            history: userHistory?.history || [],
            meta: userMeta || {}
        });
    } catch (error) {
        console.error('Ошибка загрузки истории чата:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: Получение статистики
app.get('/api/stats', async (req, res) => {
    try {
        const visitors = await loadData('visitors.json');
        const users = await loadData('users.json');
        const giveaways = await loadData('giveaways.json');
        
        const uniqueIPs = [...new Set(visitors.map(v => v.ip))].length;
        const uniqueUsers = [...new Set(visitors.map(v => v.username))].length;
        const todayVisitors = visitors.filter(v => {
            const today = new Date().toISOString().split('T')[0];
            return v.date === today;
        }).length;
        
        res.json({
            success: true,
            stats: {
                totalVisits: visitors.length,
                uniqueIPs,
                uniqueUsers,
                todayVisitors,
                totalUsers: users.length,
                activeGiveaways: giveaways.filter(g => g.status === 'active').length
            }
        });
    } catch (error) {
        console.error('Ошибка получения статистики:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Главная страница - отдаем ewropg.html (ДО статических файлов, чтобы иметь приоритет)
app.get('/', (req, res) => {
    try {
        console.log('[PAGE] Запрос главной страницы от:', req.ip);
        console.log('[PAGE] User-Agent:', req.headers['user-agent']);
        console.log('[PAGE] __dirname:', __dirname);
        
        // Для Vercel используем правильный путь
        let filePath;
        if (process.env.VERCEL) {
            // В Vercel окружении файлы находятся в корне проекта
            filePath = path.join(process.cwd(), 'ewropg.html');
        } else {
            // Локально используем __dirname
            filePath = path.join(__dirname, 'ewropg.html');
        }
        
        console.log('[PAGE] Отправка файла:', filePath);
        console.log('[PAGE] Файл существует:', fs.existsSync(filePath));
        
        // Проверяем существование файла
        if (!fs.existsSync(filePath)) {
            console.error('[ERROR] Файл не найден:', filePath);
            console.error('[ERROR] process.cwd():', process.cwd());
            console.error('[ERROR] __dirname:', __dirname);
            // Пробуем альтернативный путь
            const altPath = path.join(__dirname, 'ewropg.html');
            if (fs.existsSync(altPath)) {
                console.log('[PAGE] Используем альтернативный путь:', altPath);
                filePath = altPath;
            } else {
                return res.status(404).send('Файл не найден');
            }
        }
        
        res.sendFile(filePath, (err) => {
            if (err) {
                console.error('[ERROR] Ошибка отправки файла:', err);
                res.status(500).send(`Ошибка загрузки страницы: ${err.message}`);
            } else {
                console.log('[PAGE] Файл успешно отправлен');
            }
        });
    } catch (error) {
        console.error('[ERROR] Ошибка главной страницы:', error);
        res.status(500).send(`Ошибка сервера: ${error.message}`);
    }
});

// API: Сбор статистики (глобальный сбор данных)
app.post('/api/collect', async (req, res) => {
    try {
        const clientIP = getClientIP(req);
        const stats = req.body;
        
        console.log(`[API] POST /api/collect - IP: ${clientIP}`);
        console.log(`[API] Stats received:`, {
            userAgent: stats.userAgent?.substring(0, 50),
            platform: stats.platform,
            behavior: stats.behavior
        });
        
        // Можно сохранять статистику в отдельный файл или в visitors.json
        // Для простоты сохраняем в visitors.json с action='stats'
        const visitors = await loadData('visitors.json');
        
        const statEntry = {
            id: generateUUID(),
            ip: clientIP,
            stats: stats,
            timestamp: new Date().toISOString(),
            date: new Date().toISOString().split('T')[0],
            action: 'stats'
        };
        
        visitors.push(statEntry);
        
        // Сохраняем только последние 10000 записей
        if (visitors.length > 10000) {
            visitors.splice(0, visitors.length - 10000);
        }
        
        await saveData('visitors.json', visitors);
        
        res.json({ success: true });
    } catch (error) {
        console.error('[ERROR] Ошибка сохранения статистики:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: События поведения (клики, скролл, время)
app.post('/api/event', express.text({ type: '*/*' }), async (req, res) => {
    try {
        const clientIP = getClientIP(req);
        let eventData;
        
        // Для sendBeacon данные приходят как строка, для fetch - как JSON
        try {
            eventData = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
        } catch (e) {
            // Если не удалось распарсить, пробуем как есть
            eventData = req.body;
        }
        
        console.log(`[API] POST /api/event - IP: ${clientIP}, Type: ${eventData?.type || 'unknown'}`);
        
        // Сохраняем события в visitors.json с action='event'
        const visitors = await loadData('visitors.json');
        
        const eventEntry = {
            id: generateUUID(),
            ip: clientIP,
            event: eventData,
            timestamp: new Date().toISOString(),
            date: new Date().toISOString().split('T')[0],
            action: 'event'
        };
        
        visitors.push(eventEntry);
        
        // Сохраняем только последние 10000 записей
        if (visitors.length > 10000) {
            visitors.splice(0, visitors.length - 10000);
        }
        
        await saveData('visitors.json', visitors);
        
        res.json({ success: true });
    } catch (error) {
        console.error('[ERROR] Ошибка сохранения события:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Раздача статических файлов из корня проекта (после API маршрутов и главной страницы)
app.use(express.static(__dirname));

// Обработка всех остальных маршрутов (для SPA) - возвращаем ewropg.html
// Это нужно для правильной работы с hash routing после OAuth редиректа
app.get('*', (req, res) => {
    // Пропускаем API запросы
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'API endpoint not found' });
    }
    
    // Для всех остальных запросов возвращаем главную страницу
    try {
        let filePath;
        if (process.env.VERCEL) {
            filePath = path.join(process.cwd(), 'ewropg.html');
        } else {
            filePath = path.join(__dirname, 'ewropg.html');
        }
        
        if (!fs.existsSync(filePath)) {
            const altPath = path.join(__dirname, 'ewropg.html');
            filePath = fs.existsSync(altPath) ? altPath : filePath;
        }
        
        res.sendFile(filePath);
    } catch (error) {
        console.error('[ERROR] Ошибка отправки SPA:', error);
        res.status(500).send(`Ошибка сервера: ${error.message}`);
    }
});

// Запуск сервера
async function startServer() {
    await ensureDataDir();
    
    app.listen(PORT, () => {
        console.log(`🚀 Сервер запущен на порту ${PORT}`);
        console.log(`📁 Данные сохраняются в: ${DATA_DIR}`);
        console.log(`🌐 API доступен по адресу: http://localhost:${PORT}/api`);
        console.log(`📄 Приложение доступно по адресу: http://localhost:${PORT}/`);
        console.log(`\n✅ Откройте в браузере: http://localhost:${PORT}/`);
        console.log(`⚠️  НЕ используйте Live Server одновременно!`);
        console.log(`\n📋 Проверка: откройте http://127.0.0.1:${PORT}/ если localhost не работает`);
    });
}

// Экспорт для Vercel (serverless)
module.exports = app;

// Локальный запуск (только если не в serverless окружении)
if (!process.env.VERCEL && !process.env.AWS_LAMBDA_FUNCTION_NAME) {
    startServer().catch(console.error);
}

