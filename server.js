const express = require('express');
const http = require('http');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const { body, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const Database = require('./database');
const { AuthService, authenticateToken, requireAdmin, requireNotBanned } = require('./auth');
const ChatServer = require('./chat-server');

const app = express();
const server = http.createServer(app);
const db = new Database();
const authService = new AuthService();

// Настройка безопасности
app.use(helmet({
    contentSecurityPolicy: false, // Отключаем для упрощения разработки
    crossOriginEmbedderPolicy: false
}));

// Настройка сжатия
app.use(compression());

// Настройка CORS
app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:8080', 'http://localhost:5000'],
    credentials: true
}));

// Настройка rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 минут
    max: 1000, // максимум 1000 запросов с IP
    message: 'Слишком много запросов, попробуйте позже'
});
app.use(limiter);

// Парсинг JSON и URL-кодированных данных
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Статические файлы
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// Создание директории для загрузок
if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
    fs.mkdirSync(path.join(__dirname, 'uploads'));
}

// Настройка multer для загрузки файлов
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, 'uploads'));
    },
    filename: (req, file, cb) => {
        const uniqueName = `${uuidv4()}-${Date.now()}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

const fileFilter = (req, file, cb) => {
    // Разрешенные типы файлов
    const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt|mp4|mp3|wav|ppt|pptx/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
        return cb(null, true);
    } else {
        cb(new Error('Неподдерживаемый тип файла'));
    }
};

const upload = multer({
    storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB максимум
    fileFilter
});

// ================== API РОУТЫ ==================

// РЕГИСТРАЦИЯ
app.post('/api/register', [
    body('username').isLength({ min: 3, max: 50 }).matches(/^[a-zA-Z0-9_]+$/),
    body('password').isLength({ min: 6 }),
    body('displayName').optional().isLength({ max: 100 })
], async (req, res) => {
    try {
        console.log('Получен запрос на регистрацию:', req.body);

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            console.log('Ошибки валидации:', errors.array());
            return res.status(400).json({
                error: 'Ошибка валидации',
                details: errors.array()
            });
        }

        const { username, password, displayName } = req.body;
        console.log('Данные для регистрации:', { username, displayName });

        const result = await authService.register({ username, password, displayName });
        console.log('Результат регистрации:', result);

        if (result.success) {
            res.json({
                message: 'Регистрация успешна',
                user: result.user,
                token: result.token
            });
        } else {
            console.error('Ошибка в authService.register:', result.error);
            res.status(400).json({ error: result.error });
        }
    } catch (error) {
        console.error('Ошибка регистрации:', error);
        res.status(500).json({ error: 'Ошибка сервера при регистрации' });
    }
});

// ВХОД
app.post('/api/login', [
    body('username').notEmpty(),
    body('password').notEmpty()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: 'Ошибка валидации', 
                details: errors.array() 
            });
        }

        const { username, password } = req.body;
        
        const result = await authService.login(username, password);
        
        if (result.success) {
            res.json({
                message: 'Вход выполнен успешно',
                user: result.user,
                token: result.token
            });
        } else {
            res.status(401).json({ error: result.error });
        }
    } catch (error) {
        console.error('Ошибка входа:', error);
        res.status(500).json({ error: 'Ошибка сервера при входе' });
    }
});

// ВЫХОД
app.post('/api/logout', authenticateToken(authService), async (req, res) => {
    try {
        const token = req.headers.authorization.split(' ')[1];
        await authService.logout(token);
        res.json({ message: 'Выход выполнен успешно' });
    } catch (error) {
        console.error('Ошибка выхода:', error);
        res.status(500).json({ error: 'Ошибка сервера при выходе' });
    }
});

// ВАЛИДАЦИЯ ТОКЕНА
app.get('/api/validate-token', authenticateToken(authService), async (req, res) => {
    try {
        res.json({
            valid: true,
            user: req.user
        });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка валидации токена' });
    }
});

// ПОЛУЧЕНИЕ КОМНАТ
app.get('/api/rooms', authenticateToken(authService), requireNotBanned, async (req, res) => {
    try {
        const rooms = await db.getUserRooms(req.user.id);
        res.json({ rooms });
    } catch (error) {
        console.error('Ошибка получения комнат:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// СОЗДАНИЕ КОМНАТЫ
app.post('/api/rooms', [
    authenticateToken(authService),
    requireNotBanned,
    body('name').isLength({ min: 1, max: 100 }),
    body('description').optional().isLength({ max: 500 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Ошибка валидации', details: errors.array() });
        }

        const { name, description, isPrivate = false } = req.body;

        return new Promise((resolve, reject) => {
            db.db.run(
                'INSERT INTO rooms (name, description, is_private, created_by) VALUES (?, ?, ?, ?)',
                [name, description, isPrivate ? 1 : 0, req.user.id],
                function(err) {
                    if (err) {
                        reject(err);
                        return;
                    }

                    const roomId = this.lastID;
                    
                    // Создатель автоматически присоединяется к комнате
                    db.joinRoom(req.user.id, roomId).then(() => {
                        res.json({
                            success: true,
                            room: {
                                id: roomId,
                                name,
                                description,
                                isPrivate,
                                createdBy: req.user.id,
                                createdAt: new Date().toISOString()
                            }
                        });
                    }).catch(err => {
                        res.status(500).json({ error: 'Ошибка присоединения к комнате' });
                    });
                }
            );
        });
    } catch (error) {
        console.error('Ошибка создания комнаты:', error);
        res.status(500).json({ error: 'Ошибка сервера при создании комнаты' });
    }
});

// ПРИСОЕДИНЕНИЕ К КОМНАТЕ
app.post('/api/rooms/:roomId/join', authenticateToken(authService), requireNotBanned, async (req, res) => {
    try {
        const { roomId } = req.params;
        await db.joinRoom(req.user.id, roomId);
        res.json({ success: true, message: 'Присоединение к комнате выполнено' });
    } catch (error) {
        console.error('Ошибка присоединения к комнате:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ВЫХОД ИЗ КОМНАТЫ
app.post('/api/rooms/:roomId/leave', authenticateToken(authService), async (req, res) => {
    try {
        const { roomId } = req.params;
        await db.leaveRoom(req.user.id, roomId);
        res.json({ success: true, message: 'Выход из комнаты выполнен' });
    } catch (error) {
        console.error('Ошибка выхода из комнаты:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ПОИСК СООБЩЕНИЙ
app.get('/api/messages/search', authenticateToken(authService), requireNotBanned, async (req, res) => {
    try {
        const { q, roomId } = req.query;
        if (!q || q.trim().length < 2) {
            return res.json({ results: [] });
        }

        const results = await db.searchMessages(q.trim(), roomId ? parseInt(roomId) : null);
        res.json({ 
            query: q.trim(),
            results 
        });
    } catch (error) {
        console.error('Ошибка поиска:', error);
        res.status(500).json({ error: 'Ошибка сервера при поиске' });
    }
});

// ЗАГРУЗКА ФАЙЛОВ
app.post('/api/upload', authenticateToken(authService), requireNotBanned, upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'Файл не выбран' });
        }

        const fileUrl = `/uploads/${req.file.filename}`;
        const fileInfo = {
            url: fileUrl,
            name: req.file.originalname,
            size: req.file.size,
            type: req.file.mimetype
        };

        res.json({ 
            success: true,
            file: fileInfo
        });
    } catch (error) {
        console.error('Ошибка загрузки файла:', error);
        res.status(500).json({ error: 'Ошибка сервера при загрузке файла' });
    }
});

// ОБНОВЛЕНИЕ ПРОФИЛЯ
app.put('/api/profile', authenticateToken(authService), [
    body('displayName').optional().isLength({ max: 100 }),
    body('avatar').optional().isURL()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Ошибка валидации', details: errors.array() });
        }

        const updates = {};
        if (req.body.displayName) updates.display_name = req.body.displayName;
        if (req.body.avatar) updates.avatar = req.body.avatar;

        const result = await authService.updateProfile(req.user.id, updates);
        
        if (result.success) {
            res.json({ 
                success: true,
                message: 'Профиль обновлен',
                user: {
                    ...req.user,
                    displayName: updates.display_name || req.user.displayName,
                    avatar: updates.avatar || req.user.avatar
                }
            });
        } else {
            res.status(400).json({ error: result.error });
        }
    } catch (error) {
        console.error('Ошибка обновления профиля:', error);
        res.status(500).json({ error: 'Ошибка сервера при обновлении профиля' });
    }
});

// СМЕНА ПАРОЛЯ
app.put('/api/change-password', authenticateToken(authService), [
    body('currentPassword').notEmpty(),
    body('newPassword').isLength({ min: 6 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Ошибка валидации', details: errors.array() });
        }

        const { currentPassword, newPassword } = req.body;
        
        const result = await authService.changePassword(req.user.id, currentPassword, newPassword);
        
        if (result.success) {
            res.json({ success: true, message: 'Пароль изменен успешно' });
        } else {
            res.status(400).json({ error: result.error });
        }
    } catch (error) {
        console.error('Ошибка смены пароля:', error);
        res.status(500).json({ error: 'Ошибка сервера при смене пароля' });
    }
});

// ================== АДМИНСКИЕ РОУТЫ ==================

// ПОЛУЧЕНИЕ СТАТИСТИКИ
app.get('/api/admin/stats', authenticateToken(authService), requireAdmin, async (req, res) => {
    try {
        const result = await authService.getUserStats();
        res.json(result);
    } catch (error) {
        console.error('Ошибка получения статистики:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ПОЛУЧЕНИЕ ВСЕХ ПОЛЬЗОВАТЕЛЕЙ
app.get('/api/admin/users', authenticateToken(authService), requireAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 50, search } = req.query;
        const offset = (page - 1) * limit;

        let sql = 'SELECT id, username, email, display_name, avatar, is_admin, is_banned, last_seen, created_at FROM users';
        let params = [];

        if (search) {
            sql += ' WHERE username LIKE ? OR display_name LIKE ? OR (email IS NOT NULL AND email LIKE ?)';
            params.push(`%${search}%`, `%${search}%`, `%${search}%`);
        }

        sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        params.push(parseInt(limit), parseInt(offset));

        const users = await new Promise((resolve, reject) => {
            db.db.all(sql, params, (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });

        res.json({ users });
    } catch (error) {
        console.error('Ошибка получения пользователей:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// БЛОКИРОВКА/РАЗБЛОКИРОВКА ПОЛЬЗОВАТЕЛЯ
app.put('/api/admin/users/:userId/ban', authenticateToken(authService), requireAdmin, [
    body('isBanned').isBoolean(),
    body('reason').optional().isLength({ max: 500 })
], async (req, res) => {
    try {
        const { userId } = req.params;
        const { isBanned, reason } = req.body;

        const result = await authService.toggleUserBan(parseInt(userId), isBanned, req.user.id);
        
        if (result.success) {
            res.json({ 
                success: true, 
                message: isBanned ? 'Пользователь заблокирован' : 'Пользователь разблокирован' 
            });
        } else {
            res.status(400).json({ error: result.error });
        }
    } catch (error) {
        console.error('Ошибка изменения статуса пользователя:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ================== STATIC ROUTES ==================

// Главная страница
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Мини мессенджер виджет
app.get('/widget', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'widget.html'));
});

// SPA поддержка - все остальные роуты отправляют на index.html
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ================== СОЗДАНИЕ И НАСТРОЙКА WEBSOCKET ==================

const chatServer = new ChatServer(server);

// Обработка ошибок
process.on('uncaughtException', (error) => {
    console.error('Необработанное исключение:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Необработанное отклонение Promise:', reason);
});

// Запуск сервера
const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
    console.log(`
🚀 Сервер запущен на порту ${PORT}
🌐 Откройте http://localhost:${PORT} в браузере
💬 Чат в реальном времени готов к работе
📁 Файлы загружаются в директорию uploads/
🗄️ База данных: SQLite (chat.db)
    `);
});

// Корректное завершение работы
process.on('SIGTERM', () => {
    console.log('Получен SIGTERM, завершаю работу...');
    server.close(() => {
        console.log('HTTP сервер закрыт');
        chatServer.close();
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('Получен SIGINT, завершаю работу...');
    server.close(() => {
        console.log('HTTP сервер закрыт');
        chatServer.close();
        process.exit(0);
    });
});

module.exports = { app, server };