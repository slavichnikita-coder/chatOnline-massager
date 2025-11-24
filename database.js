const sqlite3 = require('sqlite3').verbose();
const path = require('path');

class Database {
    constructor() {
        this.db = new sqlite3.Database(path.join(__dirname, 'chat.db'), (err) => {
            if (err) {
                console.error('Ошибка подключения к базе данных:', err.message);
            } else {
                console.log('Подключение к базе данных SQLite установлено');
                this.init();
            }
        });
    }

    static async create() {
        const instance = new Database();
        await instance.waitForConnection();
        await instance.init();
        return instance;
    }

    waitForConnection() {
        return new Promise((resolve, reject) => {
            const checkConnection = () => {
                if (this.db && this.db.open) {
                    resolve();
                } else {
                    setTimeout(checkConnection, 10);
                }
            };
            checkConnection();
        });
    }

    async init() {
        const tables = [
            // Создание таблицы пользователей
            `CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE,
                password_hash TEXT NOT NULL,
                display_name VARCHAR(100),
                avatar TEXT,
                is_admin BOOLEAN DEFAULT 0,
                is_banned BOOLEAN DEFAULT 0,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`,
            // Создание таблицы комнат чата
            `CREATE TABLE IF NOT EXISTS rooms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(100) NOT NULL,
                description TEXT,
                is_private BOOLEAN DEFAULT 0,
                created_by INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users (id)
            )`,
            // Создание таблицы участников комнат
            `CREATE TABLE IF NOT EXISTS room_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_id INTEGER,
                user_id INTEGER,
                joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (room_id) REFERENCES rooms (id),
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(room_id, user_id)
            )`,
            // Создание таблицы сообщений
            `CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                content TEXT,
                message_type VARCHAR(20) DEFAULT 'text',
                file_url TEXT,
                file_name TEXT,
                file_size INTEGER,
                is_edited BOOLEAN DEFAULT 0,
                is_deleted BOOLEAN DEFAULT 0,
                parent_message_id INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (room_id) REFERENCES rooms (id),
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (parent_message_id) REFERENCES messages (id)
            )`,
            // Создание таблицы реакций на сообщения
            `CREATE TABLE IF NOT EXISTS message_reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER,
                user_id INTEGER,
                emoji VARCHAR(10),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (message_id) REFERENCES messages (id),
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(message_id, user_id, emoji)
            )`,
            // Создание таблицы сессий
            `CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )`,
            // Создание таблицы модерации
            `CREATE TABLE IF NOT EXISTS moderation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER,
                user_id INTEGER,
                action_type VARCHAR(20), -- 'warn', 'mute', 'ban', 'delete'
                reason TEXT,
                moderator_id INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (message_id) REFERENCES messages (id),
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (moderator_id) REFERENCES users (id)
            )`
        ];

        const indexes = [
            `CREATE INDEX IF NOT EXISTS idx_messages_room_id ON messages(room_id)`,
            `CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id)`,
            `CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at)`,
            `CREATE INDEX IF NOT EXISTS idx_room_members_room_id ON room_members(room_id)`,
            `CREATE INDEX IF NOT EXISTS idx_room_members_user_id ON room_members(user_id)`,
            `CREATE INDEX IF NOT EXISTS idx_message_reactions_message_id ON message_reactions(message_id)`
        ];

        try {
            // Создание таблиц
            for (const sql of tables) {
                await this.runAsync(sql);
            }

            // Создание индексов
            for (const sql of indexes) {
                await this.runAsync(sql);
            }

            // Создание комнат по умолчанию
            this.createDefaultRooms();
            console.log('База данных инициализирована успешно');
        } catch (error) {
            console.error('Ошибка инициализации базы данных:', error);
        }
    }

    runAsync(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.run(sql, params, function(err) {
                if (err) reject(err);
                else resolve({ id: this.lastID, changes: this.changes });
            });
        });
    }

    createDefaultRooms() {
        const defaultRooms = [
            { name: 'Общий чат', description: 'Общая комната для всех пользователей' },
            { name: 'Техническая поддержка', description: 'Помощь и поддержка пользователей' },
            { name: 'Новости', description: 'Новости и объявления' }
        ];

        defaultRooms.forEach(room => {
            this.db.get('SELECT id FROM rooms WHERE name = ?', [room.name], (err, row) => {
                if (!row) {
                    this.db.run(
                        'INSERT INTO rooms (name, description) VALUES (?, ?)',
                        [room.name, room.description]
                    );
                }
            });
        });
    }

    // Методы для работы с пользователями
    createUser(userData) {
        return new Promise((resolve, reject) => {
            console.log('Создание пользователя в БД:', userData);
            this.db.run(
                'INSERT INTO users (username, email, password_hash, display_name) VALUES (?, ?, ?, ?)',
                [userData.username, userData.email || null, userData.passwordHash, userData.displayName || userData.username],
                function(err) {
                    if (err) {
                        console.error('Ошибка создания пользователя:', err);
                        reject(err);
                    } else {
                        console.log('Пользователь создан с ID:', this.lastID);
                        resolve({ id: this.lastID, ...userData });
                    }
                }
            );
        });
    }

    getUserByUsername(username) {
        return new Promise((resolve, reject) => {
            this.db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    }

    getUserByEmail(email) {
        return new Promise((resolve, reject) => {
            this.db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    }

    getUserById(id) {
        return new Promise((resolve, reject) => {
            this.db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    }

    updateUserLastSeen(userId) {
        this.db.run('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [userId]);
    }

    updateUserAvatar(userId, avatarUrl) {
        return new Promise((resolve, reject) => {
            this.db.run('UPDATE users SET avatar = ? WHERE id = ?', [avatarUrl, userId], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }

    // Методы для работы с комнатами
    getAllRooms() {
        return new Promise((resolve, reject) => {
            this.db.all(
                `SELECT r.*, u.display_name as creator_name 
                 FROM rooms r 
                 LEFT JOIN users u ON r.created_by = u.id 
                 ORDER BY r.created_at DESC`,
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                }
            );
        });
    }

    getUserRooms(userId) {
        return new Promise((resolve, reject) => {
            this.db.all(
                `SELECT r.*, u.display_name as creator_name
                 FROM rooms r
                 JOIN room_members rm ON r.id = rm.room_id
                 LEFT JOIN users u ON r.created_by = u.id
                 WHERE rm.user_id = ?
                 ORDER BY r.name`,
                [userId],
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                }
            );
        });
    }

    joinRoom(userId, roomId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT OR IGNORE INTO room_members (user_id, room_id) VALUES (?, ?)',
                [userId, roomId],
                (err) => {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
    }

    leaveRoom(userId, roomId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'DELETE FROM room_members WHERE user_id = ? AND room_id = ?',
                [userId, roomId],
                (err) => {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
    }

    // Методы для работы с сообщениями
    createMessage(messageData) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `INSERT INTO messages (room_id, user_id, content, message_type, file_url, file_name, file_size, parent_message_id) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    messageData.roomId,
                    messageData.userId,
                    messageData.content,
                    messageData.messageType || 'text',
                    messageData.fileUrl,
                    messageData.fileName,
                    messageData.fileSize,
                    messageData.parentMessageId
                ],
                function(err) {
                    if (err) {
                        reject(err);
                    } else {
                        resolve({ id: this.lastID, ...messageData });
                    }
                }
            );
        });
    }

    getMessages(roomId, limit = 50, offset = 0) {
        return new Promise((resolve, reject) => {
            this.db.all(
                `SELECT m.*, u.display_name, u.username, u.avatar
                 FROM messages m
                 JOIN users u ON m.user_id = u.id
                 WHERE m.room_id = ? AND m.is_deleted = 0
                 ORDER BY m.created_at DESC
                 LIMIT ? OFFSET ?`,
                [roomId, limit, offset],
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows.reverse()); // Возвращаем в прямом хронологическом порядке
                }
            );
        });
    }

    searchMessages(query, roomId = null) {
        return new Promise((resolve, reject) => {
            let sql = `
                SELECT m.*, u.display_name, u.username, r.name as room_name
                FROM messages m
                JOIN users u ON m.user_id = u.id
                JOIN rooms r ON m.room_id = r.id
                WHERE m.content LIKE ? AND m.is_deleted = 0
            `;
            let params = [`%${query}%`];
            
            if (roomId) {
                sql += ' AND m.room_id = ?';
                params.push(roomId);
            }
            
            sql += ' ORDER BY m.created_at DESC LIMIT 50';
            
            this.db.all(sql, params, (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }

    deleteMessage(messageId) {
        return new Promise((resolve, reject) => {
            this.db.run('UPDATE messages SET is_deleted = 1 WHERE id = ?', [messageId], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }

    // Методы для работы с реакциями
    addReaction(messageId, userId, emoji) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT OR REPLACE INTO message_reactions (message_id, user_id, emoji) VALUES (?, ?, ?)',
                [messageId, userId, emoji],
                (err) => {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
    }

    removeReaction(messageId, userId, emoji) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'DELETE FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?',
                [messageId, userId, emoji],
                (err) => {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
    }

    getMessageReactions(messageId) {
        return new Promise((resolve, reject) => {
            this.db.all(
                `SELECT emoji, COUNT(*) as count
                 FROM message_reactions
                 WHERE message_id = ?
                 GROUP BY emoji`,
                [messageId],
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                }
            );
        });
    }

    // Методы для модерации
    addModerationAction(actionData) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `INSERT INTO moderation (message_id, user_id, action_type, reason, moderator_id) 
                 VALUES (?, ?, ?, ?, ?)`,
                [
                    actionData.messageId,
                    actionData.userId,
                    actionData.actionType,
                    actionData.reason,
                    actionData.moderatorId
                ],
                function(err) {
                    if (err) reject(err);
                    else resolve({ id: this.lastID, ...actionData });
                }
            );
        });
    }

    banUser(userId, reason, moderatorId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE users SET is_banned = 1 WHERE id = ?',
                [userId],
                (err) => {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
    }

    unbanUser(userId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE users SET is_banned = 0 WHERE id = ?',
                [userId],
                (err) => {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
    }

    // Методы для работы с сессиями
    createSession(userId, tokenHash, expiresAt) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
                [userId, tokenHash, expiresAt],
                function(err) {
                    if (err) reject(err);
                    else resolve({ id: this.lastID });
                }
            );
        });
    }

    getSession(tokenHash) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT s.*, u.username, u.display_name, u.is_admin FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token_hash = ? AND s.expires_at > CURRENT_TIMESTAMP',
                [tokenHash],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
    }

    deleteSession(tokenHash) {
        return new Promise((resolve, reject) => {
            this.db.run('DELETE FROM sessions WHERE token_hash = ?', [tokenHash], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }

    cleanupExpiredSessions() {
        this.db.run('DELETE FROM sessions WHERE expires_at <= CURRENT_TIMESTAMP');
    }

    close() {
        return new Promise((resolve) => {
            this.db.close((err) => {
                if (err) {
                    console.error('Ошибка закрытия базы данных:', err.message);
                } else {
                    console.log('База данных закрыта');
                }
                resolve();
            });
        });
    }
}

module.exports = Database;