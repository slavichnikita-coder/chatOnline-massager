const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const Database = require('./database');

class AuthService {
    constructor() {
        this.db = new Database();
        this.JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
        this.JWT_EXPIRES_IN = '24h';
    }

    // Хеширование пароля
    async hashPassword(password) {
        return await bcrypt.hash(password, 12);
    }

    // Проверка пароля
    async verifyPassword(password, hash) {
        return await bcrypt.compare(password, hash);
    }

    // Генерация JWT токена
    generateToken(user) {
        return jwt.sign(
            {
                id: user.id,
                username: user.username,
                displayName: user.display_name,
                isAdmin: user.is_admin
            },
            this.JWT_SECRET,
            { expiresIn: this.JWT_EXPIRES_IN }
        );
    }

    // Проверка JWT токена
    verifyToken(token) {
        try {
            return jwt.verify(token, this.JWT_SECRET);
        } catch (error) {
            return null;
        }
    }

    // Регистрация пользователя
    async register(userData) {
        try {
            console.log('Регистрация пользователя:', userData);

            // Проверка уникальности имени пользователя
            const existingUser = await this.db.getUserByUsername(userData.username);
            console.log('Проверка существующего пользователя:', existingUser);
            if (existingUser) {
                throw new Error('Пользователь с таким именем уже существует');
            }

            // Хеширование пароля
            const passwordHash = await this.hashPassword(userData.password);
            console.log('Пароль захеширован');

            // Создание пользователя
            const newUser = await this.db.createUser({
                username: userData.username,
                passwordHash,
                displayName: userData.displayName || userData.username
            });
            console.log('Пользователь создан:', newUser);

            // Генерация токена
            const token = this.generateToken(newUser);
            console.log('Токен сгенерирован');

            // Создание сессии
            const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
            const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 часа
            console.log('Создание сессии для пользователя:', newUser.id, 'с хешем:', tokenHash.substring(0, 10) + '...', 'истекает:', expiresAt.toISOString());
            await this.db.createSession(newUser.id, tokenHash, expiresAt.toISOString());
            console.log('Сессия создана успешно');

            // Добавление в общие комнаты
            const rooms = await this.db.getAllRooms();
            console.log('Найдено комнат:', rooms.length);
            for (const room of rooms) {
                await this.db.joinRoom(newUser.id, room.id);
            }
            console.log('Пользователь добавлен в комнаты');

            return {
                success: true,
                user: {
                    id: newUser.id,
                    username: newUser.username,
                    displayName: newUser.display_name,
                    avatar: newUser.avatar,
                    isAdmin: newUser.is_admin
                },
                token
            };
        } catch (error) {
            console.error('Ошибка в register:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Вход пользователя
    async login(username, password) {
        try {
            // Поиск пользователя по имени пользователя
            const user = await this.db.getUserByUsername(username);

            if (!user) {
                throw new Error('Пользователь не найден');
            }

            if (user.is_banned) {
                throw new Error('Пользователь заблокирован');
            }

            // Проверка пароля
            const isValidPassword = await this.verifyPassword(password, user.password_hash);
            if (!isValidPassword) {
                throw new Error('Неверный пароль');
            }

            // Обновление времени последнего входа
            this.db.updateUserLastSeen(user.id);

            // Генерация токена
            const token = this.generateToken(user);

            // Создание сессии
            const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
            const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 часа
            await this.db.createSession(user.id, tokenHash, expiresAt.toISOString());

            return {
                success: true,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    displayName: user.display_name,
                    avatar: user.avatar,
                    isAdmin: user.is_admin,
                    lastSeen: user.last_seen
                },
                token
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Выход пользователя
    async logout(token) {
        try {
            const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
            await this.db.deleteSession(tokenHash);
            return { success: true };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Проверка токена и получение пользователя
    async validateToken(token) {
        try {
            console.log('Валидация токена...');
            const decoded = this.verifyToken(token);
            if (!decoded) {
                console.log('Токен недействительный');
                return { valid: false, error: 'Недействительный токен' };
            }

            const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
            console.log('Поиск сессии с хешем:', tokenHash.substring(0, 10) + '...');
            const session = await this.db.getSession(tokenHash);
            console.log('Найденная сессия:', session);

            if (!session) {
                console.log('Сессия не найдена');
                return { valid: false, error: 'Сессия истекла' };
            }

            const user = await this.db.getUserById(session.user_id);
            if (!user || user.is_banned) {
                return { valid: false, error: 'Пользователь не найден или заблокирован' };
            }

            return {
                valid: true,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    displayName: user.display_name,
                    avatar: user.avatar,
                    isAdmin: user.is_admin,
                    lastSeen: user.last_seen
                }
            };
        } catch (error) {
            return { valid: false, error: error.message };
        }
    }

    // Обновление профиля пользователя
    async updateProfile(userId, updates) {
        try {
            const allowedUpdates = ['display_name', 'avatar'];
            const updateFields = [];
            const updateValues = [];

            for (const [key, value] of Object.entries(updates)) {
                if (allowedUpdates.includes(key)) {
                    updateFields.push(`${key} = ?`);
                    updateValues.push(value);
                }
            }

            if (updateFields.length === 0) {
                throw new Error('Нет допустимых полей для обновления');
            }

            updateValues.push(userId);

            return new Promise((resolve, reject) => {
                this.db.db.run(
                    `UPDATE users SET ${updateFields.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
                    updateValues,
                    function(err) {
                        if (err) {
                            reject(err);
                        } else {
                            resolve({ success: true, changes: this.changes });
                        }
                    }
                );
            });
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Смена пароля
    async changePassword(userId, currentPassword, newPassword) {
        try {
            const user = await this.db.getUserById(userId);
            if (!user) {
                throw new Error('Пользователь не найден');
            }

            const isValidPassword = await this.verifyPassword(currentPassword, user.password_hash);
            if (!isValidPassword) {
                throw new Error('Неверный текущий пароль');
            }

            const newPasswordHash = await this.hashPassword(newPassword);

            return new Promise((resolve, reject) => {
                this.db.db.run(
                    'UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                    [newPasswordHash, userId],
                    function(err) {
                        if (err) {
                            reject(err);
                        } else {
                            resolve({ success: true });
                        }
                    }
                );
            });
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Блокировка/разблокировка пользователя (для администраторов)
    async toggleUserBan(userId, isBanned, moderatorId) {
        try {
            const user = await this.db.getUserById(userId);
            if (!user) {
                throw new Error('Пользователь не найден');
            }

            const action = isBanned ? 'ban' : 'unban';
            await this.db.addModerationAction({
                messageId: null,
                userId,
                actionType: action,
                reason: isBanned ? 'Заблокирован администратором' : 'Разблокирован администратором',
                moderatorId
            });

            if (isBanned) {
                await this.db.banUser(userId);
            } else {
                await this.db.unbanUser(userId);
            }

            return { success: true };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Получение статистики пользователей (для админов)
    async getUserStats() {
        try {
            const totalUsers = await new Promise((resolve, reject) => {
                this.db.db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
                    if (err) reject(err);
                    else resolve(row.count);
                });
            });

            const bannedUsers = await new Promise((resolve, reject) => {
                this.db.db.get('SELECT COUNT(*) as count FROM users WHERE is_banned = 1', (err, row) => {
                    if (err) reject(err);
                    else resolve(row.count);
                });
            });

            const activeUsers = await new Promise((resolve, reject) => {
                this.db.db.get(
                    'SELECT COUNT(*) as count FROM users WHERE last_seen > datetime("now", "-7 days")',
                    (err, row) => {
                        if (err) reject(err);
                        else resolve(row.count);
                    }
                );
            });

            return {
                success: true,
                stats: {
                    totalUsers,
                    bannedUsers,
                    activeUsers,
                    activePercentage: ((activeUsers / totalUsers) * 100).toFixed(1)
                }
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Очистка истекших сессий
    async cleanupExpiredSessions() {
        this.db.cleanupExpiredSessions();
    }
}

// Middleware для аутентификации
const authenticateToken = (authService) => {
    return async (req, res, next) => {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Токен доступа обязателен' });
        }

        const validation = await authService.validateToken(token);
        if (!validation.valid) {
            return res.status(403).json({ error: validation.error });
        }

        req.user = validation.user;
        next();
    };
};

// Middleware для проверки админских прав
const requireAdmin = (req, res, next) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Требуются права администратора' });
    }
    next();
};

// Middleware для проверки незабаненного пользователя
const requireNotBanned = (req, res, next) => {
    if (req.user.isBanned) {
        return res.status(403).json({ error: 'Пользователь заблокирован' });
    }
    next();
};

module.exports = {
    AuthService,
    authenticateToken,
    requireAdmin,
    requireNotBanned
};