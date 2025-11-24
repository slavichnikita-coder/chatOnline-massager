const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const Database = require('./database');
const { AuthService } = require('./auth');

class ChatServer {
    constructor(httpServer) {
        this.io = new Server(httpServer, {
            cors: {
                origin: "*",
                methods: ["GET", "POST"]
            }
        });
        
        this.db = new Database();
        this.authService = new AuthService();
        
        // Хранилище подключенных пользователей
        this.connectedUsers = new Map(); // socketId -> userInfo
        this.userSockets = new Map(); // userId -> Set of socketIds
        this.userTyping = new Map(); // userId -> roomId
        
        this.setupSocketHandlers();
        
        // Очистка истекших сессий каждые 5 минут
        setInterval(() => {
            this.authService.cleanupExpiredSessions();
        }, 5 * 60 * 1000);
    }

    setupSocketHandlers() {
        this.io.use(async (socket, next) => {
            try {
                const token = socket.handshake.auth.token;
                if (!token) {
                    return next(new Error('Токен аутентификации обязателен'));
                }

                const validation = await this.authService.validateToken(token);
                if (!validation.valid) {
                    return next(new Error(validation.error));
                }

                socket.user = validation.user;
                socket.userId = validation.user.id;
                
                next();
            } catch (error) {
                next(new Error('Ошибка аутентификации'));
            }
        });

        this.io.on('connection', (socket) => {
            console.log(`Пользователь ${socket.user.displayName} подключился`);
            
            // Сохранение информации о подключенном пользователе
            this.connectedUsers.set(socket.id, {
                id: socket.userId,
                username: socket.user.username,
                displayName: socket.user.displayName,
                avatar: socket.user.avatar,
                isAdmin: socket.user.isAdmin,
                socketId: socket.id
            });

            // Добавление сокета к пользователю
            if (!this.userSockets.has(socket.userId)) {
                this.userSockets.set(socket.userId, new Set());
            }
            this.userSockets.get(socket.userId).add(socket.id);

            // Уведомление о подключении
            this.broadcastUserStatus(socket.userId, 'online');

            // Обработка присоединения к комнате
            socket.on('join-room', async (roomId) => {
                try {
                    socket.join(`room-${roomId}`);
                    console.log(`Пользователь ${socket.user.displayName} присоединился к комнате ${roomId}`);
                    
                    // Обновление времени последнего визита
                    this.db.updateUserLastSeen(socket.userId);
                    
                    // Отправка информации о пользователях в комнате
                    const roomUsers = this.getRoomUsers(`room-${roomId}`);
                    socket.emit('room-users', roomUsers);
                    
                } catch (error) {
                    socket.emit('error', 'Ошибка при присоединении к комнате');
                }
            });

            // Обработка выхода из комнаты
            socket.on('leave-room', (roomId) => {
                socket.leave(`room-${roomId}`);
                console.log(`Пользователь ${socket.user.displayName} вышел из комнаты ${roomId}`);
                
                // Уведомление о выходе
                this.broadcastUserStatus(socket.userId, 'offline', roomId);
            });

            // Обработка отправки сообщения
            socket.on('send-message', async (data) => {
                try {
                    const { roomId, content, messageType = 'text', fileUrl, fileName, fileSize, parentMessageId } = data;
                    
                    if (!roomId || (!content && !fileUrl)) {
                        socket.emit('error', 'Необходимы данные для отправки сообщения');
                        return;
                    }

                    // Проверка, что пользователь присоединен к комнате
                    const room = socket.rooms.has(`room-${roomId}`);
                    if (!room) {
                        socket.emit('error', 'Необходимо присоединиться к комнате');
                        return;
                    }

                    // Создание сообщения в базе данных
                    const messageData = {
                        roomId,
                        userId: socket.userId,
                        content: content?.trim() || '',
                        messageType,
                        fileUrl,
                        fileName,
                        fileSize,
                        parentMessageId
                    };

                    const message = await this.db.createMessage(messageData);

                    // Получение полной информации о сообщении
                    const fullMessage = await this.getMessageWithUserInfo(message.id);

                    // Отправка сообщения всем пользователям в комнате
                    this.io.to(`room-${roomId}`).emit('new-message', fullMessage);

                    console.log(`Сообщение отправлено в комнату ${roomId}: ${content || '[Файл]'}`);

                } catch (error) {
                    console.error('Ошибка отправки сообщения:', error);
                    socket.emit('error', 'Ошибка отправки сообщения');
                }
            });

            // Обработка печати
            socket.on('typing-start', (roomId) => {
                this.userTyping.set(socket.userId, roomId);
                socket.to(`room-${roomId}`).emit('user-typing', {
                    userId: socket.userId,
                    displayName: socket.user.displayName,
                    typing: true
                });
            });

            socket.on('typing-stop', (roomId) => {
                this.userTyping.delete(socket.userId);
                socket.to(`room-${roomId}`).emit('user-typing', {
                    userId: socket.userId,
                    displayName: socket.user.displayName,
                    typing: false
                });
            });

            // Обработка реакций на сообщения
            socket.on('add-reaction', async (data) => {
                try {
                    const { messageId, emoji } = data;
                    
                    await this.db.addReaction(messageId, socket.userId, emoji);
                    
                    // Получение обновленных реакций
                    const reactions = await this.db.getMessageReactions(messageId);
                    
                    // Отправка обновленных реакций всем в комнате
                    this.io.emit('message-reactions-updated', {
                        messageId,
                        reactions
                    });
                    
                } catch (error) {
                    socket.emit('error', 'Ошибка добавления реакции');
                }
            });

            socket.on('remove-reaction', async (data) => {
                try {
                    const { messageId, emoji } = data;
                    
                    await this.db.removeReaction(messageId, socket.userId, emoji);
                    
                    // Получение обновленных реакций
                    const reactions = await this.db.getMessageReactions(messageId);
                    
                    // Отправка обновленных реакций всем в комнате
                    this.io.emit('message-reactions-updated', {
                        messageId,
                        reactions
                    });
                    
                } catch (error) {
                    socket.emit('error', 'Ошибка удаления реакции');
                }
            });

            // Обработка удаления сообщений (для админов)
            socket.on('delete-message', async (data) => {
                try {
                    const { messageId } = data;
                    
                    if (!socket.user.isAdmin) {
                        socket.emit('error', 'Недостаточно прав для удаления сообщений');
                        return;
                    }

                    await this.db.deleteMessage(messageId);
                    
                    // Уведомление всех пользователей об удалении
                    this.io.emit('message-deleted', { messageId });
                    
                    // Запись в лог модерации
                    await this.db.addModerationAction({
                        messageId,
                        userId: null,
                        actionType: 'delete',
                        reason: 'Удалено администратором',
                        moderatorId: socket.userId
                    });
                    
                } catch (error) {
                    socket.emit('error', 'Ошибка удаления сообщения');
                }
            });

            // Запрос истории сообщений
            socket.on('get-messages', async (data) => {
                try {
                    const { roomId, limit = 50, offset = 0 } = data;
                    
                    const messages = await this.db.getMessages(roomId, limit, offset);
                    
                    // Добавление информации о реакциях к сообщениям
                    const messagesWithReactions = await Promise.all(
                        messages.map(async (message) => {
                            const reactions = await this.db.getMessageReactions(message.id);
                            return { ...message, reactions };
                        })
                    );
                    
                    socket.emit('messages-history', {
                        roomId,
                        messages: messagesWithReactions
                    });
                    
                } catch (error) {
                    socket.emit('error', 'Ошибка получения истории сообщений');
                }
            });

            // Поиск сообщений
            socket.on('search-messages', async (data) => {
                try {
                    const { query, roomId } = data;
                    
                    if (!query || query.trim().length < 2) {
                        socket.emit('search-results', { results: [] });
                        return;
                    }
                    
                    const results = await this.db.searchMessages(query.trim(), roomId);
                    
                    socket.emit('search-results', {
                        query: query.trim(),
                        results
                    });
                    
                } catch (error) {
                    socket.emit('error', 'Ошибка поиска сообщений');
                }
            });

            // Обработка отключения
            socket.on('disconnect', () => {
                console.log(`Пользователь ${socket.user.displayName} отключился`);
                
                // Удаление из хранилищ
                this.connectedUsers.delete(socket.id);
                
                const userSocketSet = this.userSockets.get(socket.userId);
                if (userSocketSet) {
                    userSocketSet.delete(socket.id);
                    if (userSocketSet.size === 0) {
                        this.userSockets.delete(socket.userId);
                        this.userTyping.delete(socket.userId);
                        
                        // Уведомление о том, что пользователь офлайн
                        this.broadcastUserStatus(socket.userId, 'offline');
                    }
                }
            });
        });
    }

    // Получение информации о пользователях в комнате
    getRoomUsers(roomKey) {
        const users = [];
        const socketsInRoom = this.io.sockets.adapter.rooms.get(roomKey);
        
        if (socketsInRoom) {
            socketsInRoom.forEach(socketId => {
                const user = this.connectedUsers.get(socketId);
                if (user) {
                    users.push({
                        id: user.id,
                        username: user.username,
                        displayName: user.displayName,
                        avatar: user.avatar,
                        isOnline: true,
                        isTyping: this.userTyping.get(user.id) !== undefined
                    });
                }
            });
        }
        
        return users;
    }

    // Отправка уведомления о статусе пользователя
    broadcastUserStatus(userId, status, roomId = null) {
        const userInfo = this.connectedUsers.get([...this.connectedUsers.entries()].find(([, info]) => info.id === userId)?.[0]);
        
        if (userInfo) {
            const statusData = {
                userId,
                displayName: userInfo.displayName,
                status, // 'online' или 'offline'
                timestamp: new Date().toISOString()
            };

            if (roomId) {
                this.io.to(`room-${roomId}`).emit('user-status-changed', statusData);
            } else {
                this.io.emit('user-status-changed', statusData);
            }
        }
    }

    // Получение сообщения с информацией о пользователе
    async getMessageWithUserInfo(messageId) {
        return new Promise((resolve, reject) => {
            this.db.db.get(
                `SELECT m.*, u.display_name, u.username, u.avatar 
                 FROM messages m 
                 JOIN users u ON m.user_id = u.id 
                 WHERE m.id = ?`,
                [messageId],
                async (err, row) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    
                    if (row) {
                        const reactions = await this.db.getMessageReactions(messageId);
                        resolve({ ...row, reactions });
                    } else {
                        resolve(null);
                    }
                }
            );
        });
    }

    // Отправка уведомления администраторам
    notifyAdmins(event, data) {
        this.userSockets.forEach((socketIds, userId) => {
            // Найти информацию о пользователе
            const userInfo = [...this.connectedUsers.values()].find(u => u.id === userId);
            if (userInfo && userInfo.isAdmin) {
                socketIds.forEach(socketId => {
                    this.io.to(socketId).emit(event, data);
                });
            }
        });
    }

    // Отправка системных уведомлений
    sendSystemNotification(roomId, message, type = 'info') {
        const notification = {
            id: Date.now(),
            type,
            message,
            timestamp: new Date().toISOString(),
            system: true
        };
        
        this.io.to(`room-${roomId}`).emit('system-notification', notification);
    }

    // Закрытие сервера
    close() {
        this.io.close();
        this.db.close();
    }
}

module.exports = ChatServer;