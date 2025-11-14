# Twitch Giveaway Server

Серверная часть для приложения Twitch Giveaway.

## Установка

1. Установите зависимости:
```bash
npm install
```

2. Запустите сервер:
```bash
npm start
```

Для разработки с автоперезагрузкой:
```bash
npm run dev
```

## API Endpoints

### Получение реального IP
```
GET /api/ip
```
Возвращает реальный IP адрес клиента и User Agent.

### Регистрация посетителя
```
POST /api/visitors
Body: {
  "username": "string",
  "userId": "string",
  "channel": "string",
  "action": "visit" | "message" | "giveaway"
}
```

### Получение посетителей
```
GET /api/visitors?channel=string&date=YYYY-MM-DD&limit=1000
```

### Статистика по IP
```
GET /api/visitors/ip/:ip
```

### Сохранение/Загрузка данных пользователей
```
POST /api/users
GET /api/users
```

### Сохранение/Загрузка розыгрышей
```
POST /api/giveaways
GET /api/giveaways?channel=string
```

### История чата
```
POST /api/chat-history
GET /api/chat-history/:username
```

### Статистика
```
GET /api/stats
```

## Структура данных

Все данные сохраняются в папке `data/`:
- `visitors.json` - все посетители
- `users.json` - пользователи системы
- `streamers.json` - стримеры
- `giveaways.json` - розыгрыши
- `winners.json` - победители
- `chat_history.json` - история чата
- `auth_log.json` - лог авторизаций

## Порт

По умолчанию сервер запускается на порту 3000.
Измените переменную окружения PORT для другого порта:
```bash
PORT=8080 npm start
```

