const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const session = require('express-session');
const app = express();

app.use(cors({
    origin: 'http://127.0.0.1:5500', // Укажите точный адрес вашего фронтенда
    credentials: true, // Разрешить отправку куки
}));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

const upload = multer();

app.use(session({
    secret: 'your_secret_key', 
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } 
}));

// Подключение к базе данных
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'auth_db'
});

db.connect((err) => {
    if (err) {
        console.error('Ошибка подключения к базе данных: ' + err.stack);
        return;
    }
    console.log('Подключено к базе данных.');
});

// Регистрация
app.post('/register', upload.none(), async (req, res) => {
    const { email, pass, pass_repeat } = req.body;

    if (!email || !pass || !pass_repeat) {
        return res.json({ status: 'error', message: 'Все поля обязательны для заполнения' });
    }

    if (pass !== pass_repeat) {
        return res.json({ status: 'error', message: 'Пароли не совпадают' });
    }

    try {
        const hashedPassword = await bcrypt.hash(pass, 10);

        const query = 'INSERT INTO users (email, password) VALUES (?, ?)';
        db.query(query, [email, hashedPassword], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.json({ status: 'error', message: 'Email уже используется' });
                }
                console.error('Ошибка при добавлении пользователя:', err);
                return res.json({ status: 'error', message: 'Ошибка при регистрации' });
            }
            res.json({ status: 'success', message: 'Пользователь успешно зарегистрирован' });
        });
    } catch (error) {
        console.error('Ошибка хеширования пароля:', error);
        return res.json({ status: 'error', message: 'Ошибка при обработке данных' });
    }
});

// Вход
app.post('/login', upload.none(), (req, res) => {
    const { email, pass } = req.body;

    if (!email || !pass) {
        return res.json({ status: 'error', message: 'Все поля обязательны для заполнения' });
    }

    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], async (err, results) => {
        if (err) {
            return res.json({ status: 'error', message: 'Ошибка при поиске пользователя' });
        }

        if (results.length === 0) {
            return res.json({ status: 'error', message: 'Пользователь не найден' });
        }

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(pass, user.password);

        if (isPasswordValid) {
            req.session.user = { id: user.id, email: user.email };
            return res.json({ status: 'success', message: 'Успешный вход' });
        } else {
            return res.json({ status: 'error', message: 'Неверный пароль' });
        }
    });
});

// Профиль
app.get('/get-profile', (req, res) => {
    const email = req.query.email;

    if (!email) {
        return res.status(400).json({ status: 'error', message: 'Email обязателен' });
    }

    const query = 'SELECT email, registration_date FROM users WHERE email = ?';
    db.query(query, [email], (err, results) => {
        if (err) {
            console.error('Ошибка получения профиля:', err);
            return res.status(500).json({ status: 'error', message: 'Ошибка сервера' });
        }

        if (results.length > 0) {
            const user = results[0];
            res.json({ status: 'success', email: user.email, registration_date: user.registration_date });
        } else {
            res.status(404).json({ status: 'error', message: 'Пользователь не найден' });
        }
    });
});

app.listen(3000, () => {
    console.log('Сервер запущен на http://localhost:3000');
});