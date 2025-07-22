const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'your_super_secret_key_123';

const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'likhith@0902',
    database: 'expense_tracker_db'
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// =================== MIDDLEWARE ===================
const authenticate = (req, res, next) => {
    try {
        const token = req.header('Authorization');
        if (!token) return res.status(401).json({ success: false, message: 'Access denied, no token provided' });
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch {
        return res.status(401).json({ success: false, message: 'Invalid token' });
    }
};

// =================== AUTH ROUTES ===================
app.post('/user/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) return res.status(400).json({ message: 'All fields required.' });

        const [existing] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (existing.length > 0) return res.status(409).json({ message: 'User already exists.' });

        const hashed = await bcrypt.hash(password, 10);
        await db.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashed]);
        res.status(201).json({ message: 'Signup successful!' });
    } catch (err) {
        res.status(500).json({ message: 'Signup failed', error: err.message });
    }
});

app.post('/user/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) return res.status(404).json({ message: 'User not found' });

        const user = users[0];
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) return res.status(401).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ id: user.id, name: user.name, isPremiumUser: user.isPremiumUser }, JWT_SECRET);
        res.status(200).json({ success: true, token });
    } catch (err) {
        res.status(500).json({ message: 'Login error', error: err.message });
    }
});

// =================== EXPENSE ROUTES ===================
app.post('/expense/addexpense', authenticate, async (req, res) => {
    try {
        const { expenseamount, description, category } = req.body;
        await db.execute('INSERT INTO expenses (expenseamount, description, category, userId) VALUES (?, ?, ?, ?)', [
            expenseamount, description, category, req.user.id
        ]);
        res.status(201).json({ success: true, message: 'Expense added.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to add expense', error: err.message });
    }
});

app.get('/expense/getexpenses', authenticate, async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT * FROM expenses WHERE userId = ?', [req.user.id]);
        res.status(200).json({ success: true, expenses: rows });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to get expenses', error: err.message });
    }
});

app.delete('/expense/delete-expense/:id', authenticate, async (req, res) => {
    try {
        const [result] = await db.execute('DELETE FROM expenses WHERE id = ? AND userId = ?', [req.params.id, req.user.id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Not found' });
        res.json({ success: true, message: 'Deleted' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to delete expense', error: err.message });
    }
});

// =================== CASHFREE PAYMENT ===================
app.post('/purchase/premium-membership', authenticate, async (req, res) => {
    try {
        const userId = req.user.id;
        const orderId = `PREMIUM_${Date.now()}`;

        const headers = {
            accept: 'application/json',
            'content-type': 'application/json',
            'x-api-version': '2023-08-01',
            'x-client-id': 'TEST1072713536be86671a36cc0bff4753172701',
            'x-client-secret': 'cfsk_ma_test_9baf01178d78edea08016f025d75c4f0_652083bf'
        };

        const body = {
            order_id: orderId,
            order_amount: 2000.00,
            order_currency: "INR",
            customer_details: {
                customer_id: `user_${userId}`,
                customer_email: "test@example.com",
                customer_phone: "9999999999"
            },
            order_meta: {
                return_url: `http://localhost:3000/payment-status?order_id=${orderId}`
            }
        };

        const response = await axios.post("https://sandbox.cashfree.com/pg/orders", body, { headers });
        await db.execute('INSERT INTO orders (orderId, status, userId) VALUES (?, ?, ?)', [orderId, 'PENDING', userId]);

        res.status(200).json({ payment_session_id: response.data.payment_session_id });
    } catch (err) {
        console.error("Cashfree Error:", err.response?.data || err.message);
        res.status(500).json({ success: false, message: 'Payment failed' });
    }
});

// =================== PAYMENT CALLBACK ===================
app.get('/payment-status', async (req, res) => {
    const { order_id } = req.query;
    try {
        const [rows] = await db.execute("SELECT userId FROM orders WHERE orderId = ?", [order_id]);
        if (rows.length === 0) return res.status(404).send('Order not found');

        const userId = rows[0].userId;

        await db.execute("UPDATE orders SET status = 'SUCCESSFUL' WHERE orderId = ?", [order_id]);
        await db.execute("UPDATE users SET isPremiumUser = true WHERE id = ?", [userId]);

        res.sendFile(path.join(__dirname, 'public', 'payment-success.html'));
    } catch (error) {
        console.error("Payment status error:", error.message);
        await db.execute("UPDATE orders SET status = 'FAILED' WHERE orderId = ?", [order_id]);
        res.sendFile(path.join(__dirname, 'public', 'payment-failure.html'));
    }
});

// =================== LEADERBOARD ROUTE ===================
app.get('/premium/showleaderboard', authenticate, async (req, res) => {
    try {
        const [userRow] = await db.execute("SELECT isPremiumUser FROM users WHERE id = ?", [req.user.id]);
        if (!userRow[0].isPremiumUser) {
            return res.status(403).json({ message: "Access denied. Not a premium user." });
        }

        const [rows] = await db.execute(`
            SELECT users.name, SUM(expenses.expenseamount) AS total_expense
            FROM expenses
            JOIN users ON expenses.userId = users.id
            GROUP BY users.id
            ORDER BY total_expense DESC
        `);

        res.status(200).json(rows);
    } catch (err) {
        console.error("Leaderboard error:", err.message);
        res.status(500).json({ message: "Failed to fetch leaderboard" });
    }
});

// =================== START SERVER ===================
app.listen(PORT, () => console.log(`✅ Server is running on http://localhost:${PORT}`));
