import express from 'express';
import cors from 'cors';
import mysql from 'mysql2'; // Use mysql2
import bcrypt from 'bcrypt';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';
import multer from 'multer';
import path, { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path'
import dotenv from 'dotenv';
import fs from 'fs';
import jwt from 'jsonwebtoken';
import https from 'https';
import cron from 'node-cron';

dotenv.config();
const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const router = express.Router();

app.use('/uploads', express.static(join(__dirname, 'uploads')));
app.use(bodyParser.json());
app.use(cors({
origin: 'http://localhost:5173',
methods: ['GET','HEAD','PUT','PATCH','POST','DELETE'], 

credentials: true,

}));


app.use(cookieParser());
app.use(express.json());
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 699900000 }   

}));
const PORT=8082;
const con = mysql.createConnection({
    host: '127.0.0.1',
    user: 'root',
    password: 'Pakistan@2k17',
    database: 'gold_mine', 
});

con.connect(function(err){
    if (err) {
        console.error('Error in connection:', err); 
    } else {
        console.log('Connected');
    }
}
);


const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
      cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
  });
  const upload = multer({ storage: storage });
  app.get('/', (req, res) => {
    if(req.session.email){
        return res.json({valid:true,Email:req.session.email});
    }
    else{
        return res.json({valid:false,Status:"!valid"});
    }
})

cron.schedule('0 0 * * *', () => {
    const deleteQuery = 'DELETE FROM user_product_clicks WHERE last_clicked < CURDATE()';
    con.query(deleteQuery, (err, result) => {
        if (err) {
            console.error('Error deleting old records:', err);
        } else {
            console.log('Deleted old records:', result.affectedRows);
        }
    });
});

app.post('/login', (req, res) => {
    const sql = "SELECT * FROM users WHERE email = ? AND password = ?";
    con.query(sql, [req.body.email, req.body.password], (err, result) => {
        if (err) return res.json({Status: "Error", Error: err});

        if (result.length > 0) {
            req.session.userId = result[0].id; 
            req.session.email = result[0].email;
            return res.json({
                Status: "Success",
                Email: req.session.email,
                PaymentOk: result[0].payment_ok,
                id: result[0].id,
                approved: result[0].approved
            });
        } else {
            return res.json({Status: "Error", Error: "Invalid Email/Password"});
        }
    });
});

app.post('/register', (req, res) => {
    try {
        const { ref } = req.query;
        const user = { ...req.body };
        delete user.confirmPassword;

        const checkEmailSql = "SELECT * FROM users WHERE email = ?";
        con.query(checkEmailSql, [user.email], (err, existingUsers) => {
            if (err) {
                return res.json({ status: 'error', error: 'An error occurred while checking the email' });
            }

            if (existingUsers.length > 0) {
                return res.json({ status: 'error', error: 'Email already registered' });
            }

            const registerUser = () => {
                // Inserting referrer ID into the user object
                user.refer_by = ref;

                const sql = "INSERT INTO users SET ?";
                con.query(sql, user, (err, result) => {
                    if (err) {
                        return res.json({ status: 'error', error: 'Failed to register user' });
                    }

                    // Set session cookie upon successful registration
                    req.session.userId = result.insertId;

                    return res.json({ status: 'success', message: 'User registered successfully', userId: result.insertId });
                });
            };

            if (ref) {
                const checkReferralSql = "SELECT * FROM users WHERE id = ?";
                con.query(checkReferralSql, [ref], (err, referralUsers) => {
                    if (err) {
                        return res.json({ status: 'error', error: 'Failed to check referral ID' });
                    }

                    if (referralUsers.length === 0) {
                        return res.json({ status: 'error', error: 'Invalid referral ID' });
                    }

                    registerUser();
                });
            } else {
                registerUser();
            }
        });
    } catch (error) {
        return res.json({ status: 'error', error: 'An unexpected error occurred' });
    }
});

// app.post('/payment', (req, res) => {
//     const { trx_id, sender_name, sender_number, id, type } = req.body;
//     const payment_ok = 1;
//     const rejected = 0;

//     // Query to check if the user already has a trx_id
//     const checkUserTrxQuery = 'SELECT trx_id FROM users WHERE id = ?';
//     con.query(checkUserTrxQuery, [id], (checkUserErr, checkUserResults) => {
//         if (checkUserErr) {
//             return res.status(500).json({ status: 'error', error: 'Database error' });
//         }

//         // If user already has a trx_id, don't update it
//         let updateSql;
//         let queryParams;

//         if (checkUserResults.length > 0 && checkUserResults[0].trx_id) {
//             // User already has a trx_id, don't update it
//             updateSql = 'UPDATE users SET sender_name = ?, sender_number = ?, type = ?, payment_ok = ?, rejected = ? WHERE id = ?';
//             queryParams = [sender_name, sender_number, type, payment_ok, rejected, id];
//         } else {
//             // User does not have a trx_id, update it
//             updateSql = 'UPDATE users SET trx_id = ?, sender_name = ?, sender_number = ?, type = ?, payment_ok = ?, rejected = ? WHERE id = ?';
//             queryParams = [trx_id, sender_name, sender_number, type, payment_ok, rejected, id];
//         }

//         con.query(updateSql, queryParams, (updateErr, updateResult) => {
//             if (updateErr) {
//                 return res.status(500).json({ status: 'error', error: 'Failed to update payment data' });
//             }

//             res.json({ status: 'success' });
//         });
//     });
// });



app.post('/payment', (req, res) => {
    console.log('Received /payment request with body:', req.body);

    const { trx_id, sender_name, sender_number, id, type } = req.body;
    const payment_ok = 1;
    const rejected = 0;

    console.log('Extracted request parameters:', { trx_id, sender_name, sender_number, id, type });

    // Query to check if the user already has a trx_id and their payment status
    const checkUserQuery = 'SELECT trx_id, payment_ok, rejected FROM users WHERE id = ?';
    con.query(checkUserQuery, [id], (checkUserErr, checkUserResults) => {
        if (checkUserErr) {
            console.error('Database error during user check:', checkUserErr);
            return res.status(500).json({ status: 'error', error: 'Database error' });
        }

        console.log('User check results:', checkUserResults);

        // If no user found, return an error
        if (checkUserResults.length === 0) {
            console.log('No user found with id:', id);
            return res.status(404).json({ status: 'error', error: 'User not found' });
        }

        const user = checkUserResults[0];
        console.log('User data retrieved:', user);

        // Check if the user's payment_ok or rejected status allows for an update
        if (user.payment_ok === 1 && user.rejected === 0) {
            console.log('User is not allowed to update payment data:', { payment_ok: user.payment_ok, rejected: user.rejected });
            return res.status(403).json({ status: 'error', error: 'User is not allowed to update payment data' });
        }

        // Determine the appropriate update query based on trx_id presence
        let updateSql;
        let queryParams;

        if (user.trx_id) {
            console.log('User already has a trx_id, preparing update query without trx_id');
            // User already has a trx_id, don't update it
            updateSql = 'UPDATE users SET trx_id = ?, sender_name = ?, sender_number = ?, type = ?, payment_ok = ?, rejected = ? WHERE id = ?';
            queryParams = [trx_id, sender_name, sender_number, type, payment_ok, rejected, id];
        } else {
            console.log('User does not have a trx_id, preparing update query with trx_id');
            // User does not have a trx_id, update it
            updateSql = 'UPDATE users SET trx_id = ?, sender_name = ?, sender_number = ?, type = ?, payment_ok = ?, rejected = ? WHERE id = ?';
            queryParams = [trx_id, sender_name, sender_number, type, payment_ok, rejected, id];
        }

        console.log('Executing update query with parameters:', queryParams);
        con.query(updateSql, queryParams, (updateErr, updateResult) => {
            if (updateErr) {
                console.error('Error during update:', updateErr);
                return res.status(500).json({ status: 'error', error: 'Failed to update payment data' });
            }

            console.log('Update successful:', updateResult);
            res.json({ status: 'success' });
        });
    });
});



app.post('/payment-crypto', (req, res) => {
    const { trx_id,  id } = req.body;
    const payment_ok = 1;
    const rejected = 0;
    const type=1;

    const checkQuery = 'SELECT COUNT(*) AS count FROM users WHERE trx_id = ?';
    con.query(checkQuery, [trx_id], (checkErr, checkResults) => {
        if (checkErr) {
            return res.status(500).json({ status: 'error', error: 'Database error' });
        }

if (checkResults[0].count > 0) {
    return res.status(400).json({ status: 'error', error: 'Transaction ID already in use' });
  }
  

        const sql = 'UPDATE users SET trx_id = ?,  type = ?, payment_ok = ?, rejected = ? WHERE id = ?';

        con.query(sql, [trx_id, type, payment_ok, rejected, id], (err, result) => {
            if (err) {
                return res.status(500).json({ status: 'error', error: 'Failed to update payment data' });
            }

            res.json({ status: 'success' });
        });
    });
});

  
app.get('/getUserData', (req, res) => {
    if(!req.session.email) {
        return res.json({Status: 'Error', Error: 'User not logged in'});
    }

    const sql = "SELECT * FROM users WHERE email = ?";
    con.query(sql, [req.session.email], (err, result) => {
        if (err) {
            return res.json({Status: 'Error', Error: 'Failed to fetch user data'});
        }

        if (result.length > 0) {
            return res.json({Status: 'Success', Data: result[0]});
        } else {
            return res.json({Status: 'Error', Error: 'User not found'});
        }
    });
});


app.get('/getAllAdmins',verifyToken, (req, res) => {
    const sql = "SELECT * FROM admins";
    con.query(sql, (err, result) => {
        if (err) {
            return res.json({Status: 'Error', Error: 'Failed to fetch admins data'});
        }

        if (result.length > 0) {
            return res.json({Status: 'Success', Data: result});
        } else {
            return res.json({Status: 'Error', Error: 'No admins found'});
        }
    });
});


app.post('/changePassword', (req, res) => {
    const { username, oldPassword, newPassword } = req.body;
  
    const sql = "SELECT password FROM admins WHERE username = ?";
    
    con.query(sql, [username], (err, result) => {
      if (err || result.length === 0) {
        return res.json({ message: 'Username not found' });
      }
  
      const storedPassword = result[0].password;
  
      if (storedPassword !== oldPassword) { 
        return res.json({ message: 'Old password is incorrect' });
      }
  
      const updateSql = "UPDATE admins SET password = ? WHERE username = ?";
      
      con.query(updateSql, [newPassword, username], (updateErr, updateResult) => {
        if (updateErr) {
          return res.json({ message: 'Failed to update password' });
        }
  
        return res.json({ message: 'Password updated successfully' });
      });
    });
  });
  

app.get('/balance', async (req, res) => {
    const userId = req.session.userId; // Get user ID from session

    if (!userId) {
        return res.status(400).json({status: 'error', error: 'User ID is missing from session'});
    }

    const sqlQuery = `
        SELECT balance FROM users 
        WHERE id = ?;
    `;

    con.query(sqlQuery, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({status: 'error', error: 'Failed to fetch user balance'});
        }

        if (results.length === 0) {
            return res.status(404).json({status: 'error', error: 'User not found'});
        }

        const balance = results[0].balance;
        return res.json({status: 'success', balance: balance});
    });
});


  app.post('/sellCoins/:userId', (req, res) => {
    const userId = req.params.userId;
    const { amount, coin, table, value } = req.body;

    if (!amount) {
        return res.status(400).json({ status: 'error', error: 'Amount is required' });
    }

    const coinColumnName = `${coin.toLowerCase()}`;

    // Fetch the existing value of the coin column
    const checkCoinValueQuery = `SELECT ${coinColumnName} FROM users WHERE id = ?`;
    con.query(checkCoinValueQuery, [userId], (err, result) => {
        if (err) {
            console.error('Error fetching coin value:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch coin value' });
        }

        const coinValue = result[0][coinColumnName];
        if (coinValue === 0) {
            return res.status(200).json({ status: 'success', message: 'No coins to sell' });
        }

        const deductQuery = `UPDATE users SET balance = balance + ?, ${coinColumnName} = 0 WHERE id = ?`;

        con.beginTransaction(function(err) {
            if (err) {
                console.error('Transaction error:', err);
                return res.status(500).json({ status: 'error', error: 'Failed to start transaction' });
            }

            con.query(deductQuery, [amount, userId], (err, result) => {
                if (err) {
                    console.error('Error selling coins:', err);
                    return con.rollback(function() {
                        return res.status(500).json({ status: 'error', error: 'Failed to sell coins' });
                    });
                }

                const sellHistoryQuery = `INSERT INTO ${table} (user_id, amount, value) VALUES (?, ?, ?)`;
                con.query(sellHistoryQuery, [userId, amount, value], (err, result) => {
                    if (err) {
                        console.error('Error adding to sell history:', err);
                        return con.rollback(function() {
                            return res.status(500).json({ status: 'error', error: 'Failed to add to sell history' });
                        });
                    }

                    con.commit(function(err) {
                        if (err) {
                            console.error('Commit error:', err);
                            return con.rollback(function() {
                                return res.status(500).json({ status: 'error', error: 'Failed to commit transaction' });
                            });
                        }

                        res.json({ status: 'success', message: 'Coins sold successfully' });
                    });
                });
            });
        });
    });
});


app.get('/products', (req, res) => {
    const getProductsSql = 'SELECT * FROM products';

    con.query(getProductsSql, (err, products) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch products' });
        }

        res.json({ status: 'success', products });
    });
});
app.post('/updateBalance', (req, res) => {
    const { productId, reward } = req.body;

    if (!req.session.userId) { 
        return res.json({ Status: 'Error', Error: 'User not logged in' });
    }

    const checkLastClickedSql = 'SELECT last_clicked FROM user_product_clicks WHERE user_id = ? AND product_id = ?';
    con.query(checkLastClickedSql, [req.session.userId, productId], (err, result) => {
        if (err) {
            console.error('Error checking last clicked time:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to check the last clicked time' });
        }

        const currentTime = new Date();

        if (result.length > 0) {
            const lastClicked = new Date(result[0].last_clicked);
            const timeDifference = currentTime - lastClicked;

            if (timeDifference < 12 * 60 * 60 * 1000) { 
                return res.json({ status: 'error', error: 'You have completed your task' });
            }
        }

        const updateBalanceSql = `UPDATE users SET winstuk_coin = winstuk_coin + ?, backend_wallet = backend_wallet - ? WHERE id = ?`;
        con.query(updateBalanceSql, [reward, reward, req.session.userId], (err, updateResult) => {
            if (err) {
                console.error('Error updating balance and backend wallet:', err);
                return res.status(500).json({ status: 'error', error: 'Failed to update the balance and backend wallet' });
            }

            const updateLastClickedSql = `
                INSERT INTO user_product_clicks (user_id, product_id, last_clicked) 
                VALUES (?, ?, ?) 
                ON DUPLICATE KEY UPDATE last_clicked = VALUES(last_clicked)
            `;
            con.query(updateLastClickedSql, [req.session.userId, productId, currentTime], (err, clickResult) => {
                if (err) {
                    console.error('Error updating last clicked time:', err);
                    return res.status(500).json({ status: 'error', error: 'Failed to update the last clicked time' });
                }

                // Insert userId and reward into winstuck table
                const insertWinstuckSql = 'INSERT INTO winstuk_coin (user_id, reward) VALUES (?, ?)';
                con.query(insertWinstuckSql, [req.session.userId, reward], (err, insertResult) => {
                    if (err) {
                        console.error('Error inserting userId and reward into winstuck table:', err);
                        return res.status(500).json({ status: 'error', error: 'Failed to insert userId and reward into winstuck table' });
                    }

                    return res.json({ status: 'success', message: 'Balance and backend wallet updated successfully' });
                });
            });
        });
    });
});













app.get('/getUserTaskStatus/:userId', (req, res) => {
    const userId = req.params.userId;
    const sql = 'SELECT * FROM user_product_clicks WHERE user_id = ?';
    
    con.query(sql, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch user task status' });
        }
        
        const taskStatus = results.reduce((acc, curr) => {
            acc[curr.product_id] = curr.last_clicked;
            return acc;
        }, {});

        res.json({ status: 'success', taskStatus });
    });
});

app.post('/logout', (req, res) => {
    if (req.session) {
        req.session.destroy(err => {
            if (err) {
                return res.json({ Status: 'Error', Error: 'Failed to logout' });
            }

            return res.json({ Status: 'Success', Message: 'Logged out successfully' });
        });
    } else {
        return res.json({ Status: 'Error', Error: 'No session to logout' });
    }
});

app.get('/referrals', async (req, res) => {
    const referrerId = req.query.referrerId;

    if (!referrerId) {
        return res.status(400).json({status: 'error', error: 'Referrer ID is required'});
    }

    const sqlReferrals = `
        SELECT * FROM referrals 
        WHERE referrer_id = ? 
    `;

    con.query(sqlReferrals, [referrerId], async (err, referrals) => {
        if (err) {
            return res.status(500).json({status: 'error', error: 'Failed to fetch referrals'});
        }

        if (referrals.length > 0) {
            const referredIds = referrals.map(referral => referral.referred_id);
            const sqlUsers = `
                SELECT COUNT(*) as approvedCount FROM users 
                WHERE id IN (?) 
                AND approved = 1;
            `;

            con.query(sqlUsers, [referredIds], (err, results) => {
                if (err) {
                    return res.status(500).json({status: 'error', error: 'Failed to fetch users'});
                }

                return res.json({status: 'success', approvedReferralsCount: results[0].approvedCount});
            });
        } else {
            return res.status(404).json({status: 'error', error: 'No approved referrals found for this referrer ID'});
        }
    });
});

    
    


app.post('/admin-login', (req, res) => {
    const sentloginUserName = req.body.LoginUserName;
    const sentLoginPassword = req.body.LoginPassword;

    const sql = 'SELECT * FROM admins WHERE username = ? && password = ?';
    const values = [sentloginUserName, sentLoginPassword];

    con.query(sql, values, (err, results) => {
        if (err) {
            res.status(500).send({ error: err });
        }
        if (results.length > 0) {
            const token = jwt.sign({ username: sentloginUserName ,isAdmin: true}, 'your_secret_key', { expiresIn: '24h' });
            res.status(200).send({ token });
        } else {
            res.status(401).send({ message: `Credentials don't match!` });
        }
    });
});



app.get('/approved-users',verifyToken, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.perPage) || 10;
    const searchTerm = req.query.searchTerm || ''; 
    const sortKey = req.query.sortKey || 'id';
    const sortDirection = req.query.sortDirection || 'asc'; 


    let sql = `SELECT id,balance,team,backend_wallet,  name,email,trx_id,total_withdrawal,CurrTeam,refer_by,password FROM  users
    WHERE 
        approved = 1
        AND payment_ok = 1`;

    if (searchTerm) {
        sql += ` AND (name LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%' OR id = '${searchTerm}')`;
    } else {
        sql += ` AND (CurrTeam >= 3 OR team >= 5)`;
    }


    const countSql = `SELECT COUNT(*) AS totalCount FROM users WHERE approved = 1 AND payment_ok = 1 ${searchTerm ? `AND (name LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%' OR id = '${searchTerm}')` : ''}`;


    con.query(countSql, (countErr, countResult) => {
        if (countErr) {
            console.error('Count Query Error:', countErr);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching total count.' });
        }

        const totalCount = countResult[0].totalCount;

        sql += ` ORDER BY ${sortKey} ${sortDirection}`;

        con.query(sql, (err, result) => {
            if (err) {
                console.error('Main Query Error:', err);
                return res.status(500).json({ success: false, message: 'An error occurred while fetching approved users.' });
            }

            res.status(200).json({
                success: true,
                approvedUsers: result,
                totalCount: totalCount,
                currentPage: page,
                totalPages: Math.ceil(totalCount / perPage)
            });
        });
    });


        
});
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    


    if (!token) {
        return res.status(403).json({ success: false, message: `No token provided ${token}` });
    }

    jwt.verify(token, 'your_secret_key', (err, decoded) => {
        if (err) {
            return res.status(401).json({ success: false, message: 'Failed to authenticate token.' });
        }

        if (!decoded.isAdmin) {
            return res.status(403).json({ success: false, message: 'Not authorized to access this resource.' });
        }

        next();
    });
}

app.get('/users-by-email', verifyToken,(req, res) => {



    const email = req.query.email || '';
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.perPage) || 10;
    const sortKey = req.query.sortKey || 'id';
    const sortDirection = req.query.sortDirection || 'asc';

    let sql = `SELECT id,balance,team,backend_wallet,  name,email,trx_id,total_withdrawal,CurrTeam,refer_by,password FROM  users
    WHERE 
        approved = 1
        AND payment_ok = 1`;
    if (email) {
        sql += ` AND (email LIKE '%${email}%' OR id = '${email}' OR trx_id LIKE '%${email}%')`;
    } else {
        sql += ` AND (CurrTeam >= 3 OR team >= 5)`;
    }


    const countSql = `SELECT COUNT(*) AS totalCount FROM users WHERE approved = 1 AND payment_ok = 1 ${email ? `AND email LIKE '%${email}%'` : ''}`;


    con.query(countSql, (countErr, countResult) => {
        if (countErr) {
            console.error('Count Query Error:', countErr);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching total count.' });
        }

        const totalCount = countResult[0].totalCount;

        sql += ` ORDER BY ${sortKey} ${sortDirection}`;

        con.query(sql, (err, result) => {
            if (err) {
                console.error('Main Query Error:', err); 
                return res.status(500).json({ success: false, message: 'An error occurred while fetching users by email.' });
            }

            res.status(200).json({
                success: true,
                users: result,
                totalCount: totalCount,
                currentPage: page,
                totalPages: Math.ceil(totalCount / perPage)
            });
        });
    });
});

app.get('/todayApproved', (req, res) => {


    const sql = `SELECT * FROM users WHERE approved = 1 AND approved_at >=  CURDATE() AND payment_ok = 1`;

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', approvedUsers: result });
        } else {
            return res.status(404).json({ status: 'error', error: 'No approved users found' });
        }
    });
});


app.put('/rejectUser/:userId', (req, res) => {
    const userId = req.params.userId;

    if (!userId) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }

    const sql = `
        UPDATE users 
        SET 
            rejected = 1, 
            payment_ok = 0,
            approved = 0,
       
                        rejected_at = CURRENT_TIMESTAMP 
        WHERE id = ? AND rejected = 0`;

    con.query(sql, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to reject user' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found or already rejected' });
        }

        res.json({ status: 'success', message: 'User rejected successfully' });
    });
});


app.get('/rejectedUsers', (req, res) => {
    const sql = 'SELECT * FROM users WHERE rejected = 1 ';

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', approvedUsers: result });
        } else {

        }
    });
});


app.get('/EasypaisaUsers', (req, res) => {
    const { type } = req.query; // Use req.query to get query parameters
console.log(type);
    // SQL query to select users based on type
    const sql = 'SELECT id,trx_id,refer_by,name,email,sender_name,sender_number FROM users WHERE approved = 0 AND payment_ok = 1 AND type = ?';

    con.query(sql, [type], (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', approvedUsers: result });
        } else {
            return res.status(404).json({ status: 'error', error: 'No approved users found' });
        }
    });
});



app.post('/withdraw', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ status: 'error', error: 'User not logged in' });
    }

    const userId = req.session.userId;
    const { amount, accountName, accountNumber, bankName, CurrTeam, totalWithdrawn, team } = req.body;

    if (!amount || !accountName || !accountNumber || !bankName) {
        return res.status(400).json({ status: 'error', error: 'All fields are required' });
    }

    const checkRequestSql = `
        SELECT * FROM withdrawal_requests
        WHERE user_id = ? AND approved = 'pending' AND reject = 0
    `;

    con.query(checkRequestSql, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to check for existing requests', details: err.message });
        }

        if (results.length > 0) {
            return res.status(400).json({ status: 'error', error: 'You already have a pending withdrawal request' });
        }

        const getUserLevelSql = `
            SELECT level FROM users WHERE id = ?
        `;

        con.query(getUserLevelSql, [userId], (err, userResults) => {
            if (err) {
                return res.status(500).json({ status: 'error', error: 'Failed to fetch user level', details: err.message });
            }

            if (userResults.length === 0) {
                return res.status(500).json({ status: 'error', error: 'User not found' });
            }

            const userLevel = userResults[0].level;

            const checkLimitsSql = `
                SELECT * FROM withdraw_limit
                WHERE level = ? AND ? >= min AND ? <= max
            `;

            con.query(checkLimitsSql, [userLevel, amount, amount], (err, limitResults) => {
                if (err) {
                    return res.status(500).json({ status: 'error', error: 'Failed to check withdrawal limits', details: err.message });
                }

                if (limitResults.length === 0) {
                    return res.status(400).json({ status: 'error', error: 'You Cannot withdraw this amount' });
                }

                const getExchangeFeeSql = `
                    SELECT fee FROM exchange_fee WHERE id = 1
                `;

                con.query(getExchangeFeeSql, (err, feeResults) => {
                    if (err) {
                        return res.status(500).json({ status: 'error', error: 'Failed to fetch exchange fee', details: err.message });
                    }

                    if (feeResults.length === 0) {
                        return res.status(500).json({ status: 'error', error: 'Exchange fee not found' });
                    }

                    const feePercentage = feeResults[0].fee;
                    const fee = (amount * feePercentage) / 100;
                    const amountAfterFee = amount - fee;

                    if (amountAfterFee <= 0) {
                        return res.status(400).json({ status: 'error', error: 'Amount after fee must be greater than zero' });
                    }

                    con.beginTransaction(err => {
                        if (err) {
                            return res.status(500).json({ status: 'error', error: 'Failed to start transaction' });
                        }

                        const withdrawSql = `
                            INSERT INTO withdrawal_requests (user_id, amount, account_name, account_number, bank_name, CurrTeam, total_withdrawn, team, request_date, approved, fee)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), 'pending', ?)
                        `;

                        con.query(withdrawSql, [userId, amountAfterFee, accountName, accountNumber, bankName, CurrTeam, totalWithdrawn, team, fee], (err, withdrawResult) => {
                            if (err) {
                                return con.rollback(() => {
                                    res.status(500).json({ status: 'error', error: 'Failed to make withdrawal', details: err.message });
                                });
                            }

                            con.commit(err => {
                                if (err) {
                                    return con.rollback(() => {
                                        res.status(500).json({ status: 'error', error: 'Failed to commit transaction', details: err.message });
                                    });
                                }
                                res.json({ status: 'success', message: 'Withdrawal request submitted successfully' });
                            });
                        });
                    });
                });
            });
        });
    });
});







app.get('/fetchCommissionData', (req, res) => {
    const sql = 'SELECT * FROM commission';

    con.query(sql, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch commission data' });
        }

        res.json({ status: 'success', data: result });
    });
});

app.get('/fetchLevelsData', (req, res) => {
    const sql = 'SELECT * FROM levels';

    con.query(sql, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch commission data' });
        }

        res.json({ status: 'success', data: result });
    });
});
app.get('/fetchLimitsData', (req, res) => {
    const sql = 'SELECT * FROM withdraw_limit';

    con.query(sql, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch commission data' });
        }

        res.json({ status: 'success', data: result });
    });
});

app.put('/updateLevelData', (req, res) => {
    const { id, min_team, max_team, level } = req.body;

    if (!min_team || !max_team || !level) {
        return res.status(400).json({ status: 'error', message: 'Min Team, Max Team, and Level are required' });
    }

    let updateQuery = `
        UPDATE levels
        SET 
            min_team = ?,
            max_team = ?,
            level = ?
        WHERE id = ?`;
    let queryParams = [min_team, max_team, level, id];


    con.query(updateQuery, queryParams, (err, result) => {
        if (err) {
            console.error('Error updating level data:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to update level data' });
        }


        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'Level data not found' });
        }

        res.json({ status: 'success', message: 'Level data updated successfully' });
    });
});
app.put('/updateWithdrawData', (req, res) => {
    const { id, min, max, level } = req.body;

    if (!min || !max || !level) {
        return res.status(400).json({ status: 'error', message: 'Min Team, Max Team, and Level are required' });
    }

    let updateQuery = `
        UPDATE withdraw_limit

        SET 
            min = ?,
            max = ?,
            level = ?
        WHERE id = ?`;
    let queryParams = [min, max, level, id];


    con.query(updateQuery, queryParams, (err, result) => {
        if (err) {
            console.error('Error updating level data:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to update level data' });
        }


        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'Level data not found' });
        }

        res.json({ status: 'success', message: 'Level data updated successfully' });
    });
});
app.put('/updateCommissionData', (req, res) => {
    const { id, direct_bonus, indirect_bonus } = req.body;

    if (!direct_bonus || !indirect_bonus) {
        return res.status(400).json({ status: 'error', message: 'Direct Bonus and Indirect Bonus are required' });
    }

    let updateQuery;
    let queryParams;

    if (id === 0) {
        updateQuery = `
            UPDATE commission
            SET 
                direct_bonus = ?,
                indirect_bonus = ?
            WHERE id = 0`;
        queryParams = [direct_bonus, indirect_bonus];
    } else {
        updateQuery = `
            UPDATE commission
            SET 
                direct_bonus = ?,
                indirect_bonus = ?
            WHERE id = ?`;
        queryParams = [direct_bonus, indirect_bonus, id];
    }


    con.query(updateQuery, queryParams, (err, result) => {
        if (err) {
            console.error('Error updating commission data:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to update commission data' });
        }


        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'Commission data not found' });
        }

        res.json({ status: 'success', message: 'Commission data updated successfully' });
    });
});
app.put('/updateUser', (req, res) => {
    if (!req.body.id) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }

    const { id, name, email, balance, CurrTeam, trx_id,password, total_withdrawal, backend_wallet } = req.body;

    const sql = `
        UPDATE users 
        SET 
            name = ?, 
            email = ?, 
            balance = ?, 
            CurrTeam = ?,
            trx_id = ?, 
            password = ?,
            total_withdrawal = ? ,
            backend_wallet = ?
        WHERE id = ?`;

    con.query(sql, [name, email, balance, CurrTeam, trx_id,password, total_withdrawal, backend_wallet, id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: 'error', error: 'Failed to update user', details: err });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        res.json({ status: 'success', message: 'User updated successfully' });
    });
});
app.post('/trackButton', (req, res) => {
    const { userId, buttonId } = req.body;
  
    // Insert the button click data into your database
    const sql = "INSERT INTO user_button_clicks (userId, buttonId, clickTime) VALUES (?, ?, NOW())";
    con.query(sql, [userId, buttonId], (err, result) => {
      if (err) {
        console.error('Error tracking button click:', err);
        return res.status(500).json({ Status: 'Error', Error: err.message });
      }
      console.log('Button click tracked successfully.');
      return res.status(200).json({ Status: 'Success' });
    });
  });
  // Endpoint to check if a button has been clicked by a user
app.get('/checkButtonClick', (req, res) => {
    const { userId, buttonId } = req.query;
  
    const sql = "SELECT COUNT(*) AS clickCount FROM user_button_clicks WHERE userId = ? AND buttonId = ?";
    con.query(sql, [userId, buttonId], (err, result) => {
      if (err) {
        console.error('Error checking button click status:', err);
        return res.status(500).json({ Status: 'Error', Error: err.message });
      }
      const clickCount = result[0].clickCount;
      const clicked = clickCount > 0;
      return res.status(200).json({ Status: 'Success', clicked });
    });
  });
  

app.put('/approveUser/:userId', (req, res) => {
    const userId = req.params.userId;

    if (!userId) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }

    const updateUsersQuery = `
    UPDATE users 
    SET 
        approved = 1, 
        payment_ok = 1,
        rejected = 0,
        approved_at = CURRENT_TIMESTAMP,
        backend_wallet = backend_wallet + (
            SELECT joining_fee * (SELECT initial_percent FROM initial_fee WHERE id = 1) / 100
            FROM joining_fee
            WHERE id = 1
        ) 
    WHERE id = ?`;

    const getReferrerIdQuery = `
        SELECT refer_by
        FROM users
        WHERE id = ?`;

    const getJoiningFeeQuery = `
        SELECT joining_fee
        FROM joining_fee
        WHERE id = 1`; 

    const incrementCurrTeamForReferrerQuery = `
        UPDATE users AS u1
        JOIN users AS u2 ON u1.id = u2.refer_by
        JOIN levels AS l ON u2.team + 1 >= l.min_team AND u2.team + 1 <= l.max_team
        SET u1.team = u2.team + 1,
            u1.level = l.level
        WHERE u2.id = ?;
    `;

    const incrementTodayTeamForReferrerQuery = `
        UPDATE users
        SET today_team = today_team + 1
        WHERE id = ?;
    `;

    const updateBalancesAndWalletQuery = `
        UPDATE users AS u
        JOIN commission AS c1 ON u.id = c1.person
        LEFT JOIN users AS r ON u.refer_by = r.id
        LEFT JOIN commission AS c2 ON r.id = c2.person
        JOIN joining_fee AS j ON j.id = 1
        SET 
            u.balance = u.balance + (c1.direct_bonus * (j.joining_fee / 100)), 
            u.backend_wallet = u.backend_wallet + COALESCE((c2.indirect_bonus * (j.joining_fee / 100)), 0)
        WHERE u.id = ?`;

    const IncrementsChain = (referrerId, depth) => {
        if (depth < 7) {
            updateBalancesAndWallet(referrerId, depth);
        } else {
            console.log('Reached maximum referral depth');
        }
    };

    const updateBalancesAndWallet = (userId, depth) => {
        if (depth >= 7) {
            return;
        }

        con.query(updateBalancesAndWalletQuery, [userId], (err, updateResult) => {
            if (err) {
                console.error('Error updating balances and wallet:', err);
                return;
            }

            con.query(getReferrerIdQuery, [userId], (err, referrerResult) => {
                if (err) {
                    console.error('Error fetching referrer ID:', err);
                    return;
                }

                const referrerId = referrerResult[0]?.refer_by;

                if (referrerId) {
                    const commissionQuery = `
                        SELECT direct_bonus, indirect_bonus
                        FROM commission
                        WHERE id = ?`;
                    con.query(commissionQuery, [depth], (err, commissionResult) => {
                        if (err) {
                            console.error('Error fetching commission data:', err);
                            return;
                        }

                        const directBonus = commissionResult[0]?.direct_bonus || 0;
                        const indirectBonus = commissionResult[0]?.indirect_bonus || 0;

                        con.query(getJoiningFeeQuery, (err, feeResult) => {
                            if (err) {
                                console.error('Error fetching joining fee:', err);
                                return;
                            }

                            const joiningFee = feeResult[0]?.joining_fee || 0;

                            const directBonusPercentage = (directBonus * (joiningFee / 100));
                            const indirectBonusPercentage = (indirectBonus * (joiningFee / 100));
                           
                            const updateBalancesQuery = `
                                UPDATE users
                                SET andor_coin = andor_coin + ?,
                                    backend_wallet = backend_wallet + ?
                                WHERE id = ?`;

                            con.query(updateBalancesQuery, [directBonusPercentage, indirectBonusPercentage, referrerId], (err, updateBalancesResult) => {
                                if (err) {
                                    console.error('Error updating referrer balances:', err);
                                    return;
                                }

                                IncrementsChain(referrerId, depth + 1);
                            });
                        });
                    });

                } else {
                    console.log('Reached top of referral hierarchy');
                }
            });

        });
    };

    con.beginTransaction((err) => {
        if (err) {
            console.error('Transaction start failed:', err);
            return res.status(500).json({ status: 'error', error: 'Transaction start failed' });
        }

        con.query(updateUsersQuery, [userId], (err, userResult) => {
            if (err) {
                console.error('Error updating users:', err);
                return con.rollback(() => {
                    res.status(500).json({ status: 'error', error: 'Failed to update user' });
                });
            }

            if (userResult.affectedRows === 0) {
                console.error('User not found or already approved');
                return con.rollback(() => {
                    res.status(404).json({ status: 'error', message: 'User not found or already approved' });
                });
            }

            updateBalancesAndWallet(userId, 0);

            con.query(getReferrerIdQuery, [userId], (err, referrerResult) => {
                if (err) {
                    console.error('Error fetching referrer ID:', err);
                    return con.rollback(() => {
                        res.status(500).json({ status: 'error', error: 'Failed to fetch referrer ID' });
                    });
                }

                const referrerId = referrerResult[0]?.refer_by;

                if (referrerId) {
                    con.query(incrementCurrTeamForReferrerQuery, [referrerId], (err, incrementResult) => {
                        if (err) {
                            console.error('Error incrementing CurrTeam for referring user:', err);
                            return con.rollback(() => {
                                res.status(500).json({ status: 'error', error: 'Failed to increment CurrTeam for referring user' });
                            });
                        }

                        con.query(incrementTodayTeamForReferrerQuery, [referrerId], (err, todayTeamResult) => {
                            if (err) {
                                console.error('Error incrementing today_team for referring user:', err);
                                return con.rollback(() => {
                                    res.status(500).json({ status: 'error', error: 'Failed to increment today_team for referring user' });
                                });
                            }

                            con.commit((err) => {
                                if (err) {
                                    console.error('Error committing transaction:', err);
                                    return con.rollback(() => {
                                        res.status(500).json({ status: 'error', error: 'Failed to commit transaction' });
                                    });
                                }

                                res.status(200).json({ status: 'success', message: 'User approved and balances updated' });
                            });
                        });
                    });

                } else {
                    console.log('Reached top of referral hierarchy');
                }
            });
        });
    });
});




app.get('/withdrawal-requests', (req, res) => {
    const userId = req.session.userId;

    if (!userId) {
        return res.status(401).json({ error: 'User not logged in' });
    }

    const sql = 'SELECT fee,user_id,account_number, request_date, reject, amount, bank_name, approved FROM withdrawal_requests WHERE user_id = ? ORDER BY request_date DESC';

    con.query(sql, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch withdrawal requests' });
        }

        const formattedResults = results.map(request => ({
            id: request.user_id,
            date: request.request_date,
            amount: request.amount,
            bank_name: request.bank_name,
            approved: request.approved,
            reject: request.reject,
            account_number: request.account_number,
            fee:request.fee
        }));
        res.json(formattedResults);
    });
});





app.get('/all-withdrawal-requests', (req, res) => {
  
  
  
      const sql = 'SELECT * FROM withdrawal_requests WHERE approved = "pending" AND reject = "0"';
      con.query(sql, (error, results) => {
        if (error) {
          res.status(500).json({ error: 'Internal Server Error' });
          return;
        }
  
        const mappedResults = results.map(item => ({
          id: item.id,
          user_id: item.user_id,
          amount: item.amount,
          account_name: item.account_name,
          bank_name: item.bank_name,
          CurrTeam: item.CurrTeam,
          account_number: item.account_number,
          approved: item.approved === 1,
          team: item.team,
          total_withdrawn: item.total_withdrawn
        }));
  
        res.json(mappedResults);
      });
  });




app.post('/approve-withdrawal', async (req, res) => {
    const { userId, requestId, amount } = req.body;

    if (!userId || !requestId || !amount) {
        return res.status(400).json({ error: 'User ID, request ID, and amount are required' });
    }

    const updateWithdrawalRequestsSql = `
        UPDATE withdrawal_requests 
        SET approved = 'approved', reject = 0, approved_time = CURRENT_TIMESTAMP 
        WHERE id = ? AND user_id = ? AND approved = 'pending'`;

    const updateUserBalanceAndTotalWithdrawalSql = `
        UPDATE users
        SET balance = 0,
            total_withdrawal = total_withdrawal + ?
        WHERE id = ?`;

    const deleteUserClicksSql = `
        DELETE FROM user_product_clicks
        WHERE user_id = ?`;

    const deleteReferralsSql =
        `  DELETE FROM referrals
    WHERE referrer_id = ?`;

    con.beginTransaction(error => {
        if (error) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        con.query(updateWithdrawalRequestsSql, [requestId, userId], (error, results) => {
            if (error) {
                return con.rollback(() => {
                    res.status(500).json({ error: 'Internal Server Error' });
                });
            }

            if (results.affectedRows === 0) {
                return res.status(400).json({ error: 'Could not find the withdrawal request or it is already approved' });
            }

            con.query(updateUserBalanceAndTotalWithdrawalSql, [amount, userId], (error, results) => {
                if (error) {
                    return con.rollback(() => {
                        res.status(500).json({ error: 'Internal Server Error' });
                    });
                }

                con.query(deleteUserClicksSql, [userId], (error, results) => {
                    if (error) {
                        return con.rollback(() => {
                            res.status(500).json({ error: 'Internal Server Error' });
                        });
                    }

                    // Added code to delete referrals
                    con.query(deleteReferralsSql, [userId], (error, deleteResult) => {
                        if (error) {
                            return con.rollback(() => {
                                res.status(500).json({ status: 'error', error: 'Failed to delete referrals' });
                            });
                        }

                        con.commit(error => {
                            if (error) {
                                return con.rollback(() => {
                                    res.status(500).json({ status: 'error', error: 'Failed to commit transaction' });
                                });
                            }

                            res.json({ message: 'Withdrawal request approved, balance and total withdrawal updated, user clicks data, and referrals deleted successfully!' });
                        });
                    });
                });
            });
        });
    });
});




app.post('/reject-withdrawal', async (req, res) => {
    const { requestId, userId } = req.body; 

    if (!requestId || !userId) {
        return res.status(400).json({ error: 'Request ID and User ID are required' });
    }

    const updateWithdrawalRequestsSql = `
        UPDATE withdrawal_requests 
        SET reject=1, approved='pending', reject_at=CURRENT_TIMESTAMP 
        WHERE id=? AND user_id=? ;
    `;

    try {
        con.query(updateWithdrawalRequestsSql, [requestId, userId], (err, result) => {
            if (err) {
                console.error('Error executing query', err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            if (result.affectedRows > 0) {
                return res.json({ message: 'Withdrawal request rejected successfully!' });
            } else {
                return res.status(404).json({ error: 'No matching withdrawal request found' });
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.get('/withdrawalRequestsApproved', (req, res) => {
    const sql = 'SELECT * FROM withdrawal_requests WHERE approved = "approved" && reject = 0 ORDER BY id DESC';

    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved withdrawal requests' });
        }

        if (results.length === 0) {
            return res.status(404).json({ status: 'error', message: 'No approved withdrawal requests found' });
        }

        res.json({ status: 'success', data: results });
    });
});
app.get('/withdrawalRequestsRejected', (req, res) => {
    const sql = 'SELECT * FROM withdrawal_requests WHERE approved = "pending" && reject = 1';

    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved withdrawal requests' });
        }

        if (results.length === 0) {
            return res.status(404).json({ status: 'error', message: 'No approved withdrawal requests found' });
        }

        res.json({ status: 'success', data: results });
    });
});
app.get('/products', (req, res) => {
    const sql = 'SELECT * FROM products';
    
    db.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the products.' }); 
        }

        res.status(200).json({ success: true, data: results });
    });
});

app.post('/products', (req, res) => {
    const { description, link, reward } = req.body;
    if (!description || !link || !reward) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    const product = { description, link, reward };
    const sql = 'INSERT INTO products SET ?';

    con.query(sql, product, (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while adding the product.' });
        }
        res.status(201).json({ success: true, message: 'Product added successfully.' });
    });
});

app.delete('/products/:id', (req, res) => {
    const id = req.params.id;

    if (!id) {
        return res.status(400).json({ success: false, message: 'ID is required.' });
    }

    const sql = 'DELETE FROM products WHERE id = ?';
    con.query(sql, [id], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while deleting the product.' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Product not found.' });
        }

        res.status(200).json({ success: true, message: 'Product deleted successfully.' });
    });
});

app.put('/products/:id', (req, res) => {
    const id = req.params.id;
    const { description, link, reward } = req.body;

    if (!description || !link || !reward) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    const sql = 'UPDATE products SET description = ?, link = ?, reward = ? WHERE id = ?';

    con.query(sql, [description, link, reward, id], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while updating the product.' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Product not found.' });
        }

        res.status(200).json({ success: true, message: 'Product updated successfully.' });
    });
});










app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    let sql = `SELECT * FROM users WHERE id = ${con.escape(userId)}`;
    con.query(sql, (err, result) => {
        if (err) {
            res.status(500).send(err);
            return;
        }

        if (result.length === 0) {
            res.status(404).send({ message: 'User not found' });
            return;
        }

        res.send(result[0]);
    });
});

app.get('/mining-status', (req, res) => {
    const user_id = req.session.userId;
    const sql = 'SELECT mining_status FROM users WHERE id = ?';

    if (user_id) {
        con.query(sql, [user_id], (err, result) => {
            if (err) {
                return res.status(500).json({ status: 'error', error: 'Failed to fetch mining status' });
            }
            if (result.length === 0) {
                return res.status(404).json({ status: 'error', error: 'User not found' });
            }
            return res.status(200).json({ status: 'success', data: result[0].mining_status });
        });
    } else {
        return res.status(400).json({ status: 'error', error: 'User ID is missing' });
    }
});
app.post('/mining-status', (req, res) => {
    const user_id = req.session.userId;
    const sqlUpdateStatus = 'UPDATE users SET mining_status = 1 WHERE id = ? AND mining_status = 0';

    // Update the mining status to 1 for the specific user with status 0
    con.query(sqlUpdateStatus, [user_id], (err, result) => {
        if (err) {
            console.log('Error updating mining status:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to update mining status' });
        }

        // Check if any rows were affected (i.e., if the user's status was updated)
        if (result.affectedRows > 0) {
            return res.status(200).json({ status: 'success', data: 'Mining status updated successfully' });
        } else {
            return res.status(200).json({ status: 'success', data: 'No update needed. Mining status was already set to 1 or user not found' });
        }
    });
});





app.get('/get-accounts', (req, res) => {
    const sql = 'SELECT * FROM accounts'; 

    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching accounts.' });
        }

        res.status(200).json({ success: true, accounts: results });
    });
});
app.get('/receive-accounts', (req, res) => {
    const status = 'on';  
    const sql = 'SELECT * FROM accounts WHERE status = ? LIMIT 1'; 

    con.query(sql, [status], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching accounts.' });
        }

        if (result.length > 0) {
            res.status(200).json({ success: true, account: result[0] });
        } else {
            res.status(404).json({ success: false, message: 'No account found with the given status.' });
        }
    });
});

app.get('/get-fee', (req, res) => {
    const sql = 'SELECT joining_fee FROM joining_fee WHERE id = ?';
    

    const accountId = 1; 
    

    con.query(sql, [accountId], (err, result) => {
        if (err) {
            console.error('Error fetching fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the fee.' });
        }

        if (result.length > 0) {
            const feeValue = result[0].joining_fee;
            res.status(200).json({ success: true, fee: feeValue });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});
app.get('/get-exchange-fee', (req, res) => {
    const sql = 'SELECT fee FROM exchange_fee    WHERE id = ?';
    

    const accountId = 1; 
    

    con.query(sql, [accountId], (err, result) => {
        if (err) {
            console.error('Error fetching fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the fee.' });
        }

        if (result.length > 0) {
            const feeValue = result[0].fee;
            res.status(200).json({ success: true, fee: feeValue });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});
app.get('/get-winstuk-value', (req, res) => {
    const sql = 'SELECT value FROM winstuk_value  WHERE id = ?';
    

    const accountId = 1; 
    

    con.query(sql, [accountId], (err, result) => {
        if (err) {
            console.error('Error fetching fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the fee.' });
        }

        if (result.length > 0) {
            const Value = result[0].value;
            res.status(200).json({ success: true, value: Value });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});
app.get('/get-tact-value', (req, res) => {
    const sql = 'SELECT value FROM hizo_value    WHERE id = ?';
    

    const accountId = 1; 
    

    con.query(sql, [accountId], (err, result) => {
        if (err) {
            console.error('Error fetching fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the fee.' });
        }

        if (result.length > 0) {
            const Value = result[0].value;
            res.status(200).json({ success: true, value: Value });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});
app.get('/get-kiton-value', (req, res) => {
    const sql = 'SELECT value FROM kiton_value    WHERE id = ?';
    

    const accountId = 1; 
    

    con.query(sql, [accountId], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the fee.' });
        }

        if (result.length > 0) {
            const Value = result[0].value;
            res.status(200).json({ success: true, value: Value });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});
app.get('/get-andor-value', (req, res) => {
    const sql = 'SELECT value FROM andor_value    WHERE id = ?';
    

    const accountId = 1; 
    

    con.query(sql, [accountId], (err, result) => {
        if (err) {
            console.error('Error fetching fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the fee.' });
        }

        if (result.length > 0) {
            const Value = result[0].value;
            res.status(200).json({ success: true, value: Value });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});

app.get('/get-percentage', (req, res) => {
    const sql = 'SELECT initial_percent FROM initial_fee WHERE id = 1';
    
    con.query(sql, (err, result) => {
         if (err) {
            console.error('Error fetching fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the fee.' });
        }
         else{
            if (result.length > 0) {
                const feeValue = result[0].initial_percent;
                res.status(200).json({ success: true, initial_percent: feeValue });
            } else {
                res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
            }
         }
    })

  
});

app.get('/get-rate', (req, res) => {
    const sql = 'SELECT rate FROM usd_rate WHERE id = ?'; 

    const accountId = 1; 

    con.query(sql, [accountId], (err, result) => {
        if (err) {
            console.error('Error fetching fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the fee.' });
        }

        if (result.length > 0) {
            const rateValue = result[0].rate;
            res.status(200).json({ success: true, rate: rateValue });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});
app.get('/get-offer', (req, res) => {
    const sql = 'SELECT offer FROM offer WHERE id = ?';

    const accountId = 1;

    con.query(sql, [accountId], (err, result) => {
        if (err) {
            console.error('Error fetching offer:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the offer.' });
        }

        if (result.length > 0) {
            const offerValue = result[0].offer;
            res.status(200).json({ success: true, offer: offerValue });
        } else {
            res.status(404).json({ success: false, message: 'No offer found for the given account ID.' });
        }
    });
});


app.post('/update-fee', (req, res) => {
    const { newFeeValue } = req.body;

    const accountId = 1; 

    const updateSql = 'UPDATE joining_fee SET joining_fee = ? WHERE id = ?';

    con.query(updateSql, [newFeeValue, accountId], (err, result) => {
        if (err) {
            console.error('Error updating fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while updating the fee.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'Fee updated successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});
app.post('/update-winstuk-value', (req, res) => {
    const { newWinstukValue } = req.body;

    const accountId = 1; 

    const updateSql = 'UPDATE winstuk_value    SET value = ? WHERE id = ?';

    con.query(updateSql, [newWinstukValue, accountId], (err, result) => {
        if (err) {
            console.error('Error updating fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while updating the fee.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'Winstuk updated successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'No Value found for the given account ID.' });
        }
    });
});
app.post('/update-andor-value', (req, res) => {
    const { newAndorValue } = req.body;

    const accountId = 1; 

    const updateSql = 'UPDATE andor_value    SET value = ? WHERE id = ?';

    con.query(updateSql, [newAndorValue, accountId], (err, result) => {
        if (err) {
            console.error('Error updating fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while updating the fee.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'Winstuk updated successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'No Value found for the given account ID.' });
        }
    });
});

app.post('/update-tact-value', (req, res) => {
    const { newTactCoinValue } = req.body;

    const accountId = 1; 

    const updateSql = 'UPDATE hizo_value    SET value = ? WHERE id = ?';

    con.query(updateSql, [newTactCoinValue, accountId], (err, result) => {
        if (err) {
            console.error('Error updating fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while updating the fee.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'Tact updated successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'No Value found for the given account ID.' });
        }
    });
});
app.post('/update-kiton-value', (req, res) => {
    const { newKitonValue } = req.body;

    const accountId = 1; 

    const updateSql = 'UPDATE kiton_value    SET value = ? WHERE id = ?';

    con.query(updateSql, [newKitonValue, accountId], (err, result) => {
        if (err) {
            console.error('Error updating fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while updating the fee.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'Tact updated successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'No Value found for the given account ID.' });
        }
    });
});
app.post('/update-percentage', (req, res) => {
    const { newFeeValue } = req.body;

    const accountId = 1;
    const updateSql = 'UPDATE initial_fee   SET initial_percent = ? WHERE id = 1';

    con.query(updateSql, [newFeeValue, accountId], (err, result) => {
        if (err) {
            console.error('Error updating fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while updating the fee.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'Percentage updated .' });
        } else {
            res.status(404).json({ success: false, message: 'No Percentage found for the given account ID.' });
        }
    });
});
app.get('/pending-users', (req, res) => {
    const searchTerm = req.query.searchTerm;

    if (!searchTerm) {
        return res.status(400).json({ success: false, message: 'No search term provided.' });
    }

    let sql = 'SELECT * FROM users WHERE payment_ok = 0 AND approved = 0 AND (name LIKE ? OR email LIKE ?)';
    const searchTermWildcard = `%${searchTerm}%`;
    const params = [searchTermWildcard, searchTermWildcard];

    con.query(sql, params, (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the pending users.' });
        }

        res.status(200).json({
            success: true,
            pendingUsers: result
        });
    });
});

app.post('/update-usd', (req, res) => {
    const { newFeeValue } = req.body;

    const accountId = 1;

    const updateSql = 'UPDATE usd_rate SET rate = ? WHERE id = ?';

    con.query(updateSql, [newFeeValue, accountId], (err, result) => {
        if (err) {
            console.error('Error updating fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while updating the fee.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'Fee updated successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});
app.post('/update-exchange-fee', (req, res) => {
    const { newExchangeFee } = req.body;

    const id = 1;

    const updateSql = 'UPDATE exchange_fee    SET fee = ? WHERE id = ?';

    con.query(updateSql, [newExchangeFee, id], (err, result) => {
        if (err) {
            console.error('Error updating fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while updating the fee.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'Fee updated successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});

app.post('/update-offer', (req, res) => {
    const { newOfferValue } = req.body;

    const accountId = 1; 

    const updateSql = 'UPDATE offer SET offer = ? WHERE id = ?';

    con.query(updateSql, [newOfferValue, accountId], (err, result) => {
        if (err) {
            console.error('Error updating fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while updating the fee.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'Fee updated successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});


app.delete('/delete-user/:id', (req, res) => {
    const userId = req.params.id;
    const sql = 'DELETE FROM users WHERE id = ?';

    con.query(sql, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while deleting the user.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'User deleted successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'User not found.' });
        }
    });
});
app.delete('/delete-7-days-old-users', (req, res) => {
    const sql = `
        DELETE FROM users 
        WHERE payment_ok=0 AND approved=0 AND created_at <= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
    `;

    con.query(sql, (err, result) => {
        if(err) {
            console.error(err);
            return res.status(500).json({ success: false, message: "An error occurred while deleting the users." });
        }

        res.status(200).json({ success: true, message: `${result.affectedRows} users deleted successfully.` });
    });
});

  
 
app.post('/update-accounts', (req, res) => {
    const accounts = req.body.accounts;

    if (!accounts || !Array.isArray(accounts)) {
        return res.status(400).json({ success: false, message: 'Invalid account data.' });
    }

    accounts.forEach(account => {
        if (account.account_id) {  
            const sql = 'UPDATE accounts SET account_name = ?, account_number = ?, status = ? WHERE account_id = ?';
            const values = [account.account_name, account.account_number, account.status, account.account_id];

            con.query(sql, values, (err) => {
                if (err) {
                    console.error('Failed to update account:', err);
                }
            });
        } else {
            console.error('Account ID is NULL, skipping update.');
        }
    });

    res.json({ success: true, message: 'Accounts updated successfully.' });
});

app.get('/dashboard-data', (req, res) => {
    const today = new Date();
    today.setHours(0,0,0,0);
    const tomorrow = new Date(today);
    tomorrow.setDate(today.getDate() + 1);

    const sql = `
        SELECT 
            (SELECT COUNT(*) FROM users WHERE approved = 1) as approvedUsersCount,
            (SELECT COUNT(*) FROM users WHERE approved = 1 AND approved_at >= ? AND approved_at < ?) as approvedUsersCountToday,
            (SELECT SUM(amount) FROM withdrawal_requests where approved='approved') as totalWithdrawal ,
            (SELECT SUM(amount) FROM withdrawal_requests WHERE DATE(approved_time) = CURDATE()) as totalAmountToday,
            (SELECT COUNT(*) FROM users WHERE payment_ok = 0 AND approved = 0) as unapprovedUnpaidUsersCount,
            (SELECT SUM(amount) as total_amount FROM withdrawal_requests WHERE DATE(approved_time) = CURDATE()) as totalAmountTodayWithdrawal,
            (SELECT SUM(jf.joining_fee * (SELECT COUNT(*) FROM users WHERE approved = 1)) FROM joining_fee jf) as totalReceived,
            (SELECT SUM(jf.joining_fee * (SELECT COUNT(*) FROM users WHERE approved = 1 AND approved_at >= ? AND approved_at < ?)) FROM joining_fee jf) as totalReceivedToday
    `;

    con.query(sql, [today, tomorrow, today, tomorrow], (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching dashboard data.' });
        }

        const dashboardData = {
            approvedUsersCount: results[0].approvedUsersCount,
            approvedUsersCountToday: results[0].approvedUsersCountToday,
            totalWithdrawal: results[0].totalWithdrawal,
            totalAmountToday: results[0].totalAmountToday,
            unapprovedUnpaidUsersCount: results[0].unapprovedUnpaidUsersCount,
            totalAmountTodayWithdrawal: results[0].totalAmountTodayWithdrawal,
            totalReceived: results[0].totalReceived,
            totalReceivedToday: results[0].totalReceivedToday
        };

        res.status(200).json({ success: true, dashboardData });
    });
});



app.get('/get-total-withdrawal', (req, res) => {
    const sql = 'SELECT SUM(amount) AS totalWithdrawal FROM withdrawal_requests';

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the total withdrawal.' });
        }

        if (result.length === 0) {
            return res.status(404).json({ success: false, message: 'No withdrawal requests found.' });
        }

        res.status(200).json({ success: true, totalWithdrawal: result[0].totalWithdrawal });
    });
});
app.delete('/delete-old-rejected-users', (req, res) => {
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const deleteOldRejectedUsersSql = `
        DELETE FROM users
        WHERE rejected = 1 AND rejected_at < ?`;

    con.query(deleteOldRejectedUsersSql, [sevenDaysAgo], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        res.json({ message: 'Old rejected user records deleted successfully' });
    });
});
app.delete('/delete-rejected-users', (req, res) => {
    const deleteRejectedUsersSql = `
        DELETE FROM users
        WHERE rejected = 1`;

    con.query(deleteRejectedUsersSql, (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (results.affectedRows === 0) {
            return res.json({ message: 'No rejected users to delete' });
        }

        res.json({ message: 'Rejected users deleted successfully' });
    });
});


app.get('/unapproved-unpaid-users-count', (req, res) => {
    const sql = 'SELECT COUNT(*) AS count FROM users WHERE payment_ok = 0 AND approved = 0';

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the users count.' });
        }

        if (result.length === 0) {
            return res.status(404).json({ success: false, message: 'No users found.' });
        }

        res.status(200).json({ success: true, count: result[0].count });
    });
});

  const fetchApprovedUserNames = (referByUserId) => {
    return new Promise((resolve, reject) => {
      const fetchNamesQuery = 'SELECT id, name ,whatsapp,backend_wallet, profile_picture FROM users WHERE refer_by = ? AND approved = 1';
      con.query(fetchNamesQuery, [referByUserId], (err, results) => {
        if (err) {
          reject(err);
        } else {
          resolve(results); 
          
        }
      });
    });
  };
  
  
  app.get('/approvedUserNames/:referByUserId', async (req, res) => {
    const { referByUserId } = req.params;
  
    try {
      const users = await fetchApprovedUserNames(referByUserId);
      res.json({ status: 'success', users });
    } catch (error) {
      console.error('Error fetching approved users:', error);
      res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
    }
  });

// --------------------------------------------------
// Coin Base
// --------------------------------------------------
app.get('/userCoins/:userId', (req, res) => {
    const userId = req.params.userId;

    const fetchUserCoinsQuery = 'SELECT winstuk_coin, andor_coin, hizo_coin, kiton_coin FROM users WHERE id = ?';
    con.query(fetchUserCoinsQuery, [userId], (err, result) => {
        if (err) {
            console.error('Error fetching user coins:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch user coins' });
        }

        if (result.length === 0) {
            return res.status(404).json({ status: 'error', error: 'User not found' });
        }

        const userCoins = result.map(row => ({
            winstuk_coin: row.winstuk_coin,
            andor_coin: row.andor_coin,
            hizo_coin: row.hizo_coin,
            kiton_coin: row.kiton_coin,
        }));

        res.json({ status: 'success', userCoins });
    });
});

  app.get('/getUserMining/:userId', (req, res) => {
    const userId = req.params.userId;

    const getUserDataSql = 'SELECT * FROM winstuk_coin WHERE user_id = ? ORDER BY created_at DESC ';

    con.query(getUserDataSql, [userId], (err, result) => {
        if (err) {
            console.error('Error fetching user data:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch user data' });
        }

        if (result.length === 0) {
            return res.status(404).json({ status: 'error', error: 'User data not found' });
        }

        res.json({ status: 'success', data: result });
    });
});





// app.post('/sellCoins/:userId', (req, res) => {
//     const userId = req.params.userId;
//     const { amount, coin,table,value } = req.body;
// console.log(amount,coin,table,value);
//     if (!amount) {
//         return res.status(400).json({ status: 'error', error: 'Amount is required' });
//     }

//     const coinColumnName = `${coin.toLowerCase()}`;
//     const deductQuery = `UPDATE users SET balance = balance + ?, ${coinColumnName} = 0 WHERE id = ?`;
//     con.beginTransaction(function(err) {
//         if (err) {
//             console.error('Transaction error:', err);
//             return res.status(500).json({ status: 'error', error: 'Failed to start transaction' });
//         }

//         con.query(deductQuery, [amount, userId], (err, result) => {
//             if (err) {
//                 console.error('Error selling coins:', err);
//                 con.rollback(function() {
//                     return res.status(500).json({ status: 'error', error: 'Failed to sell coins' });
//                 });
//             }

//             const sellHistoryQuery = `INSERT INTO ${table} (user_id, amount, value) VALUES (?, ?, ?)`;
//             con.query(sellHistoryQuery, [userId, amount, value], (err, result) => {
//                 if (err) {
//                     console.error('Error adding to sell history:', err);
//                     con.rollback(function() {
//                         return res.status(500).json({ status: 'error', error: 'Failed to add to sell history' });
//                     });
//                 }

//                 con.commit(function(err) {
//                     if (err) {
//                         console.error('Commit error:', err);
//                         con.rollback(function() {
//                             return res.status(500).json({ status: 'error', error: 'Failed to commit transaction' });
//                         });
//                     }

//                     res.json({ status: 'success', message: 'Coins sold successfully' });
//                 });
//             });
//         });
//     });
// });









app.post('/WinstuksellHistory/:userId', (req, res) => {
    const userId = req.params.userId;
    const coinName = req.body.coinName;
    console.log(coinName);
    
    if (!coinName) {
        return res.status(400).json({ status: 'error', error: 'History not Available' });
    }

    const fetchQuery = `SELECT * FROM ${coinName} WHERE user_id = ? ORDER BY created_at DESC`;

    con.query(fetchQuery, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'History not Available' });
        }
    
        console.log('Fetched data:', result); 

        const sellHistory = result.map(row => ({
            id: row.id,
            
            amount: row.amount,
            date: row.created_at,
            value: row.value

        }));

        res.json({ status: 'success', sellHistory: sellHistory });
    });
});






app.put('/updateUserAccount/:userId', (req, res) => {
    const user_id = req.params.userId;
    const { accountNumber, nameOnAccount, bankName } = req.body;

    if (!user_id || !accountNumber || !nameOnAccount || !bankName) {
        return res.status(400).json({ status: 'error', message: 'User ID, Account Number, Name on Account, and Bank Name are required' });
    }

    let updateQuery = `
        UPDATE users_accounts
        SET 
            holder_name = ?,
            holder_number = ?,
            bankName = ?
        WHERE user_id = ?`;
    let updateParams = [nameOnAccount, accountNumber, bankName, user_id];

    con.query(updateQuery, updateParams, (err, updateResult) => {
        if (err) {
            console.error('Error updating user account:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to update user account' });
        }

        if (updateResult.affectedRows === 0) {
            let insertQuery = `
                INSERT INTO users_accounts (user_id, holder_name, holder_number, bankName)
                VALUES (?, ?, ?, ?)`;
            let insertParams = [user_id, nameOnAccount, accountNumber, bankName];

            con.query(insertQuery, insertParams, (err, insertResult) => {
                if (err) {
                    console.error('Error inserting user account:', err);
                    return res.status(500).json({ status: 'error', error: 'Failed to insert user account' });
                }

                res.json({ status: 'success', message: 'User account inserted successfully' });
            });
        } else {
            res.json({ status: 'success', message: 'User account updated successfully' });
        }
    });
});


app.put('/updatePassword/:userId', (req, res) => {
    const userId = req.params.userId;
    const { oldPassword, newPassword } = req.body;

    if (!userId || !oldPassword || !newPassword) {
        return res.status(400).json({ status: 'error', message: 'User ID, Old Password, and New Password are required' });
    }
    con.query('SELECT password FROM users WHERE id = ?', [userId], (err, result) => {
        if (err) {
            console.error('Error checking old password:', err);
            return res.status(500).json({ status: 'error', message: 'Failed to check old password' });
        }

        if (result.length === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        const storedPassword = result[0].password;

        if (storedPassword !== oldPassword) {
            return res.status(401).json({ status: 'error', message: 'Incorrect old password' });
        }

        let updateQuery = `
            UPDATE users
            SET 
                password = ?
            WHERE id = ?`;
        let queryParams = [newPassword, userId];

        con.query(updateQuery, queryParams, (err, result) => {
            if (err) {
                console.error('Error updating password:', err);
                return res.status(500).json({ status: 'error', message: 'Failed to update password' });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({ status: 'error', message: 'User not found' });
            }

            res.json({ status: 'success', message: 'Password updated successfully' });
        });
    });
});


app.get('/getUserAccount/:userId', (req, res) => {
    const user_id = req.params.userId;
      if (!user_id) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }
     let fetchQuery = 'SELECT * FROM users_accounts WHERE user_id = ?';
     let queryParams = [user_id];
     con.query(fetchQuery, queryParams, (err, result) => {
         if (err) {
             console.error('Error fetching user account:', err);
             return res.status(500).json({ status: 'error', error: 'Failed to fetch user account' });
         }
         if (result.length === 0) {
             return res.status(404).json({ status: 'error', message: 'User account not found' });
         }
         res.json({ status: 'success', userAccount: result[0] });
     })
})


app.post('/updateUserAccounts/:userId', (req, res) => {
    const user_id = req.params.userId;

    if (!user_id || !req.body) {
        return res.status(400).json({ status: 'error', message: 'Missing required fields' });
    }

    const checkUserQuery = `
        SELECT user_id FROM users_accounts WHERE user_id = ?
    `;

    con.query(checkUserQuery, [user_id], (err, rows) => {
        if (err) {
            console.error('Error checking user:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to check user' });
        }

        if (rows.length > 0) {
            return res.status(200).json({ status: 'success', message: 'User account details already exist' });
        }
        const insertIntoAccountDetailsSql = `
            INSERT INTO users_accounts (user_id, holder_name, holder_number, coin_address) 
            VALUES (?, '', '', '')
        `;
        con.query(insertIntoAccountDetailsSql, [user_id], (err, result) => {
            if (err) {
                console.error('Error inserting into account details:', err);
                return res.status(500).json({ status: 'error', error: 'Failed to insert into account details' });
            }

            res.status(200).json({ status: 'success', message: 'User account details inserted successfully' });
        });
    });
});




app.get('/total-usdt', (req, res) => {
    const userId = req.session.userId; 

    if (!userId) {
        return res.status(401).json({ status: 'error', error: 'User not logged in' });
    }

    const getUserCoinsSql = `
        SELECT winstuk_coin, andor_coin, hizo_coin, kiton_coin
        FROM users
        WHERE id = ?
    `;

    con.query(getUserCoinsSql, [userId], (err, userCoins) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch user coins', details: err.message });
        }

        if (userCoins.length === 0) {
            return res.status(404).json({ status: 'error', error: 'User not found' });
        }

        const { winstuk_coin, andor_coin, hizo_coin, kiton_coin } = userCoins[0];

        const getValuesSql = `
            SELECT 
                (SELECT value FROM winstuk_value WHERE id = 1) AS winstuk_value,
                (SELECT value FROM andor_value WHERE id = 1) AS andor_value,
                (SELECT value FROM hizo_value WHERE id = 1) AS hizo_value,
                (SELECT value FROM kiton_value WHERE id = 1) AS kiton_value
        `;

        con.query(getValuesSql, (err, values) => {
            if (err) {
                return res.status(500).json({ status: 'error', error: 'Failed to fetch values', details: err.message });
            }

            const { winstuk_value, andor_value, hizo_value, kiton_value } = values[0];

          
            
            const totalUsdt = (parseFloat(winstuk_coin) + parseFloat(hizo_coin) + parseFloat(kiton_coin) + parseFloat(andor_coin) ).toFixed(3);
            console.log(winstuk_coin,hizo_coin,kiton_coin,andor_coin);
            res.json({ 
                status: 'success', 
                totalUsdt,
                breakdown: {
                    winstuk_coin: winstuk_coin,
                    andor_coin: andor_coin,
                    hizo_coin: hizo_coin,
                    kiton_coin: kiton_coin,
                    winstuk_value: winstuk_value,
                    andor_value: andor_value,
                    hizo_value: hizo_value,
                    kiton_value: kiton_value,
                    winstuk_total: winstuk_coin * winstuk_value,
                    andor_total: andor_coin * andor_value,
                    hizo_total: hizo_coin * hizo_value,
                    kiton_total: kiton_coin * kiton_value
                }
            });
        });
    });
});
const getUserIdFromSession = (req, res, next) => {
    if (req.session && req.session.userId) {
      res.json({ userId: req.session.userId });
    } else {
      res.status(401).json({ error: 'User not authenticated' });
    }
  };
  
  app.get('/getUserIdFromSession', getUserIdFromSession);
  
app.post('/update-whatsapp', (req, res) => {
    const { userId, whatsappNumber } = req.body;
    
console.log(req.body);
    if (!userId || !whatsappNumber) {
        return res.status(400).json({ error: 'User ID and WhatsApp number are required' });
    }

    const updateUserWhatsappSql = `
        UPDATE users 
        SET whatsapp = ? 
        WHERE id = ?;
    `;

    con.query(updateUserWhatsappSql, [whatsappNumber, userId], (err, result) => {
        if (err) {
            console.error('Error executing query', err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        if (result.affectedRows > 0) {
            return res.json({ message: 'WhatsApp number updated successfully!' });
        } else {
            return res.status(404).json({ error: 'No matching user found' });
        }
    });
});
app.post('/give-bonus', (req, res) => {
    const bonusQuery = `
        UPDATE users u
        JOIN (
            SELECT 
                u2.refer_by,
                COUNT(u2.id) AS referred_count
            FROM 
                users u2
            WHERE 
                u2.approved_at IS NOT NULL 
                AND DATE(u2.approved_at) = CURDATE()
            GROUP BY 
                u2.refer_by
        ) AS referrals ON u.id = referrals.refer_by
        JOIN bonus_setting bs ON referrals.referred_count BETWEEN bs.min_referred_count AND bs.max_referred_count
        SET 
            u.hizo_coin = u.hizo_coin + bs.reward;
    `;
    
    con.query(bonusQuery, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to give bonus' });
        }
        
        res.json({ status: 'success' });
    });
});

app.get('/bonus-settings', (req, res) => {
    // Execute SQL query to fetch data from bonus_setting table
    const fetchSettingsQuery = 'SELECT * FROM bonus_setting';
    
    con.query(fetchSettingsQuery, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch bonus settings' });
        }
        
        // If data fetched successfully, return it in the response
        res.json({ status: 'success', data: result });
    });
});
app.put('/bonus-settings/:id', (req, res) => {
    const settingId = req.params.id;
    const { min_referred_count, max_referred_count, reward } = req.body;
    
    const updateSettingQuery = `
        UPDATE bonus_setting
        SET min_referred_count = ?, max_referred_count = ?, reward = ?
        WHERE id = ?
    `;

    con.query(updateSettingQuery, [min_referred_count, max_referred_count, reward, settingId], (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to update bonus setting' });
        }

        res.json({ status: 'success', message: 'Bonus setting updated successfully' });
    });
});
app.listen(PORT, () => {
    console.log('Listening on port ' + PORT);
});



