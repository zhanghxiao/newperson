// require('dotenv').config();

// const express = require('express');
// const cors = require('cors');
// const crypto = require('crypto');
// const jwt = require('jsonwebtoken');
// const fs = require('fs');
// const fsPromises = require('fs/promises');
// const path = require('path');
// const compression = require('compression');
// const helmet = require('helmet');
// const morgan = require('morgan');
// const multer = require('multer');

// const app = express();

// // 环境变量配置
// const PORT = process.env.PORT || 3000;
// const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY || '1234';
// const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
// const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// // 启动时验证环境变量
// console.log('Environment check:', {
//     ADMIN_USERNAME: process.env.ADMIN_USERNAME ? '[SET]' : '[NOT SET]',
//     ADMIN_PASSWORD: process.env.ADMIN_PASSWORD ? '[SET]' : '[NOT SET]',
//     JWT_SECRET_KEY: process.env.JWT_SECRET_KEY ? '[SET]' : '[NOT SET]'
// });

// // 确保上传目录存在
// const uploadDir = path.join(__dirname, 'public/images');
// if (!fs.existsSync(uploadDir)) {
//     fs.mkdirSync(uploadDir, { recursive: true });
// }

// // 文件上传配置
// const storage = multer.diskStorage({
//     destination: function (req, file, cb) {
//         cb(null, uploadDir);
//     },
//     filename: function (req, file, cb) {
//         const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
//         const ext = path.extname(file.originalname);
//         cb(null, 'upload-' + uniqueSuffix + ext);
//     }
// });

// const upload = multer({
//     storage: storage,
//     limits: {
//         fileSize: 5 * 1024 * 1024 // 5MB limit
//     },
//     fileFilter: (req, file, cb) => {
//         if (!file.mimetype.startsWith('image/')) {
//             return cb(new Error('只允许上传图片文件'), false);
//         }
//         cb(null, true);
//     }
// });

// // 中间件配置
// app.use(cors());
// app.use(express.json());
// app.use(compression());
// app.use(helmet({
//     contentSecurityPolicy: false,
// }));
// app.use(morgan('dev'));
// app.use(express.static('public'));

// // 身份验证中间件
// const authenticateToken = (req, res, next) => {
//     try {
//         const authHeader = req.headers['authorization'];
//         if (!authHeader) {
//             return res.status(401).json({ error: '未提供认证令牌' });
//         }

//         const token = authHeader.split(' ')[1];
//         const decoded = jwt.verify(token, JWT_SECRET_KEY);
//         req.user = decoded;
//         next();
//     } catch (error) {
//         console.error('认证错误:', error);
//         return res.status(403).json({ error: '无效的认证令牌' });
//     }
// };

// // 数据操作函数
// async function readNavigationData() {
//     const dataPath = path.join(__dirname, 'public/data/navigation_data.json');
//     try {
//         const data = await fsPromises.readFile(dataPath, 'utf8');
//         return JSON.parse(data);
//     } catch (error) {
//         if (error.code === 'ENOENT') {
//             // 如果文件不存在，创建空的数据结构
//             const emptyData = { cards: [] };
//             await fsPromises.mkdir(path.dirname(dataPath), { recursive: true });
//             await fsPromises.writeFile(dataPath, JSON.stringify(emptyData, null, 2));
//             return emptyData;
//         }
//         throw error;
//     }
// }

// async function saveNavigationData(data) {
//     const dataPath = path.join(__dirname, 'public/data/navigation_data.json');
//     await fsPromises.mkdir(path.dirname(dataPath), { recursive: true });
//     await fsPromises.writeFile(dataPath, JSON.stringify(data, null, 2), 'utf8');
// }

// // 登录路由
// app.post('/api/login', async (req, res) => {
//     const { username, password } = req.body;
    
//     // 添加调试日志
//     console.log('Login attempt for username:', username);
//     console.log('Environment variables loaded:', {
//         ADMIN_USERNAME: process.env.ADMIN_USERNAME,
//         JWT_SECRET_KEY: process.env.JWT_SECRET_KEY ? '[SET]' : '[NOT SET]'
//     });

//     // 对输入密码进行哈希
//     const hashedInputPassword = crypto.createHash('sha256').update(password).digest('hex');
//     const hashedStoredPassword = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest('hex');
    
//     // 添加密码比较日志
//     console.log('Password comparison:', {
//         inputHash: hashedInputPassword.substring(0, 10) + '...',
//         storedHash: hashedStoredPassword.substring(0, 10) + '...',
//         matches: hashedInputPassword === hashedStoredPassword
//     });

//     if (username === ADMIN_USERNAME && hashedInputPassword === hashedStoredPassword) {
//         const token = jwt.sign({ username }, JWT_SECRET_KEY, { expiresIn: '24h' });
//         console.log('Login successful for user:', username);
//         res.json({ token });
//     } else {
//         console.log('Login failed. Invalid credentials.');
//         res.status(401).json({ error: '用户名或密码错误' });
//     }
// });

// // 验证令牌
// app.use('/api/verify-token', authenticateToken, (req, res) => {
//     res.json({ valid: true, user: req.user });
// });

// // 卡片管理路由
// app.get('/api/cards', async (req, res) => {
//     try {
//         const data = await readNavigationData();
//         res.json(data);
//     } catch (error) {
//         console.error('获取数据失败:', error);
//         res.status(500).json({ error: '获取数据失败' });
//     }
// });

// app.post('/api/cards', authenticateToken, async (req, res) => {
//     try {
//         const data = await readNavigationData();
//         const newCard = req.body;
//         newCard.id = Math.max(0, ...data.cards.map(c => c.id)) + 1;
//         data.cards.push(newCard);
//         await saveNavigationData(data);
//         res.json(newCard);
//     } catch (error) {
//         console.error('添加卡片失败:', error);
//         res.status(500).json({ error: '添加卡片失败' });
//     }
// });

// app.put('/api/cards/:id', authenticateToken, async (req, res) => {
//     try {
//         const data = await readNavigationData();
//         const id = parseInt(req.params.id);
//         const index = data.cards.findIndex(card => card.id === id);
        
//         if (index === -1) {
//             return res.status(404).json({ error: '卡片不存在' });
//         }

//         const updatedCard = { ...req.body, id };
//         data.cards[index] = updatedCard;
//         await saveNavigationData(data);
//         res.json(updatedCard);
//     } catch (error) {
//         console.error('更新卡片失败:', error);
//         res.status(500).json({ error: '更新卡片失败' });
//     }
// });

// app.delete('/api/cards/:id', authenticateToken, async (req, res) => {
//     try {
//         const data = await readNavigationData();
//         const id = parseInt(req.params.id);
//         data.cards = data.cards.filter(card => card.id !== id);
//         await saveNavigationData(data);
//         res.json({ message: '删除成功' });
//     } catch (error) {
//         console.error('删除卡片失败:', error);
//         res.status(500).json({ error: '删除卡片失败' });
//     }
// });

// app.post('/api/cards/reorder', authenticateToken, async (req, res) => {
//     try {
//         const { order } = req.body;
//         const data = await readNavigationData();
//         const reorderedCards = order.map(id => 
//             data.cards.find(card => card.id === parseInt(id))
//         ).filter(Boolean);
        
//         data.cards = reorderedCards;
//         await saveNavigationData(data);
//         res.json({ message: '排序更新成功' });
//     } catch (error) {
//         console.error('更新排序失败:', error);
//         res.status(500).json({ error: '更新排序失败' });
//     }
// });

// // 文件上传路由
// app.post('/api/upload', authenticateToken, upload.single('image'), (req, res) => {
//     try {
//         if (!req.file) {
//             return res.status(400).json({ error: '没有上传文件' });
//         }
//         const imageUrl = `/images/${req.file.filename}`;
//         res.json({ url: imageUrl });
//     } catch (error) {
//         console.error('文件上传失败:', error);
//         res.status(500).json({ error: '文件上传失败' });
//     }
// });

// // 错误处理中间件
// app.use((err, req, res, next) => {
//     console.error('服务器错误:', err);
    
//     if (err instanceof multer.MulterError) {
//         if (err.code === 'LIMIT_FILE_SIZE') {
//             return res.status(400).json({ error: '文件大小不能超过5MB' });
//         }
//         return res.status(400).json({ error: '文件上传失败' });
//     }
    
//     res.status(500).json({ error: '服务器内部错误' });
// });

// // 启动服务器
// app.listen(PORT, () => {
//     console.log(`服务器运行在 http://localhost:${PORT}`);
// });
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const fsPromises = require('fs/promises');
const path = require('path');
const compression = require('compression');
const helmet = require('helmet');
const morgan = require('morgan');
const multer = require('multer');

const app = express();

// 环境变量配置
const PORT = process.env.PORT || 3000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// 启动时验证环境变量
console.log('Environment check:', {
    ADMIN_USERNAME: process.env.ADMIN_USERNAME ? '[SET]' : '[NOT SET]',
    ADMIN_PASSWORD: process.env.ADMIN_PASSWORD ? '[SET]' : '[NOT SET]'
});

// 确保上传目录存在
const uploadDir = path.join(__dirname, 'public/images');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// 文件上传配置
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, 'upload-' + uniqueSuffix + ext);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: (req, file, cb) => {
        if (!file.mimetype.startsWith('image/')) {
            return cb(new Error('只允许上传图片文件'), false);
        }
        cb(null, true);
    }
});

// 中间件配置
app.use(cors());
app.use(express.json());
app.use(compression());
app.use(helmet({
    contentSecurityPolicy: false,
}));
app.use(morgan('dev'));
app.use(express.static('public'));

// 身份验证中间件
const authenticateRequest = (req, res, next) => {
    const username = req.headers.username;
    const password = req.headers.password;
    
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        next();
    } else {
        res.status(401).json({ error: '未经授权的访问' });
    }
};

// 数据操作函数
async function readNavigationData() {
    const dataPath = path.join(__dirname, 'public/data/navigation_data.json');
    try {
        const data = await fsPromises.readFile(dataPath, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            const emptyData = { cards: [] };
            await fsPromises.mkdir(path.dirname(dataPath), { recursive: true });
            await fsPromises.writeFile(dataPath, JSON.stringify(emptyData, null, 2));
            return emptyData;
        }
        throw error;
    }
}

async function saveNavigationData(data) {
    const dataPath = path.join(__dirname, 'public/data/navigation_data.json');
    await fsPromises.mkdir(path.dirname(dataPath), { recursive: true });
    await fsPromises.writeFile(dataPath, JSON.stringify(data, null, 2), 'utf8');
}

// 登录路由
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    console.log('Login attempt for username:', username);
    console.log('Environment variables loaded:', {
        ADMIN_USERNAME: process.env.ADMIN_USERNAME,
        ADMIN_PASSWORD: '[HIDDEN]'
    });

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        console.log('Login successful for user:', username);
        res.json({ success: true });
    } else {
        console.log('Login failed. Invalid credentials.');
        res.status(401).json({ error: '用户名或密码错误' });
    }
});

// 卡片管理路由
app.get('/api/cards', async (req, res) => {
    try {
        const data = await readNavigationData();
        res.json(data);
    } catch (error) {
        console.error('获取数据失败:', error);
        res.status(500).json({ error: '获取数据失败' });
    }
});

app.post('/api/cards', authenticateRequest, async (req, res) => {
    try {
        const data = await readNavigationData();
        const newCard = req.body;
        newCard.id = Math.max(0, ...data.cards.map(c => c.id)) + 1;
        data.cards.push(newCard);
        await saveNavigationData(data);
        res.json(newCard);
    } catch (error) {
        console.error('添加卡片失败:', error);
        res.status(500).json({ error: '添加卡片失败' });
    }
});

app.put('/api/cards/:id', authenticateRequest, async (req, res) => {
    try {
        const data = await readNavigationData();
        const id = parseInt(req.params.id);
        const index = data.cards.findIndex(card => card.id === id);
        
        if (index === -1) {
            return res.status(404).json({ error: '卡片不存在' });
        }

        const updatedCard = { ...req.body, id };
        data.cards[index] = updatedCard;
        await saveNavigationData(data);
        res.json(updatedCard);
    } catch (error) {
        console.error('更新卡片失败:', error);
        res.status(500).json({ error: '更新卡片失败' });
    }
});

app.delete('/api/cards/:id', authenticateRequest, async (req, res) => {
    try {
        const data = await readNavigationData();
        const id = parseInt(req.params.id);
        data.cards = data.cards.filter(card => card.id !== id);
        await saveNavigationData(data);
        res.json({ message: '删除成功' });
    } catch (error) {
        console.error('删除卡片失败:', error);
        res.status(500).json({ error: '删除卡片失败' });
    }
});

app.post('/api/cards/reorder', authenticateRequest, async (req, res) => {
    try {
        const { order } = req.body;
        const data = await readNavigationData();
        const reorderedCards = order.map(id => 
            data.cards.find(card => card.id === parseInt(id))
        ).filter(Boolean);
        
        data.cards = reorderedCards;
        await saveNavigationData(data);
        res.json({ message: '排序更新成功' });
    } catch (error) {
        console.error('更新排序失败:', error);
        res.status(500).json({ error: '更新排序失败' });
    }
});

// 文件上传路由
app.post('/api/upload', authenticateRequest, upload.single('image'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: '没有上传文件' });
        }
        const imageUrl = `/images/${req.file.filename}`;
        res.json({ url: imageUrl });
    } catch (error) {
        console.error('文件上传失败:', error);
        res.status(500).json({ error: '文件上传失败' });
    }
});

// 错误处理中间件
app.use((err, req, res, next) => {
    console.error('服务器错误:', err);
    
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: '文件大小不能超过5MB' });
        }
        return res.status(400).json({ error: '文件上传失败' });
    }
    
    res.status(500).json({ error: '服务器内部错误' });
});

// 启动服务器
app.listen(PORT, () => {
    console.log(`服务器运行在 http://localhost:${PORT}`);
});