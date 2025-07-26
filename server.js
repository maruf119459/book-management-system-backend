const express = require("express");
const cors = require('cors');
const jwt = require("jsonwebtoken");
const { MongoClient, ObjectId } = require("mongodb");
const admin = require("firebase-admin");
const dotenv = require("dotenv");
dotenv.config();

const app = express();
app.use(express.json());

const allowedOrigins = [
  "http://localhost:3000",
  "https://book-management-system-frontend-self.vercel.app"
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (e.g., mobile apps, curl)
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'PUT'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

const PORT = process.env.PORT;
const onlyEmail = process.env.ONLY_EMAIL;
const secret = process.env.JWT_SECRET;


// Firebase Admin Init
admin.initializeApp({
  credential: admin.credential.cert({
    type: process.env.FIREBASE_TYPE,
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'), // fix newline issue
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: process.env.FIREBASE_AUTH_URI,
    token_uri: process.env.FIREBASE_TOKEN_URI,
    auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
    client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
    universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN
  })
});


const uri = process.env.MONGO_URI;
const client = new MongoClient(uri);

let db, users, books;
async function connectToDatabase() {
  try {
    await client.connect();
    db = client.db('BookManager');
    users = db.collection("users");
    books = db.collection("books");
    await books.createIndex({ title: 1 }, { unique: true });
    console.log("✅ Connected to MongoDB");
  } catch (error) {
    console.error("❌ MongoDB Connection Failed:", error);
    process.exit(1);
  }
}

function authenticateUser(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(403).send("Unauthorized");
  try {
    const decoded = jwt.verify(token, secret);
    if (decoded.email !== onlyEmail) return res.status(403).send("Forbidden");
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).send("Invalid token");
  }
}

app.get('/', (req, res) => {
  res.send('📚 Book Manager API is Running');
});

// Google login - Create JWT
app.post("/login", async (req, res) => {
  const { idToken } = req.body;
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    if (decodedToken.email !== onlyEmail) return res.status(403).send("Not allowed");

    const existUser = await users.findOne({ email: decodedToken.email });
    if (!existUser) {
      await users.insertOne({ email: decodedToken.email, firebaseUID: decodedToken.uid, createdAt: new Date() });
    }

    const token = jwt.sign({ email: decodedToken.email }, secret, { expiresIn: "24h" });
    res.json({ token });
  } catch (err) {
    res.status(401).send("Invalid Firebase Token");
  }
});

// ✅ Add book (title & url provided by user)
app.post("/books", authenticateUser, async (req, res) => {
  const { title, url } = req.body;
  if (!title) return res.status(400).send("Title is required");

  try {
    const user = await users.findOne({ email: req.user.email });
    const bookData = {
      userId: user._id,
      title,
      addedAt: new Date()
    };

    if (url) bookData.url = url;

    const result = await books.insertOne(bookData);
    res.json({ success: true, bookId: result.insertedId });
  } catch (err) {
    console.error("Add Book Error:", err);
    res.status(500).send("Failed to add book");
  }
});

// ✅ Update book
app.put("/books/:id", authenticateUser, async (req, res) => {
  const { title, url } = req.body;
  try {
    const updateFields = {};
    if (title) updateFields.title = title;
    if (url) updateFields.url = url;

    await books.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: updateFields }
    );
    res.send("Updated");
  } catch (err) {
    console.error("Update Error:", err);
    res.status(500).send("Failed to update book");
  }
});

// ✅ Delete book
app.delete("/books/:id", authenticateUser, async (req, res) => {
  try {
    await books.deleteOne({ _id: new ObjectId(req.params.id) });
    res.send("Deleted");
  } catch (err) {
    console.error("Delete Error:", err);
    res.status(500).send("Failed to delete book");
  }
});

// 🔍 Search book
app.get("/books/search", authenticateUser, async (req, res) => {
  const keyword = req.query.q || "";
  const data = await books.find({ title: { $regex: keyword, $options: "i" } }).toArray();
  res.json(data);
});

// 📖 Paginated book view
app.get("/books", authenticateUser, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 10;
  const skip = (page - 1) * limit;
  const data = await books.find().skip(skip).limit(limit).toArray();
  const total = await books.countDocuments();
  res.json({ books: data, totalPages: Math.ceil(total / limit) });
});

app.get('/books/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;

  try {
    const book = await books.findOne({ _id: new ObjectId(id) });  // ✅ Fix here
    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }
    res.json(book);
  } catch (err) {
    console.error("Fetch Book Error:", err);
    res.status(500).json({ message: 'Server error' });
  }
});

// 🚀 Start server
connectToDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
  });
});
