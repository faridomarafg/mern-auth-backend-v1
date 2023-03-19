require('dotenv').config();
const express = require('express');
const app = express();
const dbConnect = require('./config/dbConnect');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const PORT = process.env.PORT || 3500;

//connection to mongoDB
dbConnect();

// Middlewares
app.use(express.json({limit: '10mb'}));
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(
  cors({
    origin: ["http://localhost:3000","https://mern-auth-frontend-v1.onrender.com"],
    credentials: true,
  })
);




//Routes
app.use('/api/users', require('./routes/userRoutes'));

app.listen(PORT, ()=>{
    console.log(`app is running on Port ${PORT}`);
})