require('dotenv').config();
const http = require("http");
const express = require("express");
const connectDB = require('./services/database');
const multer = require("multer");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");                  
const cors = require('cors'); 
const winston = require('winston'); 
const PORT = process.env.PORT || 3000;
const globalError = require('./middlewares/errorMiddleware');
const ApiError = require('./utils/apiError');

const app = express();
const server = http.createServer(app);

const userRoute = require("./routes/userRoute")
const authRoute = require("./routes/authRoute")


const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});



const fileStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'images');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype === 'image/jpg' || file.mimetype === 'image/jpeg' || file.mimetype === 'image/png') {
    cb(null, true);
  } else {
    cb(null, false);
  }
};
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? [process.env.DOMAIN_URl1, process.env.DOMAIN_URl2] 
    : '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));


app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());


// تسجيل الطلبات
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
  console.log(`mode: ${process.env.NODE_ENV}`)
} else {
  app.use(morgan('combined', {
    console: { write: message => logger.info(message.trim()) },
    file: { write: message => logger.info(message.trim()) },
    stream: { write: message => logger.info(message.trim()) }
    
  }));
}


app.use("/test", (req, res) => {
  console.log("hey in the url");
})

app.use((error, req, res, next) => {
  console.error(error);
  const status = error.statusCode || 500;
  const message = error.message || 'Internal Server Error';
  const data = error.data || null;
  logger.error(`Error ${status}: ${message}`, { data });
  res.status(status).json({ message, data });
});

connectDB();

app.use('/user', userRoute)
app.use('/', authRoute)

app.all('*', (req, res, next) => {
  next(new ApiError(`Can't find this route: ${req.originalUrl}`, 400));
});


app.use(globalError);

const port = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`App Server running on port ${PORT}`);
});

// Handle rejection outside express
process.on('unhandledRejection', (err) => {
  console.error(`UnhandledRejection Errors: ${err.name} | ${err.message}| ${err.stack}`);
  server.close(() => {
    console.error(`Shutting down....`);
    // process.exit(1);
  });
});
