const express = require('express')
const rateLimit = require("express-rate-limit");
const helmet = require("helmet"); 
const morgan = require("morgan");  
const cors = require("cors");
require("express-async-errors");
const xss = require("xss-clean");
const {buildSchema, GraphQLSchema, GraphQLObjectType } = require('graphql')

require('dotenv').config()

const connectDB = require('./db/connect')

const app = express()

// error handler
const notFoundMiddleware = require("../middleware/notFound");
const errorHandlerMiddleware = require("../middleware/errorHandler");
const { graphql } = require('graphql');


//Development logging
if (process.env.NODE_ENV === "production") {
    app.use(morgan("dev"));
  }

app.use(express.json());
app.use(cors());

//securtiy http header
app.use(helmet());  


const limiter = rateLimit({
    max: 500,
    windowMs: 60 * 60 * 1000,
    message:
      "Too many request from this IP address! Please try again later in one Hour",
  });
  
  app.use("/api", limiter);

  app.use(cookieParser());

  // Data sanitization against XSS
app.use(xss()); // Clean malicious HTML code

app.use(errorHandlerMiddleware);
app.use(notFoundMiddleware);

app.use('/graphql', graphqlHTTP({
    schema,
    graphql:true,
}))



const PORT = process.env.PORT || 5000;

const start = async () => {
  try {
    await connectDB(process.env.MONGO_URL); 
    app.listen(PORT, () => {
      console.log(`Server listening to port ${PORT}...`);
      console.log("DB is connected and running");
    });
  } catch (error) {
    console.log(error);
  }
};

start();
