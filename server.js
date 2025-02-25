const express = require('express')
const connectionDB = require('./Databases/dbConeection.js')
const dotenv = require('dotenv')
const authRoutes = require('./Routes/authRoutes.js')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')

dotenv.config();
const PORT = process.env.PORT || 8074;
const app = express();
connectionDB();
app.use(bodyParser.json());


//middlewares : 
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({extended : false}))

app.use('/' , authRoutes);

app.listen(PORT, ()=>{
  console.log(`The Server is running on the port : ${PORT}`);
})
