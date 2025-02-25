const mongoose = require('mongoose')
const dotenv = require('dotenv')
dotenv.config();
// Connecting to LOCAL database

const connectionDB = async () => {
  try {
    const conn = await mongoose.connect(
      process.env.LOCAL_MONGOURL, // Use your connection string
      {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      }
    );
    console.log('MongoDB connected:', conn.connection.host);
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
    process.exit(1); // Exit the process if the connection fails
  }
};


module.exports =  connectionDB;
