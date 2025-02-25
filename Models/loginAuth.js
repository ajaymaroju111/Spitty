const mongoose = require('mongoose');

const LoginSchema = new mongoose.Schema({
  id : {
    type : String,
  },
  token : {
    type : String,
  },
  expiriryDate : {
    type : Date,
  }
});

module.exports = mongoose.model('loginData' , LoginSchema)