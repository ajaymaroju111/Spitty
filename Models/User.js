const mongoose = require('mongoose')

const UserSchema = new mongoose.Schema({
  firstname : {
    type : String,
    required : true,
  },
  middlename : {
    type : String,
  },
  lastname : {
    type : String,
    required : true,
  },
  role : {
    type : String,
    enum :['user', 'admin' , 'partner'],
    default : 'user',
  },
  email : {
    type : String,
    requires : true,
    unique : true
  },
  password : {
    type : String,
    required : true
  },
  mobile : {
    type : Number,
    required : true,
    unique : true
  },
  city :{
    type : String,
    required : true,
  },
  state :{
    type : String,
    required : true,
  },
  district :{
    type : String,
    required : true,
  },
  pincode : {
    type : Number,
    required : true
  },
  status : {
    type : String,
    default : 'inactive',
    enum : ['inactive' , 'active'],
    required : true
  },
  registerotp : {
    type : String,
    default : "",
  },
  expiryTime : {
    type : Date,
  },
  loginotp : {
    type : String,
    default : ""
  },
  resetPasswordToken : {
   type : String,
   default : "",

  },
  image : {
    data: Buffer,
    contentType: String
  }
})

const User = mongoose.model('User' ,UserSchema)
module.exports =  User;