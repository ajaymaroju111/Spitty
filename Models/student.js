const mongoose = require('mongoose');


const StudentSchema = new mongoose.Schema({
  name : {
    type : String,
    required : false,
  },
  image : {
    data: Buffer,
    contentType: String
  }

  
});

module.exports = mongoose.model('student' , StudentSchema);