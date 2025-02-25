const express = require('express')
const router = express.Router();
const multer = require('multer')
const {userRegister , isvalidate, userLogin , LoginValidated ,forgetPassword ,verifyEmailToken , forgetPasswordUsingEmailandId, verifyToken, ImageUploadWithMulter, verifyTheToken} = require('../Controllers/authentication.js');
 
const storage = multer.memoryStorage(); // Store image in memory buffer
const upload = multer({ storage: storage });

//Routes for the requests for the user : 
router.get('/' ,() =>{
  res.json({message : "this is working user test"});
});
router.post('/register',userRegister);
router.post('/validate' , isvalidate);
router.post('/tokenvalidate' , );
router.post('/login' , userLogin);
router.get('getdatatbytoken' ,verifyToken , (req, res) => {
  res.json({ message: "Profile Accessed!", user: req.user });
})
router.post('/loginValidate' , LoginValidated);
router.post('/resetlink' , forgetPassword);
router.post('/resetlink2' , forgetPasswordUsingEmailandId);
router.post('/verifyresetlink' , verifyEmailToken);
router.post('/upload' , verifyTheToken, upload.single("image"), ImageUploadWithMulter);


module.exports =  router;