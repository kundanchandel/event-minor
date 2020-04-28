var express = require('express');
      router=express.Router();
      bcrypt=require('bcrypt');
  Validator = require("validator");
    isEmpty = require("is-empty");
    jwt     =require("jsonwebtoken")

const User=require('../../models/UserModel');

router.post("/register",async (req,res) => {
    const { errors, isValid } = validateRegister(req.body);
    if (!isValid) {
        return res.status(400).json(errors);
    }
    User.findOne({email:req.body.email}).then( async user=>{
        if (user) {
            return res.status(400).json({ email: "Email already exists" });
          } else {
            const salt = await bcrypt.genSalt(10);
            const hashedPassword =await  bcrypt.hash(req.body.password,salt);
            const newUser = new User({
                username: req.body.username,
                email: req.body.email,
                password: hashedPassword
                });
            newUser.save().then(user=>res.json(user))
        }
    });
});

router.post("/login", async (req,res)=>{
    console.log(req.body)
    const { errors, isValid } = validateLogin(req.body);
    // Check validation
    if (!isValid) {
        return res.status(400).json(errors);
    }
    const user = await User.findOne({email:req.body.email});
    if (!user) {
        return res.status(404).json({ emailnotfound: "Email not found" });
    }
    const validpass =await bcrypt.compare(req.body.password,user.password);
    if(!validpass){
        return res.status(400).json({ passwordincorrect: "Password incorrect" });
    }else{
        const token = jwt.sign({_id:user._id},process.env.TOKEN_SECRET,{
            expiresIn: 31556926 // 1 year in seconds
          });
          res.json({
            success: true,
            token:token
          });
    }
});


function validateRegister(data) {
    let errors = {};
  // Convert empty fields to an empty string so we can use validator functions
    data.username = !isEmpty(data.username) ? data.username : "";
    data.email = !isEmpty(data.email) ? data.email : "";
    data.password = !isEmpty(data.password) ? data.password : "";
    data.confirmPassword = !isEmpty(data.confirmPassword) ? data.confirmPassword : "";
  // Name checks
    if (Validator.isEmpty(data.username)) {
      errors.username = "Name field is required";
    }
  // Email checks
    if (Validator.isEmpty(data.email)) {
      errors.email = "Email field is required";
    } else if (!Validator.isEmail(data.email)) {
      errors.email = "Email is invalid";
    }
  // Password checks
    if (Validator.isEmpty(data.password)) {
      errors.password = "Password field is required";
    }
  if (Validator.isEmpty(data.confirmPassword)) {
      errors.confirmPassword = "Confirm password field is required";
    }
  if (!Validator.isLength(data.password, { min: 6, max: 30 })) {
      errors.password = "Password must be at least 6 characters";
    }
  if (!Validator.equals(data.password, data.confirmPassword)) {
      errors.confirmPassword = "Passwords must match";
    }
  return {
      errors,
      isValid: isEmpty(errors)
    };
};

function validateLogin(data) {
    let errors = {};
  // Convert empty fields to an empty string so we can use validator functions
    data.email = !isEmpty(data.email) ? data.email : "";
    data.password = !isEmpty(data.password) ? data.password : "";
  // Email checks
    if (Validator.isEmpty(data.email)) {
      errors.email = "Email field is required";
    } else if (!Validator.isEmail(data.email)) {
      errors.email = "Email is invalid";
    }
  // Password checks
    if (Validator.isEmpty(data.password)) {
      errors.password = "Password field is required";
    }
  return {
      errors,
      isValid: isEmpty(errors)
    };
  };

module.exports=router;