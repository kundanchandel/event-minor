var express = require('express');
      router=express.Router();
      bcrypt=require('bcrypt');

const User=require('../../models/UserModel');

router.post("/register",async (req,res) => {
    console.log(req.body)
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


module.exports=router;