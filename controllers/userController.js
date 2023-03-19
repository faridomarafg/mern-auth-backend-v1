const User = require('../models/User');
const asyncHandler = require('express-async-handler');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const Token = require('../models/tokenModel');
const crypto = require('crypto');
const sendEmail = require('../utils/sendEmail');

//Generate token;
const generateToken = (id)=>{
    return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: '1d'
    })
}


const registerUser = asyncHandler(async (req, res)=>{
      const {name, email, password,photo} = req.body;
      if(!name || !email || !password) return res.status(400).json({message: 'name email and password required!'});
      if(!photo) return res.status(400).json({message: 'Please Select a Profile Image!'});

      //check for duplicate
      const duplicate = await User.findOne({ email });
      if(duplicate) return res.status(409).json({message: 'Email already exist!'});

      //check for password length
      if(password.length <3) return res.status(400).json({message:'password must not be less than 3 characters!'});

      //create new user
      const user = await User.create({name, email, password, photo});
      console.log(req.body);
      //Generate Token
      const token = generateToken(user._id);

      //send http-only cookie to front end for valid login
      res.cookie('token', token, {
        path:'/',
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400),
        sameSite: 'none',
        //secure: true
      });

      if(user){
         res.status(201).json({
            name: user.name,
            email: user.email,
            id: user._id,
            photo: user.photo,
            phone: user.phone,
            bio: user.bio,
            token
         })
      }else{
        res.status(400).json({message: 'Invalid user data'})
      }
})

//Login user
const loginUser = asyncHandler(async (req, res)=>{
      const {email, password} = req.body;
      //confirm data
      if(!email || !password) return res.status(400).json({message: 'Email and password required'});

      //find user for login!
      const foundUser = await User.findOne({ email });
      if(!foundUser) return res.status(400).json({message: 'User not found!'});

      //validate user password
      const user = await bcrypt.compare(password, foundUser.password);

       //Generate Token
       const token = generateToken(foundUser._id);

       //send http-only cookie to front end for valid login
       res.cookie('token', token, {
         path:'/',
         httpOnly: true,
         expires: new Date(Date.now() + 1000 * 86400),
         sameSite: 'none',
         //secure: true
       });

      if(foundUser && user){
        res.status(200).json({
            name: foundUser.name,
            email: foundUser.email,
            id: foundUser._id,
            photo: foundUser.photo,
            phone: foundUser.phone,
            bio: foundUser.bio,
            token
         })
      }else{
          res.status(400).json({message: 'Invalid Password'})
      }
})

//Logout user
const logoutUser = asyncHandler(async (req, res)=>{
    res.cookie('token', '', {
        path:'/',
        httpOnly: true,
        expires: new Date(0),
        sameSite: 'none',
        //secure: true
      });

      return res.status(200).json({message: 'User logged out!'})
})



//Forgot Password
const forgotPassword =asyncHandler(async (req, res)=>{
    const { email } = req.body;
    const user = await User.findOne({ email });
    if(!user) return res.status(400).json({message:"User does not exist"}) 
    
    // Delete token if it exists in DB
    let token = await Token.findOne({ userId: user._id });
    if (token) {
      await token.deleteOne();
    }
  
    // Create Reste Token
    let resetToken = crypto.randomBytes(32).toString("hex") + user._id;
    console.log(resetToken);
  
    // Hash token before saving to DB
    const hashedToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");
  
    // Save Token to DB
    await new Token({
      userId: user._id,
      token: hashedToken,
      createdAt: Date.now(),
      expiresAt: Date.now() + 30 * (60 * 1000), // Thirty minutes
    }).save();
  
    // Create Reset Url
    const resetUrl = `${process.env.FRONTEND_URL}/resetpassword/${resetToken}`;
    // Reset Email properties!
    const message = `
        <h2>Hello ${user.name}</h2>
        <p>Please use the url below to reset your password</p>  
        <p>This reset link is valid for only 30minutes.</p>
        <a href=${resetUrl} clicktracking=off>${resetUrl}</a>
        <p>Regards...</p>
        <p>AFG -- DEVS/p>
      `;
    const subject = "Password Reset Request";
    const send_to = user.email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = 'Dont reply to this email!'
    try {
      await sendEmail(subject, message, send_to, sent_from, reply_to);
      res.status(200).json({ success: true, message: "Reset Email Sent" });
    } catch (error) {
      res.status(500);
      throw new Error("Email not sent, please try again");
    }
})

//Reset Password
const resetPassword = asyncHandler(async (req, res)=>{
      const { password }  = req.body;
      const { resetToken } = req.params;// params here is that long string of token; 
      console.log(req.body);
      
      //first we shoud convet [resetToken] to what which stored in database
      //Note: hash the token then compare it to the one in DB;
      const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
      
      //Find Token in DB;
      const userToken = await Token.findOne({
        token: hashedToken,
        expiresAt: {$gt: Date.now()}// $gt : means greater than,
      });
      if(!userToken) return res.status(400).json({message:'Invalid or expired token!'});

      //Find usr with it ID which stored in tokenModel, which is this one [userId];
      const user = await User.findOne({_id: userToken.userId});

      //when found user, now reset its password
      user.password = password;

      //save user with the changes wich done on it;
      await user.save();

      res.status(200).json({message: 'password reset successfully, pleas login'})
})


module.exports = {
     registerUser,
     loginUser,
     logoutUser,
     forgotPassword,
     resetPassword
}