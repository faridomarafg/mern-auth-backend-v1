const User = require('../models/User');
const jwt = require('jsonwebtoken');
const asyncHandler = require('express-async-handler');


const protect = asyncHandler(async(req, res, next)=>{
      try {
        // check the request come from front-end has token with cookie;
         const token  = req.cookies.token;// this .token is the name of our token in userController;
         if(!token) return res.status(401).json({message: 'Not authorized please login!'});

         //verify token
         const verifiedToken = jwt.verify(token, process.env.JWT_SECRET);

         //GET UER FROM TOKEN
         const user = await User.findById(verifiedToken.id).select('-password');
         if(!user) return res.status(404).json({message: 'User not found!'});

         req.user = user;

         next()
      } catch (error) {
        res.status(401).json({message: 'Not authorized, Please login!'})
      }   
});

module.exports = protect