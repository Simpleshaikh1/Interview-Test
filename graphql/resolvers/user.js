app.use('/graphql', graphqlHTTP({
    
rootValue: {

    Signup:  async (req, res, next) => {

        const {username, email, password} = req.body;
        const emailExist = await User.findOne({email});
      
        if (emailExist) {
          // return next(new BadRequestError("Email already exists"));
         return res.status(404).json({
            msg:"Email Already exist"
          })
          }
          
        
        const verifyToken =  crypto.randomBytes(2).toString("hex");
        // console.log(1)
      
        const newHost = await User.create({
          username,
          email,
          password,
          verifyToken
        });
      
        
        // send Email
         //send mail
         mailTransport.sendMail({
          from: "noreply@gmail.com",
          to: newHost.email,
          subject: "verify you email account",
          html: `<h4> Hello, ${email}, kindly verify your account with this token: ${verifyToken}</h4>`,
      });
      
      res.status(StatusCodes.CREATED).json({
        msg: "Success! Please check your email to verify account",
        user: newHost
      });
      
      
      },

      //verify the user
 verifyEmail: async (req, res, next) => {
    const {verifyToken, email} = req.body
  
    const user = await User.findOne({ email });
    if (!user) {
      // return next(UnauthenticatedError("Verification Failed"))
     return next(new UnauthenticatedError("Verification Failed"));
      // return res.status(StatusCodes.BAD_REQUEST).json({
      //   msg:"verification failed"
      // })
    }
  
    if (user.verifyToken !== verifyToken) {
      return next(new UnauthenticatedError("Verification Failed"));
      // res.status(StatusCodes.NOT_ACCEPTABLE).json({
      //   msg:"Incorrect Token"
      // })
      // console.log(1)
    }
  
    (user.confirmed = true);
    // console.log(1);
    user.verifyToken = "";
    
    await user.save();
  
    res.status(StatusCodes.OK).json({ msg: "Email Verified" });
  },
  login: async (req, res, next) => {
    const { email, password } = req.body;
    // console.log(2);
    //check if email and password exist
    if (!email || !password) {
    //  return next(new BadRequestError(`Please provide username or password`));
      return res.status(StatusCodes.BAD_REQUEST).json({ msg: "Please provide username or password" });
    }
  
    //check if user is existing and the user password is correct
    const user = await User.findOne({ email });
  
    if (!user) {
    //  return next(new BadRequestError(`Invalid Credentials`));
    res.status(StatusCodes.NOT_FOUND).json({ msg: "This user does not exist" });
    }
    const isPasswordCorrect = await user.comparePasswords(password);
    // // console.log(isPasswordCorrect)
    // const compare = await bcrypt.compare(password, user.password)
    if (!isPasswordCorrect) {
          // return next(new BadRequestError(`Invalid Credentials`)) ;
          res.status(StatusCodes.BAD_REQUEST).json({ msg: "Invalid Credentials" });
    }
  
    if (!user.confirmed) {
      // return next(new UnauthenticatedError("Please verify your email"));
      return res.status(StatusCodes.UNAUTHORIZED).json({ msg: "Please verify your email" });
    }
  
    let token = user.signedJwtToken(user._id);
  
    const oneDay = 1000 * 60 * 60 * 24;
  
      res.cookie("token", token, {
          httpOnly: true,
          expires: new Date(Date.now() + oneDay),
      });
  
      res.status(StatusCodes.OK).json({ msg: "Login Successful", token: token });
    
  },
   logOut : async (req, res) => {
    res.cookie("token", "loggedOut", {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true,
    });
    res.status(StatusCodes.OK).json({ msg: "user logged out!" }); 
  },
   protect:async (req, res, next) => {
    // check header
    //confirm if token is available after getting it
    let token;
    console.log(req.headers, req.cookies.jwt)
  
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    } else if (req.cookies.jwt) {
      token = req.cookies.jwt;
    }
    // console.log(token)
    if (!token) {
      // return next(new EventError("UnAuthorized to access this route", 401));
      // return next(new UnauthenticatedError("You are unAuthorized to access this route"));
      return res.status(404).json({
        msg:"You are unauthorized to access this route"
      })
    }
  
    // 2) Verification token
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
    // console.log(decoded.id);
  
    // 3) Check if user still exists
    const currentUser = await User.findById(decoded.id);
    // console.log(currentUser);
    if (!currentUser) {
      // return next(new AppError("Token not found or invalid", 401));
      // return next ( new BadRequestError(`Token not found or invalid`));
      return res.status(StatusCodes.BAD_REQUEST).json({
        msg:"Token not Found or Invalid"
      })
    }
    // 4) Check if user changed password after the token was assigned
    if (currentUser.changedPasswordAfter(decoded.iat)) {
        // new AppError("User recently changed password! Please log in again.", 401)
        // return next(new UnauthenticatedError("User recently changed password! please log in again"));
        return res.status(StatusCodes.EXPECTATION_FAILED).json({
          msg:"User recently changed password! please log in again"
        })
    }
  
    // Grant access to protected route
    req.user = currentUser;
    // console.log(req.user.id);
    res.locals.user = currentUser;
    
    next()
  },
  restrictTo: (...role) => {
    return (req, res, next) => {
      if (!role.includes(req.user.role)) {
          // new EventError("You do not have permision to perform this aciton", 403)
          // return next(new BadRequestError(`You do not have permission to perform this action`));
          return res.status(StatusCodes.BAD_REQUEST).json({ msg: "You do not have permission to perform this action" });
          
      }
      next();
    };
  },
  forgetPassword: async (req, res, next) => {
    //get user based on email
    const { email } = req.body;
    if (!email) return res.status(StatusCodes.BAD_REQUEST).json({ msg: "Please provide valid email" });
    const user = await User.findOne({ email });
    if (user){
      const passwordResetToken = crypto.randomBytes(4).toString("hex");
      // console.log(passwordResetToken)
  
      mailTransport.sendMail({
        from: "noreply@gmail.com",
        to: email,
        subject: "Reset you account",
        html: `<h4>Hi, kindly reset your password with this token: ${passwordResetToken}</h4>`,
    });
  
        const tenMinutes = 1000 * 60 * 10;
        const passwordResetExpires = new Date(Date.now() + tenMinutes);
        // const resetToken = user.newTokenCreate()
  
        user.passwordResetToken = passwordResetToken;
        user.passwordResetExpires = passwordResetExpires;
        await user.save();
  }
  
  res.status(StatusCodes.OK).json({
    msg: "Please check your email for reset password link",
    token:passwordResetToken
  });
    
  },
  resetPassword: async (req, res, next) => {
    //get user base on token
    const {token, email, password} = req.body;
    if (!token || !email || !password) {
      // return next(new BadRequestError("Please provide all values"));
     return res.status(StatusCodes.BAD_REQUEST).json({ msg: "Please provide all values" });
    }
    const user = await User.findOne({email});
  
    // 2) If token has not expired, and there is user, set the new password
    
      const currentDate = new Date();
  
      if (
          user.passwordResetToken === createRandomBytes(token) &&
          user.passwordResetExpires > currentDate
      ) {
          user.password = password;
          user.passwordResetToken = null;
          user.passwordResetExpires = null;
          await user.save();
      }
  
  
  res.status(StatusCodes.OK).json({msg:"Password reset Successfully"});
  },
  updatePassword:  async (req, res) => {
    //  Get user from collection
    // console.log(1)
    const user = await User.findById(req.user.id).select("+password");
    
  
    // Check if its posted, curent passcode is correct
    if (!(await user.comparePasswords(req.body.currentPassword, user.password))) {
      // return next(new EventError("Your current password is wrong.", 401));
      return res.status(StatusCodes.BAD_REQUEST).json({ msg: "Your current password is wrong" });
    }
  
    // update password
    user.password = req.body.password;
    await user.save();
  
    // Log user in, send TOken
    res.status(200).json({
      user:user
    })
    // createSendToken(user, 200, req, res);
  }
},

}))