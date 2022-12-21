const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const validator = require('validator');
const crypto = require('crypto');


const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, "Please provide name"],
        minlength: 3,
        maxlength: 50,
        unique: true,
    },
    email: {
        type: String,
        required: [true, 'Please provide a valid email'],
        unique: [true, 'Email already exist in our database'],
        lowercase:true,
        // validate: [validator.isEmail, 'Please provide a valid email'],
    },
    password: {
        type: String,
        required: [true, 'Please provide a password'],
        minlength: 8,
        // select: false
      },
    // confirmPassword: {
    //     type: String,
    //     // required: [true, 'Please confirm your password'],
    //     validate: {
    //       // This will only work for CREATE && SAVE!!
    //       validator: function(el) {
    //         return el === this.password;
    //       },
    //       message: 'Passwords are not the same'
    //     }
    //   },
    confirmed:{
        type:Boolean,
        default:false,
        required:true
    },
    confirm:{
        type:Date
    },
    isAdmin: {
        type:Boolean,
        default: false
      },
    masterUser:{
        type:Boolean,
        default:false
    },
    isTrash:{
        type:Boolean,
        default:false
    },
    role:{
        type:String,
        enum:[
            'admin',
            'user'
        ],
        default:'user'

    },
    // ticketSchema_id:[
    // {
    //     type:mongoose.Schema.Types.ObjectId,
    //     ref:"Ticket"
    // }

    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,
    verifyToken: String,
    verifyEmailExpires: Date,

    otp:Number
},

{
    timestamps:true,
    toJSON: {virtuals: true},
    toObject: {virtuals: true}
}

);

//populate virtually
// userSchema.virtual('eventlist', {
//     ref: 'Event',
//     foreignField: 'user',
//     localField: '_id',
//     justOne: false
//   });

// method for bcrypt password
UserSchema.pre("save", async function(next){
    if(!this.isModified('password')){
        return next()
    }
    const salt = await bcrypt.genSalt(10);
    this.password =  await bcrypt.hash(this.password, salt);

    // this.confirmPassword = undefined
    next();
});

UserSchema.pre("save", function(next){
    if(!this.isModified('password') || this.isNew) return next();

    this.passwordChangedAt = Date.now() - 1000

    next();
})

// check for active account
UserSchema.pre(/^find/, function(next){
    // present query
    this.find({active:{$ne:false}});
    next();

})

//compare bcrypt
UserSchema.methods.comparePasswords = async function(candidatePassword){
  const isMatch = await bcrypt.compare(candidatePassword, this.password);
  return isMatch;
}

UserSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
    if(this.passwordChangedAt) {
      const changedTimeStamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
  
      return JWTTimestamp < changedTimeStamp; // returns true or false
    };
  
    //  NOT changed
    return false;
  };



UserSchema.methods.newTokenCreate = function() {
    const resetToken = crypto.randomBytes(32).toString('hex');

    this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex')
    this.passwordResetExpires = Date.now() + 10 * 60 * 100;
    // console.log({resetToken}, this.passwordResetToken )

    return resetToken;
}

//email confirmation 
//
UserSchema.methods.confrimedEmailVerification = function() {
    const verifyToken = crypto
      .randomBytes(32)
      .toString('hex');
  
    this.verifyEmailToken = crypto
      .createHash('sha256')
      .update(verifyToken)
      .digest('hex');
  
    this.verifyEmailExpires = Date.now() + 10 * 60 * 1000;
  
    return verifyToken;
  }

//jwt signed token
UserSchema.methods.signedJwtToken =function(id){
    return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_LIFETIME
    })
    // UserSchema.methods.signedJwtToken =function(id){
    //     return jwt.sign({userId:this.id, email:this.email}, process.env.JWT_SECRET, {
    //         expiresIn: process.env.JWT_LIFETIME
    //     })
}


const User = mongoose.model("User", UserSchema)
module.exports= User;



