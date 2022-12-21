
require("dotenv").config();
const nodemailer = require("nodemailer");


const mailTransport = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 465,
        secure: true,
        auth: {
            user: process.env.EMAIL_USERNAME,
            pass: process.env.EMAIL_PASSWORD,
        },
        tls:{
            rejectUnauthorized:false,
        },
    });
    mailTransport.verify(function(error, success){
        if(error){
            console.log(error)
        }else{
            console.log('Server is ready')
        }
    })


    module.exports = mailTransport
