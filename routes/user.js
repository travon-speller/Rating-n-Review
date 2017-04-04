var async = require('async');
var nodemailer = require('nodemailer');
var smtpTransport = require('nodemailer-smtp-transport');
var bodyParser = require('body-parser');
var crypto = require('crypto');
var User = require('../models/user');
var secret = require('../secret/secret');

module.exports = (app, passport) => {
    
    app.get('/', function (req, res, next) {  
        if(req.session.cookie.originalMaxAge !== null){
            res.redirect('/home');
        }else{
            res.render('index', {title: 'RateMe'});
        }
    });
    
    app.get('/signup', function (req, res) {
      var errors = req.flash('error');
      res.render('user/signup', {title: 'Sign Up || RateMe', messages: errors, hasErrors: errors.length > 0});
    });

    app.post('/signup', validate, passport.authenticate('local.signup', {
        successRedirect: '/home',
        failureRedirect: '/signup',
        failureFlash: true
    }));
     
    app.get('/login', function (req, res) {
      var errors = req.flash('error');
      res.render('user/login', {title: 'Login || RateMe', messages: errors, hasErrors: errors.length > 0});
    });
     
    app.post('/login', loginvalidate, passport.authenticate('local.login', {
        failureRedirect: '/login',
        failureFlash: true
    }), (req, res) => {
        if(req.body.rememberme){
            req.session.cookie.maxAge = 10*24*60*60*1000; //10 days
        }else{
            req.session.cookie.expires = null;
        }
        
        res.redirect('/home');
    });
    
    app.get('/home', (req, res) => {
        res.render('home', {title: 'Home'});
    });
    
    app.get('/forgot', (req, res) => {
        var errors = req.flash('error');
        var info  = req.flash('info');
        res.render('user/forgot', {title: 'Password Reset', messages: errors, hasErrors: errors.length > 0, info: info, noErrors: info.length > 0});
    });
    
    app.post('/forgot', function(req, res, next) {
       async.waterfall([
           //create random number
           function(callback){
               crypto.randomBytes(20, (err, buf) => {
                   var rand = buf.toString('hex');
                   callback(err, rand);
               });
           },
           
           //if no user end else set rand into the token
           function(rand, callback){
               User.findOne({'email':req.body.email}, (err, user) => {
                   if(!user){
                       req.flash('error', 'Email not registered');
                       return res.redirect('/forgot');
                   }
                    req.checkBody('email', 'Email Is Required').notEmpty();
                    req.checkBody('email', 'Email is Invalid').isEmail();
                   
                   var errors = req.validationErrors();
                   
                   if(errors){
                    var messages = [];
                    errors.forEach((error) => {
                        messages.push(error.msg);
                    });
                       
                        var errors = req.flash('error', messages); res.redirect('/forgot');
                   }
                                   
                   user.passwordResetToken = rand;
                   user.passwordResetExpires = Date.now() + 60*60*1000;
                   
                   user.save(function(err) {
                       callback(err, rand, user)
                   });
               });
           },
           
           //create the email
           function(rand, user, callback) {
               var smtpTransport = nodemailer.createTransport({
                   service: 'Gmail',
                   auth: {
                       user: secret.auth.user,
                       pass: secret.auth.pass
                   }
               });
               
               var mailOptions = {
                   to: user.email,
                   from: 'RateMe '+'<'+secret.auth.user+'>',
                   subject: 'RateMe Password Reset',
                   text: 'You have requested a password reset token.  \n\n'+
                   'Please click on the link to complete the process: \n\n'+
                   'http://localhost:3000/reset/'+rand+'\n\n'
               }
               
               smtpTransport.sendMail(mailOptions, (err, response) => {
                   req.flash('info', 'A password reset token has been sent to '+ user.email)
                   return callback(err, user);
               });
           }
       ], function(err) {
           if(err){
               return next(err);
           }
           
           res.redirect('/forgot');
       });
    });
    
     app.get('/reset/:token', (req, res) => {
         User.findOne({passwordResetToken: req.params.token, passwordResetExpires: {$gt: Date.now()}}, (err, user) => {
             if(!user){
                 req.flash('error', 'Password Reset token has expired or invalid. Enter your email again to recieve a new token.')
                 return res.redirect('/forgot');
             }
           var error = req.flash('error');
           var success = req.flash('success');
           res.render('user/reset', {title: 'Reset Your Password', messages: error, hasErrors: error.length > 0, success: success, noErrors: success.length > 0});  
         }); 
    });
    
     app.post('/reset/:token', function(req, res) {
         async.waterfall([
             function(callback){
                User.findOne({passwordResetToken: req.params.token, passwordResetExpires: {$gt: Date.now()}}, (err, user) => {
             if(!user){
                 req.flash('error', 'Password Reset token has expired or invalid. Enter your email again to recieve a new token.')
                 return res.redirect('/forgot');
             }
                      
            req.checkBody('password', 'Password is Required').notEmpty();
            req.checkBody('password', 'Password Must Not Be Less Than 5').isLength({min:5});
            req.check("password", "Password Must Contain at least 1 Number.").matches(/^(?=.*\d)(?=.*[a-z])[0-9a-z]{5,}$/, "i");
            
            var errors = req.validationErrors();
                      
            if(req.body.password == req.body.cpassword){
                if(errors){
                    var messages = [];
                    errors.forEach((error) => {
                        messages.push(error.msg);
                    })
                    
                   var errors = req.flash('error'); res.redirect('/reset/'+req.params.token);
                }else{
                    user.password = user.encryptPassword(req.body.password);
                    
                    user.passwordResetToken = undefined;
                    user.passwordResetExpires = undefined;
                    user.save((err) => {
                        req.flash('success', 'Your password has been updated.');
                        callback(err, user);
                            
                    });
                }
            }else{
                req.flash('error', 'Password and confirm password does not match.');
                return res.redirect('/reset/' + req.params.token);
            }
         }); 
        },
             function(user,callback){
                 var smtpTransport = nodemailer.createTransport({
                   service: 'Gmail',
                   auth: {
                       user: secret.auth.user,
                       pass: secret.auth.pass
                   }
               });
               
               var mailOptions = {
                   to: user.email,
                   from: 'RateMe '+'<'+secret.auth.user+'>',
                   subject: 'Password Updated',
                   text: 'Your password has been successfully updated for'+user.email
               }
               
               smtpTransport.sendMail(mailOptions, (err, response) => {
                   var error = req.flash('error');
                   var success = req.flash('success');
                   res.render('user/reset', {title: 'Reset Your Password', messages: error, hasErrors: error.length > 0, success: success, noErrors: success.length > 0}); 
                   return callback(err, user);
               });
             }
         ]);                
     });
    
    app.get('/logout', (req,res) => {
        req.logout();
        
        req.session.destroy((err) => {
            res.redirect('/');
        });
    });
}

function validate(req, res, next){
    req.checkBody('fullname', 'Fullname Is Required').notEmpty();
    req.checkBody('fullname', 'Fullname Must Not Be Less Than 5').isLength({min:5});
    req.checkBody('email', 'Email Is Required').notEmpty();
    req.checkBody('email', 'Email is Invalid').isEmail();
    req.checkBody('password', 'Password is Required').notEmpty();
    req.checkBody('password', 'Password Must Not Be Less Than 5').isLength({min:5});
    req.check("password", "Password Must Contain at least 1 Number.").matches(/^(?=.*\d)(?=.*[a-z])[0-9a-z]{5,}$/, "i");
    
    var errors = req.validationErrors();
    
    if(errors){
        var messages = [];
        errors.forEach((error) => {
            messages.push(error.msg);
        });
        
        req.flash('error', messages);
        res.redirect('/signup');
    }else{
        return next();
    }
}

function loginvalidate(req, res, next){
    req.checkBody('email', 'Emil Is Required').notEmpty();
    req.checkBody('email', 'Email is Invalid').isEmail();
    req.checkBody('password', 'Password is Required').notEmpty();
    req.checkBody('password', 'Password Must Not Be Less Than 5').isLength({min:5});
    req.check("password", "Password Must Contain at least 1 Number.").matches(/^(?=.*\d)(?=.*[a-z])[0-9a-z]{5,}$/, "i");
    
    var loginerrors = req.validationErrors();
    
    if(loginerrors){
        var messages = [];
        loginerrors.forEach((error) => {
            messages.push(error.msg);
        });
        
        req.flash('error', messages);
        res.redirect('/login');
    }else{
        return next();
    }
}