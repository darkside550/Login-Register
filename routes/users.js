const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
// User model
const User=require('../models/User');
const async = require('async');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();


// LOGIN PAGE
router.get('/login',(req,res) => res.render('login'));

// Register PAGE
router.get('/register',(req,res) => res.render('register'));

// Forget Page
router.get('/forgot',(req,res) => res.render('forgot'));

//reset page
//router.get('/users/reset/<%= token %>',(req,res) => res.render('reset/<%= token %>'));

// Register handle
router.post('/register', (req,res) => {
    const {name, rollno, email, password, password2} = req.body;
    let errors=[];

    // check required fields
    if(!name || !rollno || !email|| !password || !password2){
        errors.push({ msg: 'Please fill in all fields'});
    }
    
    //check passwords
    if(password !== password2){
        errors.push({msg: 'Passwords do not match' });
    }

    //check pass length
    if(password.length < 6) {
        errors.push({ msg: 'Password should be at least 6 characters'});
    }

if(errors.length > 0 ) {
    res.render('register', {
        errors,
        name,
        rollno,
        email,
        password,
        password2
    });
} else {
    // validation passed
    // if email matches , user exists 
    User.findOne({email : email})
    .then(user => {
        if (user) {
            //USer Exists
            errors.push({ msg: 'Email or roll no. is already registered'});
            res.render('register', {
                errors,
                name,
                rollno,
                email,
                password,
                password2
            });
        } else {
            const newUser = new User({
                name,
                rollno,
                email,
                password
            });

           //hash password
           bcrypt.genSalt(10,(err,salt)=> bcrypt.hash(newUser.password,salt,(err,hash) => {
            if(err) throw err;
            //set password to hashed
            newUser.password=hash;
            //save user
            newUser.save()
            .then(user => {
                req.flash('success_msg', 'you are now registered and can log in');
                res.redirect('/users/login');
            })
            .catch(err> console.group(err));
           }))
        }
    });
}
});
// login handle
router.post('/login', (req,res,next) => {
    passport.authenticate('local',{
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash:true
    })(req,res,next);
});

//logout handle
router.get('/logout',(req,res) => {
    req.logOut();
    req.flash('success_msg', 'you are logged out');
    res.redirect('/users/login');
});

//forget password
router.get('/forgot',(req,res) => res.render('forgot'));

router.post('/forgot', function(req, res, next) {
    async.waterfall([
      function(done) {
        crypto.randomBytes(20, function(err, buf) {
          var token = buf.toString('hex');
          done(err, token);
        });
      },
      function(token, done) {
        User.findOne({ email: req.body.email }, function(err, user) {
          if (!user) {
            req.flash('error_msg', 'No account with that email address exists');
            return res.redirect('/users/forgot');
          }
  
          user.resetPasswordToken = token;
          user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
  
          user.save(function(err) {
            done(err, token, user);
          });
        });
      },
      function(token, user, done) {
        var smtpTransport = nodemailer.createTransport({
          service: 'Gmail', 
          auth: {
            user: process.env.EMAIL,
            pass: process.env.PASSWORD
          }
        });
        var mailOptions = {
          to: user.email,
          from: process.env.EMAIL,
          subject: 'Node.js Password Reset',
          text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
            'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
            'http://' + req.headers.host + '/users/reset/' + token + '\n\n' +
            'If you did not request this, please ignore this email and your password will remain unchanged.\n'
        };
        smtpTransport.sendMail(mailOptions, function(err) {
          console.log('mail sent');
          req.flash('success_msg', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
          done(err, 'done');
        });
      }
    ], function(err) {
      if (err) return next(err);
      res.redirect('/users/forgot');
    });
  });

router.get('/users/reset/:token', function(req, res) {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      req.flash('error', 'Password reset token is invalid or has expired.');
      return res.redirect('/users/forgot');
    }
    res.render('/users/reset', {token: req.params.token});
  });
});

router.post('/users/reset/:token', function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
          req.flash('error_msg', 'Password reset token is invalid or has expired.');
          return res.redirect('back');
        }
        if(req.body.password === req.body.confirm) {
          user.setPassword(req.body.password, function(err) {
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;

            user.save(function(err) {
              req.logIn(user, function(err) {
                done(err, user);
              });
            });
          })
        } else {
            req.flash("error_msg", "Passwords do not match.");
            return res.redirect('back');
        }
      });
    },
    function(user, done) {
      var smtpTransport = nodemailer.createTransport({
        service: 'Gmail', 
        auth: {
          user: process.env.EMAIL,
          pass: process.env.PASSWORD
        }
      });
      var mailOptions = {
        to: user.email,
        from: process.env.EMAIL,
        subject: 'Your password has been changed',
        text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        req.flash('success_msg', 'Success! Your password has been changed.');
        done(err);
      });
    }
  ], function(err) {
    res.redirect('/login');
  });
});

module.exports = router;