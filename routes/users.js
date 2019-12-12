const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
// User model
const User=require('../models/User');

// LOGIN PAGE
router.get('/login',(req,res) => res.render('login'));

// Register PAGE
router.get('/register',(req,res) => res.render('register'));

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


module.exports = router;