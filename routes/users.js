const express = require('express');
const router = express.Router();

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
    res.send('pass');
}
});

module.exports = router;