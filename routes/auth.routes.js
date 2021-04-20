const router = require("express").Router();

const UserModel = require("../models/User.model")
const bcrypt = require("bcryptjs")

/* GET Signup Form */
router.get('/signup', (req, res, next) => {
    res.render('auth/signup')
})

/* Custom Middleware: Validate user input */
const validation = (req, res, next) => {
    const { username, password } = req.body

    if (!username || !password) {
        res.render('auth/signup.hbs', { msg: 'Please fill all the fields !' })
    } else {
        next();
    }
    //  //// FIX VALIDATION 
    // ****************************************
    // UserModel.find({}, "username")
    //     .then(users => {

    //         const usernames = users.map(user => {
    //             return user.username
    //         })
    //         console.log(usernames)
    //         if (usernames.includes(username)) {
    //             res.render('auth/signup.hbs', { msg: 'Username allready taken' })
    //             return;
    //         } else {
    //             next()
    //         }
    //     })
}

/* POST create User */
router.post('/signup', validation, (req, res, next) => {
    const { username, password } = req.body
    const salt = bcrypt.genSaltSync(12);
    const hash = bcrypt.hashSync(password, salt);

    UserModel.create({ username, password: hash })
        .then(() => res.redirect("/signin"))
        .catch((err) => next(err))
})

/* GET Signin Form */
router.get("/signin", (req, res) => {
    res.render("auth/signin.hbs")
})

/* POST Login credentials */
router.post("/signin", (req, res, next) => {
    const { username, password } = req.body

    UserModel.findOne({ username })
        .then((user) => {
            if (!user) {
                res.render('auth/signin.hbs', { msg: 'Username or Password incorrect!' })
            }
            else {
                // check if password is correct 
                bcrypt.compare(password, user.password)
                    .then((isMatching) => {
                        if (isMatching) {
                            req.app.locals.isCurrentUser = true
                            req.session.currentUser = user;
                            res.redirect('/private')
                        }
                        else {
                            res.render('auth/signin.hbs', { msg: 'Username or Password incorrect!' })
                        }
                    })
            }

        }).catch((err) => {
            next(err)
        });
})

// Custom Middleware 
const authorize = (req, res, next) => {
    if (req.session.currentUser) {
        next()
    }
    else {
        res.redirect('/signin')
    }
}
/* GET Render a private page */
router.get('/private', authorize, (req, res) => {

    res.render("private/index.hbs")
})

router.get('/main', authorize, (req, res) => {
    res.render('private/main.hbs')
})

router.get('/logout', (req, res) => {
    req.session.destroy()
    req.app.locals.isCurrentUser = false
    res.redirect('/')

})



module.exports = router;