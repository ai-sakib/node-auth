const User = require('../models/user')
const bcrypt = require('bcryptjs')

exports.getLogin = (req, res, next) => {
    const flashMessage = req.flash('error')
    let errorMessage = flashMessage.length > 0 ? flashMessage[0] : null

    res.render('auth/login', {
        path: '/login',
        pageTitle: 'Login',
        isAuthenticated: false,
        errorMessage: errorMessage,
    })
}

exports.postLogin = (req, res, next) => {
    const email = req.body.email
    const password = req.body.password

    User.findOne({ email: email }).then(user => {
        if (!user) {
            req.flash('error', 'Invalid email or password.')
            return res.redirect('/login')
        }
        bcrypt
            .compare(password, user.password)
            .then(doMatch => {
                if (doMatch) {
                    req.session.isLoggedIn = true
                    req.session.user = user
                    return req.session.save(err => {
                        res.redirect('/')
                    })
                } else {
                    req.flash('error', 'Invalid email or password.')
                    res.redirect('/login')
                }
            })
            .catch(err => {
                console.log(err)
                req.flash('error', 'Something went wrong.')
                res.redirect('/login')
            })
    })
}

exports.getSignup = (req, res, next) => {
    const flashMessage = req.flash('error')
    let errorMessage = flashMessage.length > 0 ? flashMessage[0] : null

    res.render('auth/signup', {
        path: '/signup',
        pageTitle: 'Signup',
        isAuthenticated: false,
        errorMessage: errorMessage,
    })
}

exports.postSignup = (req, res, next) => {
    const email = req.body.email
    const password = req.body.password

    User.findOne({ email: email })
        .then(foundUser => {
            if (foundUser) {
                req.flash('error', 'Email already exists.')
                return res.redirect('/signup')
            }
            return bcrypt
                .hash(password, 12)
                .then(hashedPassword => {
                    const user = new User({
                        email: email,
                        password: hashedPassword,
                        cart: { items: [] },
                    })
                    return user.save()
                })
                .then(result => {
                    res.redirect('/login')
                })
        })
        .catch(err => console.log(err))
}

exports.postLogout = (req, res, next) => {
    req.session.destroy(err => {
        console.log(err)
        res.redirect('/')
    })
}
