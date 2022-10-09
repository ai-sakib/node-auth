const User = require('../models/user')

exports.getLogin = (req, res, next) => {
    res.render('auth/login', {
        path: '/login',
        pageTitle: 'Login',
        isAuthenticated: false,
    })
}

exports.postLogin = (req, res, next) => {
    User.findOne()
        .then(user => {
            req.session.isLoggedIn = true
            req.session.user = user
            req.session.save(err => {
                console.log(err)
                res.redirect('/')
            })
        })
        .catch(err => console.log(err))
}

exports.getSignup = (req, res, next) => {
    res.render('auth/signup', {
        path: '/signup',
        pageTitle: 'Signup',
        isAuthenticated: false,
    })
}

exports.postSignup = (req, res, next) => {}

exports.postLogout = (req, res, next) => {
    req.session.destroy(err => {
        console.log(err)
        res.redirect('/')
    })
}
