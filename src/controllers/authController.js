const bcrypt = require('bcrypt')
const jsonwebtoken = require('jsonwebtoken')
const { createUser, findUserByEmail } = require('../services/userService')

exports.signup = async (req, res) => {
    try {
        const { email, password } = req.body
        const existingUser = await findUserByEmail(email)
        if(existingUser.success){
            return res.status(400).json({
                message: 'User already exists'
            })
        }

        const saltRounds = 10
        const hashedPassword = await bcrypt.hash(password, saltRounds)

        const newUser = {
            email: email,
            password: hashedPassword
        }

        const userResult = await createUser(newUser)
        if(userResult.success){
            res.status(201).json({
                message: 'User saved successfully'
            })
        }
        else{
            res.status(500).json({
                message: 'Error with the user sign-in'
            })
        }

    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}

exports.login = async (req, res) => {
    try{
        const { email, password } = req.body
        const findEmail = await findUserByEmail(email)

        if(!findEmail.success){
            res.status(401).json({
                message: 'User not found'
            })
        }

        const user = findEmail.user
        const findPassword = await bcrypt.compare(password, user.password)

        if(!findPassword.success){
            res.status(401).json({
                message: 'Incorrect password'
            })
        }

        const token = jsonwebtoken.sign({
            email: user.email,
            userId: user.id
        }, process.env.TOP_SECRET, {
            expiresIn: '1h'
        })
        res.status(200).json({
            token: token
        })
    }
    catch(error){
        res.status(500).json({
            message: error.message
        })
    }}