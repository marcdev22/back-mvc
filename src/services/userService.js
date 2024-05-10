const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const { createUser, findUserByEmail } = require('../models/userModel')
require('dotenv').config()

exports.createUser = async (userData) => {
    try{
        const createdUser = await createUser(userData)

        if(createdUser){
            return {
                success: true
            }
        }

        return {
            success: false,
            message: 'Error during sign in'
        }
    }
    catch(error){
        return {
            success: false,
            error: error.message
        }
    }
}

exports.findUserByEmail = async (email) => {
    try{
        const found = await findUserByEmail(email)

        if(found.success){
            return {
                success: true,
                user: found.user
            }
        }

        return {
            success: false,
            message: 'User not found'
        }
    }
    catch(error){
        return {
            success: false,
            error: error.message
        }
    }
}

exports.comparePasswords = async (plainPassword, hashedPassword) => {
    try{
        const verifyPassword = await bcrypt.compare(plainPassword, hashedPassword)
        return verifyPassword
    }
    catch(error){
        throw new Error('Error comparing passwords')
    }
}

exports.generateToken = async (user) => {
    try{
        const token = jwt.sign({
            email: user.email,
            userId: user.id
        }, 
        process.env.TOP_SECRET,
        {
            expiresIn: '1h'
        })
    }
    catch(error){
        throw new Error('Error generating token')
    }
}