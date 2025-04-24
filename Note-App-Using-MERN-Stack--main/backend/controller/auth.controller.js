import User from "../models/user.model.js"
import { errorHandler } from "../utils/error.js"
import bcryptjs from "bcryptjs"
import jwt from "jsonwebtoken"

// SIGNUP FUNCTION
export const signup = async (req, res, next) => {
  const { username, email, password } = req.body
  

  try {
    const isValidUser = await User.findOne({ email })
    if (isValidUser) {
      return next(errorHandler(400, "User already exists"))
    }

    const hashedPassword = bcryptjs.hashSync(password, 10)
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
    })

    await newUser.save()

    res.status(201).json({
      success: true,
      message: "User created successfully",
    })
  } catch (error) {
    next(error)
  }
}

// SIGNIN FUNCTION
export const signin = async (req, res, next) => {
  const { email, password } = req.body
  
  try {
    if (!email || !password) {
      return next(errorHandler(400, "Email and password are required"))
    }
   
    const validUser = await User.findOne({ email })
    if (!validUser) {
      return next(errorHandler(404, "User not found"))
    }

    const validPassword = bcryptjs.compareSync(password, validUser.password)
    if (!validPassword) {
      return next(errorHandler(401, "Wrong credentials"))
    }

    const token = jwt.sign({ id: validUser._id }, process.env.JWT_SECRET, { expiresIn: "1d" })

    const { password: _, ...userData } = validUser._doc

    res
      .cookie("access_token", token, {
        httpOnly: true,
        sameSite: "Lax",
        secure: false, // Set to true in production (HTTPS)
      })
      .status(200)
      .json({
        success: true,
        message: "Login successful!",
        user: userData,
      })
  } catch (error) {
    next(error)
  }
}

// SIGNOUT FUNCTION
export const signout = async (req, res, next) => {
  try {
    res.clearCookie("access_token")
    res.status(200).json({
      success: true,
      message: "User logged out successfully",
    })
  } catch (error) {
    next(error)
  }
}
