// backend/controllers/user.controller.js
import User from "../models/user.model.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import axios from 'axios';
import { sendVerificationEmail } from "../helpers/sendVerificationEmail.js";
import { sendResetPasswordVerificationEmail } from "../helpers/sendResetPasswordVerificationEmail.js";

// Create a new user
export const createUser = async (req, res) => {
    try {
        const { fullName, contact, username, email, password } = req.body;

        const existingUserByUsername = await User.findOne({ username });
        if (
            existingUserByUsername &&
            existingUserByUsername.isVerified === false
        ) {
            return res.status(400).json({ sucess: true, message: "Username already exists" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const expiryDate = new Date();
        expiryDate.setMinutes(expiryDate.getMinutes() + 10); // Add 10 mins from 'now'
        let newUser;

        const existingUserByEmail = await User.findOne({ email });
        if (existingUserByEmail) {
            if (existingUserByEmail.isVerified) {
                return res.status(400).json({
                    success: false,
                    message: "Email already exists",
                });
            }
            else {
                // Update existing unverified user
                existingUserByEmail.fullName = fullName;
                existingUserByEmail.contact = contact;
                existingUserByEmail.username = username;
                existingUserByEmail.password = hashedPassword;
                existingUserByEmail.verifyCode = otp;
                existingUserByEmail.verifyCodeExpiryDate = expiryDate;

                newUser = existingUserByEmail;
                await newUser.save();
            }
        }
        else {
            newUser = await User({
                fullName,
                username,
                email,
                password: hashedPassword,
                contact,
                profilePictureUrl: "",
                verifyCode: otp,
                verifyCodeExpiryDate: expiryDate,
                isVerified: false,
            });
            await newUser.save();
        }

        // Generate Token
        const token = jwt.sign(
            { _id: newUser._id, email: newUser.email },
            process.env.JWT_SECRET,
            { expiresIn: `${process.env.JWT_SIGNUP_EXPIRES_IN}` }
        );

        // send verfication email
        const emailResponse = await sendVerificationEmail(fullName, email, otp);
        if (!emailResponse.success) {
            return res.status(500).json({
                success: false,
                message: emailResponse.message,
            });
        }

        return res.status(201).json({
            sucess: true,
            message: "User signed up successfully. Please verify your email",
            token,
            user: newUser,
        });
    }
    catch (error) {
        console.error("Error signing up the user: ", error);
        res.status(500).json({
            success: false,
            message: "Error signing up the user",
        });
    }
};

// Login user with username or email
export const loginUser = async (req, res) => {
    const { identifier, password } = req.body;
    console.log(identifier);
    try {
        let checkExistingUser;
        if (identifier) {
            checkExistingUser = await User.findOne({
                $or: [
                    { username: identifier },
                    { email: identifier }
                ]
            });
        }

        if (!checkExistingUser) {
            return res.status(400).json({ message: "Invalid username/email or password" });
        }

        console.log(checkExistingUser.password)
        // Compare password
        const isMatch = await bcrypt.compare(password, checkExistingUser.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid password' });
        }

        // Check if user is verified
        if (!checkExistingUser.isVerified) {
            return res.status(403).json({
                success: false,
                message: "Account not verified",
                user: { email: checkExistingUser.email, username: checkExistingUser.username },
            });
        }

        // Generate Token
        const token = jwt.sign(
            { _id: checkExistingUser._id, email: checkExistingUser.email },
            process.env.JWT_SECRET,
            { expiresIn: `${process.env.JWT_LOGIN_EXPIRES_IN}` }
        );

        // const token = user.generateJWT();

        res.status(200).json({ token, user: checkExistingUser, message: 'Login successful' });
    }
    catch (error) {
        res.status(500).json({ error: 'Server error' });
    }

};


export const googleLogin = async (req, res) => {
    try {
        const { access_token } = req.body;
        if (!access_token) {
            return res.status(400).json({ error: 'Missing access_token' });
        }

        // Get user info from Google API
        const googleUser = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', {
            headers: {
                Authorization: `Bearer ${access_token}`,
            },
        });

        const { sub, email, name, picture } = googleUser.data;

        // Find or create user
        let user = await User.findOne({ email });
        if (!user) {
            user = await User.create({
                googleId: sub,
                email,
                fullName: name,
                profilePictureUrl: picture,
                isVerified: true,
            });
        }

        // Create JWT token
        const token = jwt.sign(
            { _id: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: `${process.env.JWT_LOGIN_EXPIRES_IN}` }
        );

        res.status(200).json({
            message: '✅ Google login success',
            token,
            user: {
                id: user._id,
                fullName: user.fullName,
                email: user.email,
                profilePictureUrl: user.profilePictureUrl,
            },
        });

    }
    catch (error) {
        console.error('Google login failed:', error);
        res.status(500).json({ error: 'Google login failed' });
    }
};