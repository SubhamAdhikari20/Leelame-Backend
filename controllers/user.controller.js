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
        const { fullName, contact, username, email, password, terms, role } = req.body;

        // Check for existing username
        const existingUserByUsername = await User.findOne({ username });
        if (
            existingUserByUsername &&
            existingUserByUsername.isVerified === false
        ) {
            return res.status(400).json({ sucess: true, message: "Username already exists" });
        }

        // Check for existing contact number
        const existingUserByContact = await User.findOne({ contact });
        if (existingUserByContact && existingUserByContact.isVerified === true) {
            return res.status(400).json({ success: false, message: "Contact already exists" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const expiryDate = new Date();
        expiryDate.setMinutes(expiryDate.getMinutes() + 10); // Add 10 mins from 'now'
        let newUser;

        // Check for existing email
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
                terms,
                role,
            });
            await newUser.save();
        }

        // Generate Token
        const token = jwt.sign(
            { _id: newUser._id, email: newUser.email, username: newUser.username, role: newUser.role },
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

// Check if username is unique
export const checkUsernameUnique = async (req, res) => {
    try {
        const { username } = req.query;
        if (!username || username.trim() === '') {
            return res.status(400).json({ success: false, message: "Username is required" });
        }

        if (username.length < 3) {
            return res.status(400).json({ success: false, message: "Username must be atleast 3 characters long" });
        }

        if (username.length > 20) {
            return res.status(400).json({ success: false, message: "Username must not exceed 20 characters" });
        }

        const existingVerifiedUser = await User.findOne({ username });

        if (existingVerifiedUser && existingVerifiedUser.isVerified === true) {
            return res.status(400).json(
                {
                    success: false,
                    message: "Username is already taken!"
                }
            );
        }
        return res.status(200).json(
            {
                success: true,
                message: "Username is available"
            }
        );
    }
    catch (error) {
        console.error("Error checking username uniqueness: ", error);
        res.status(500).json({
            success: false,
            message: "Error checking username uniqueness",
        });
    }
};

// Verification of OTP for registration
export const verifyOTPForRegistration = async (req, res) => {
    try {
        const { username, code } = req.body;
        const otp = code;

        if (!username || username.trim() === '') {
            return res.status(400).json({ success: false, message: "Username is required" });
        }

        if (!otp || otp.trim() === '') {
            return res.status(400).json({ success: false, message: "OTP is required" });
        }

        const existingUser = await User.findOne({ username });
        if (!existingUser) {
            return res.status(404).json({ success: false, message: "User with this username does not exist." });
        }

        if (existingUser.isVerified) {
            return res.status(400).json({ success: false, message: "This account is already verified. Please login." });
        }

        if (!existingUser.verifyCode || !existingUser.verifyCodeExpiryDate) {
            return res.status(400).json({ success: false, message: "No OTP request found. Please request for a new OTP." });
        }

        if (existingUser.verifyCode !== otp) {
            return res.status(400).json({ success: false, message: "Invalid OTP. Please try again." });
        }

        if (new Date() > existingUser.verifyCodeExpiryDate) {
            return res.status(400).json({ success: false, message: "OTP has expired. Please request for a new OTP." });
        }

        existingUser.isVerified = true;
        existingUser.verifyCode = null;
        existingUser.verifyCodeExpiryDate = null;
        await existingUser.save();

        return res.status(200).json({
            sucess: true,
            message: "Account verified successfully. You can now login.",
        });
    }
    catch (error) {
        console.error("Error verifying OTP for registration: ", error);
        res.status(500).json({
            success: false,
            message: "Error verifying OTP for registration",
        });
    }
};

// Login user with username or email
export const loginUser = async (req, res) => {
    const { identifier, password } = req.body;
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
            return res.status(400).json({ message: "Invalid username or email" });
        }

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
            { _id: checkExistingUser._id, email: checkExistingUser.email, username: checkExistingUser.username, role: checkExistingUser.role },
            process.env.JWT_SECRET,
            { expiresIn: `${process.env.JWT_LOGIN_EXPIRES_IN}` }
        );

        res.status(200).json({ sucess: true, message: 'Login successful', token, user: checkExistingUser });
    }
    catch (error) {
        res.status(500).json({ error: 'Server error' });
    }

};

// Login with Google
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
            { _id: user._id, email: user.email, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: `${process.env.JWT_LOGIN_EXPIRES_IN}` }
        );

        res.status(200).json({
            message: '✅ Google login success',
            token,
            user
        });
    }
    catch (error) {
        console.error('Google login failed:', error);
        res.status(500).json({ error: 'Google login failed' });
    }
};

// Send verification email for registration
export const handleSendEmailForRegistration = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email || email.trim() === '') {
            return res.status(400).json({ success: false, message: "Email is required" });
        }

        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            return res.status(404).json({ success: false, message: "User with this email does not exist. Please sign up." });
        }

        if (existingUser.isVerified) {
            return res.status(400).json({ success: false, message: "This account is already verified. Please login." });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiryDate = new Date();
        expiryDate.setMinutes(expiryDate.getMinutes() + 10); // Add 10 mins from 'now'

        existingUser.verifyCode = otp;
        existingUser.verifyCodeExpiryDate = expiryDate;
        await existingUser.save();

        // send verfication email
        const emailResponse = await sendVerificationEmail(existingUser.fullName, email, otp);
        if (!emailResponse.success) {
            return res.status(500).json({
                success: false,
                message: emailResponse.message,
            });
        }

        return res.status(200).json({
            sucess: true,
            message: "Verification email sent. Please check your inbox.",
            user: existingUser,
        });
    }
    catch (error) {
        console.error("Error sending verification email: ", error);
        res.status(500).json({
            success: false,
            message: "Error sending verification email",
        });
    }
};

// Forgot Password
export const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email || email.trim() === '') {
            return res.status(400).json({ success: false, message: "Email is required" });
        }

        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            return res.status(404).json({ success: false, message: "User with this email does not exist." });
        }

        if (!existingUser.isVerified) {
            return res.status(400).json({ success: false, message: "This account is not verified. Please verify your email first." });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiryDate = new Date();
        expiryDate.setMinutes(expiryDate.getMinutes() + 10); // Add 10 mins from 'now'

        existingUser.verifyEmailResetPassword = otp;
        existingUser.verifyEmailResetPasswordExpiryDate = expiryDate;
        await existingUser.save();

        // send reset password verification email
        const emailResponse = await sendResetPasswordVerificationEmail(existingUser.fullName, email, otp);
        if (!emailResponse.success) {
            return res.status(500).json({
                success: false,
                message: emailResponse.message,
            });
        }

        return res.status(200).json({
            sucess: true,
            message: "Reset password verification email sent. Please check your inbox.",
        });
    }
    catch (error) {
        console.error("Error in forgot password: ", error);
        res.status(500).json({
            success: false,
            message: "Error in forgot password",
        });
    }
};

// Verify OTP for Reset Password
export const verifyOTPForResetPassword = async (req, res) => {
    try {
        const { email, code } = req.body;
        const otp = code;

        if (!email || email.trim() === '') {
            return res.status(400).json({ success: false, message: "Email is required" });
        }

        if (!otp || otp.trim() === '') {
            return res.status(400).json({ success: false, message: "OTP is required" });
        }

        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            return res.status(404).json({ success: false, message: "User with this email does not exist." });
        }

        if (!existingUser.verifyEmailResetPassword || !existingUser.verifyEmailResetPasswordExpiryDate) {
            return res.status(400).json({ success: false, message: "No OTP request found. Please request for a new OTP." });
        }

        if (existingUser.verifyEmailResetPassword !== otp) {
            return res.status(400).json({ success: false, message: "Invalid OTP. Please try again." });
        }

        if (new Date() > existingUser.verifyEmailResetPasswordExpiryDate) {
            return res.status(400).json({ success: false, message: "OTP has expired. Please request for a new OTP." });
        }

        return res.status(200).json({
            sucess: true,
            message: "OTP verified successfully. You can now reset your password.",
        });
    }
    catch (error) {
        console.error("Error verifying OTP for reset password: ", error);
        res.status(500).json({
            success: false,
            message: "Error verifying OTP for reset password",
        });
    }
};

// Reset Password
export const resetPassword = async (req, res) => {
    try {
        const { email, newPassword } = req.body;

        if (!email || email.trim() === '') {
            return res.status(400).json({ success: false, message: "Email is required" });
        }

        if (!newPassword || newPassword.trim() === '') {
            return res.status(400).json({ success: false, message: "New Password is required" });
        }

        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            return res.status(404).json({ success: false, message: "User with this email does not exist." });
        }

        if (!existingUser.verifyEmailResetPassword || !existingUser.verifyEmailResetPasswordExpiryDate) {
            return res.status(400).json({ success: false, message: "No OTP request found. Please request for a new OTP." });
        }

        if (new Date() > existingUser.verifyEmailResetPasswordExpiryDate) {
            return res.status(400).json({ success: false, message: "OTP has expired. Please request for a new OTP." });
        }

        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        existingUser.password = hashedPassword;
        existingUser.verifyEmailResetPassword = null;
        existingUser.verifyEmailResetPasswordExpiryDate = null;
        await existingUser.save();

        return res.status(200).json({
            sucess: true,
            message: "Password reset successfully. You can now login with your new password.",
        });
    }
    catch (error) {
        console.error("Error resetting password: ", error);
        res.status(500).json({
            success: false,
            message: "Error resetting password",
        });
    }
};

// Get Current User
export const getCurrentUser = async (req, res) => {
    try {
        const userId = req.user._id; // From decoded JWT via authGuard middleware
        const user = await User.findById(userId);
        // const user = await User.findById(userId).select("-password");    // exclude password
        // console.log("Fetched current user:", user);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        res.status(200).json({ success: true, user });
    } catch (error) {
        console.error("Error fetching current user:", error);
        res.status(500).json({ success: false, message: "Error fetching current user" });
    }
};