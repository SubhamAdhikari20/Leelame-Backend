// backend/models/user.model.js
import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    fullName: {
        type: String,
        required: true,
    },
    contact: {
        type: String,
        unique: true,
        sparse: true,
        trim: true,
        minLength: 10,
        maxLength: 10,
    },
    username: {
        type: String,
        unique: true,
        sparse: true,
        match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores'],
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, 'Invalid email format'],
    },
    password: {
        type: String,
        minLength: 8,
    },
    googleId: {
        type: String,
        unique: true,
        sparse: true,
    },
    profilePictureUrl: {
        type: String,
    },
    isVerified: {
        type: Boolean,
        default: false,
    },
    verifyCode: {
        type: String,
    },
    verifyCodeExpiryDate: {
        type: Date,
    },
    verifyEmailResetPassword: {
        type: String,
    },
    verifyEmailResetPasswordExpiryDate: {
        type: Date,
    },
}, {
    timestamps: true,
});

const User = mongoose.model("users", userSchema);
export default User;