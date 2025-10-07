// backend/routes/user.route.js
import express from "express";
import { authGuard } from "../middlewares/authGuard.js";
import { upload } from "../middlewares/uploadImage.js";
import { createUser, verifyOTPForRegistration, loginUser, googleLogin, checkUsernameUnique, handleSendEmailForRegistration, forgotPassword, verifyOTPForResetPassword, resetPassword, getCurrentUser, updateUserDetails, deleteUser, validateUsername, getPublicUserProfile, uploadUserProfilePicture } from "../controllers/user.controller.js";
// import { body } from "express-validator";
import User from "../models/user.model.js";

const router = express.Router();

router.post("/register-user", createUser);
router.get("/check-username-unique", checkUsernameUnique);
router.put("/verify-account-registration", verifyOTPForRegistration);

router.post("/login-user", loginUser);
router.put("/send-verification-email-registration", handleSendEmailForRegistration);
router.post("/google-login", googleLogin);
router.get("/get-current-user", authGuard, getCurrentUser);

router.put("/forgot-password", forgotPassword);
router.put("/verify-account-reset-password", verifyOTPForResetPassword);
router.put("/reset-password", resetPassword);

router.put("/update-user-details/:userId", authGuard, updateUserDetails);
router.delete("/delete-user/:userId", authGuard, deleteUser);
router.put("/profile-picture", authGuard, upload.single("profilePicture"), uploadUserProfilePicture);

router.get("/check-username", validateUsername);

// public profile (no auth)
router.get("/public-user-profile", getPublicUserProfile);


export default router;