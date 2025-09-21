// backend/routes/user.route.js
import express from "express";
import { authGuard } from "../middlewares/authGuard.js";
import { createUser, loginUser, googleLogin, checkUsernameUnique } from "../controllers/user.controller.js";
// import { body } from "express-validator";


const router = express.Router();

router.post("/register-user", createUser);
router.get("/check-username-unique", checkUsernameUnique);
router.put("/verify-account-registration", verifyOTPForRegistration);

router.post("/login-user", loginUser);
router.put("/send-verification-email-registration", handleSendEmailForRegistration);
router.post("/google-login", googleLogin);

router.put("/forgot-password", forgotPassword);
router.put("/verify-account-reset-password", verifyOTPForResetPassword);
router.put("/reset-password", resetPassword);


export default router;