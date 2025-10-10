// backend/controllers/notification.route.js
import express from "express";
import { authGuard } from "../middlewares/authGuard.js";
import { updateKnockUser } from "../controllers/notification.controller.js";

const router = express.Router();

// Route to update or create a Knock user
router.post("/knock/update-user", authGuard, updateKnockUser);

export default router;