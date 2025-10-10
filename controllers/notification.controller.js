// backend/controllers/notification.controller.js
import knock from "../utils/knock.js";
import User from "../models/user.model.js";

// Update or create a Knock user when user details change
export const updateKnockUser = async (req, res) => {
    try {
        const { userId } = req.user;
        const { fullName, email } = req.body;

        if (!fullName || !email) {
            return res.status(400).json({ message: "Full name and email are required" });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Create or Update Knock user
        await knock.users.update(String(userId), {
            name: fullName,
            email: email,
            avatar: user.profilePictureUrl,
            channel_data: {
                // Replace with actual channel ID from your Knock dashboard
                [process.env.KNOCK_IN_APP_CHANNEL_ID]: {
                    enabled: true, // Example for in-app notifications
                },
                [process.env.KNOCK_EMAIL_CHANNEL_ID]: {
                    address: email, // For email channel
                },
                [process.env.KNOCK_PUSH_CHANNEL_ID]: {
                    tokens: [user.pushToken], // For push notifications
                },
            },
            preferences: {
                default: {
                    channel_types: {
                        in_app_feed: true,
                        email: true,
                    },
                },
            },
        });

        res.status(200).json({ success: true, message: "Knock user updated successfully" });
    }
    catch (error) {
        console.error("Error updating Knock user:", error);
        res.status(500).json({ success: false, message: "Internal server error" });
    }
};