// backend/helpers/sendNotification.js
import knock from "./../utils/knock.js";

// Function to send a notification using Knock
export const sendNotification = async (
    recipientId,    // Knock user ID
    workflowKey,    // Knock workflow key
    data    // Additional data for the notification
) => {
    try {
        const response = await knock.workflows.trigger(workflowKey, {
            recipients: [recipientId],
            data: data,
        });

        console.log("Notification sent:", response);
        return response;
    }
    catch (error) {
        console.error("Error sending notification:", error);
        throw error;
    }
};