// backend/helpers/sendVerificationEmail.js
import nodemailer from "nodemailer";

export const sendVerificationEmail = async (fullName, email, otp) => {
    const html = `
    <!DOCTYPE html>
    <html lang="en" dir="ltr">
      <head>
        <meta charset="UTF-8" />
        <title>Verification Code</title>
        <style>
          @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap');
          body {
            font-family: 'Roboto', Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
          }
          .container {
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
          }
          h2 {
            color: #1a73e8;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>Hello, ${fullName}</h2>
          <p>Thank you for signing up with us. Please use the following code to verify your email address for your registration.</p>
          <p><strong>Verification Code: ${otp}</strong></p>
          <p>If you did not sign up for an account, please ignore this email.</p>
          <p>This code will expire in 10 minutes.</p>
        </div>
      </body>
    </html>
  `;

    if (!email || !html) {
        return res
            .status(400)
            .json({ error: "Missing email or html content" });
    }
    try {
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.GMAIL_USER,
                pass: process.env.GMAIL_APP_PASSWORD,
            },
        });

        await transporter.sendMail({
            from: `"Leelame" <${process.env.GMAIL_USER}>`,
            to: email,
            subject: "Leelame | Your Verification Code",
            html,
        });

        return {
            success: true,
            message: "Verification email sent  successfully.",
        };
    }
    catch (error) {
        console.log("Error sending verification email: ", error);

        return {
            success: false,
            message: "Failed to send verification email.",
        };
    }
};