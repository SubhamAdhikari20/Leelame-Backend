// backend/middlewares/authGuard.js
import jwt from "jsonwebtoken";

export const authGuard = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    try {
        if (!authHeader) {
            return res.status(401).json({
                success: false,
                error: 'User not authorized!',
            });
        }

        const token = authHeader.split(" ")[1];

        if (!token || token === '') {
            return res.status(401).json({
                success: false,
                error: 'No token in header!',
            });
        }

        const decodedUser = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decodedUser;

        next();
    }

    catch (error) {
        console.error(error);
        return res.status(401).json({ error: "Invalid Token!"});
    }

};