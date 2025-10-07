// backend/middlewares/uploadImage.js
import multer from "multer";
import { v4 as uuidv4 } from "uuid";
import { v2 as cloudinary } from "cloudinary";
import streamifier from "streamifier";
import dotenv from "dotenv";

dotenv.config();

// Configuring Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUD_NAME,
    api_key: process.env.CLOUD_API_KEY,
    api_secret: process.env.CLOUD_API_SECRET,
    secure: true,
});


// Configuring Multer to use in-memory storage
export const upload = multer({
    storage: multer.memoryStorage(),
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith("image/")) cb(null, true);
        else cb(new Error("Only image files are allowed!"), false);
    },
    limits: { fileSize: 10 * 1024 * 1024 }, // max 10MB per file
});

// Upload a single image to Cloudinary
export const uploadImage = (buffer, filename, folder = "leelame") => {
    const basename = filename.replace(/\.[^/.]+$/, "");
    const timestamp = Date.now();
    const uniqueId = uuidv4();
    const publicId = `${folder}/${basename}-${timestamp}-${uniqueId}`;

    return new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
            {
                public_id: publicId,
                folder,
                resource_type: "image",
                overwrite: true,
            },
            (error, result) => {
                if (error) return reject(error);
                resolve(result.secure_url);
            }
        );

        streamifier.createReadStream(buffer).pipe(uploadStream);
    });
};

// Upload multiple images to Cloudinary
export const uploadMultipleImages = (buffers, filenames, folder = "leelame") => {
    return Promise.all(
        buffers.map((buf, i) => {
            const basename = filenames[i].replace(/\.[^/.]+$/, "");
            const timestamp = Date.now();
            const uniqueId = uuidv4();
            const publicId = `${folder}/${basename}-${timestamp}-${uniqueId}`;

            return new Promise((resolve, reject) => {
                const uploadStream = cloudinary.uploader.upload_stream(
                    {
                        public_id: publicId,
                        folder,
                        resource_type: "image",
                        overwrite: true,
                    },
                    (error, result) => {
                        if (error) reject(error);
                        else resolve(result.secure_url);
                    }
                );

                streamifier.createReadStream(buf).pipe(uploadStream);
            });
        })
    );
};