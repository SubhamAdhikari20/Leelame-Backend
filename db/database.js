import mongoose from "mongoose";

const connectDB = async () => {
    try {
        const dbConnect = await mongoose.connect(process.env.MONGODB_URI);
        console.log(`Connected to MongoDB server......`);
    }
    catch (error) {
        console.log("MongoDB connection error: ", error);
        process.exit(1);
    }
};

export default connectDB;