// Import mongoose for MongoDB connection and ODM features
import mongoose from "mongoose";

// Import database name constant
// Keeps DB name centralized and reusable
import { DB_NAME } from "../constants.js";

// Async function to connect to MongoDB
const connectDB = async () => {
  try {
    // Connect to MongoDB using connection string + DB name
    const connectionInstance = await mongoose.connect(
      `${process.env.MONGODB_URI}/${DB_NAME}`
    );

    // Log successful connection with host info
    console.log(
      `\nMongoDB connected successfully!! Host: ${connectionInstance.connection.host}\n`
    );

    // Return connection instance (useful for testing or extensions)
    return connectionInstance;
  } catch (error) {
    // Log connection error
    console.error("DB CONNECTION ERROR:", error);

    // Exit the process if DB connection fails
    // Prevents app from running in broken state
    process.exit(1);
  }
};

// Export the connectDB function
// Used in src/index.js before starting the server
export default connectDB;
