// Import asyncHandler to catch async errors automatically
import { asyncHandler } from "../utils/asyncHandler.js";

// Import custom ApiError for consistent error handling
import ApiError from "../utils/ApiError.js";

// Import jsonwebtoken to verify JWT tokens
import jwt from "jsonwebtoken";

// Import User model (named export)
import { User } from "../models/user.models.js";

// Middleware to verify access token (JWT)
export const verifyJWT = asyncHandler(async (req, res, next) => {
  
  // Extract access token from Authorization header
  // Expected format: "Bearer <token>"
  const token = req.header("Authorization")?.replace("Bearer ", "");

  // If token is missing, user is not authenticated
  if (!token) {
    throw new ApiError(401, "Unauthorized: Access token missing");
  }

  // Verify the token using secret key
  // jwt.verify throws an error automatically if token is invalid or expired
  const decodedToken = jwt.verify(
    token,
    process.env.ACCESS_TOKEN_SECRET
  );

  // Find the user using ID from token payload
  // Exclude sensitive fields explicitly
  const user = await User.findById(decodedToken._id).select(
    "-password -refreshToken"
  );

  // If user does not exist, token is invalid
  if (!user) {
    throw new ApiError(401, "Unauthorized: User not found");
  }

  // Attach user object to request
  // This allows controllers to access req.user
  req.user = user;

  // Allow request to continue to controller
  next();
});
