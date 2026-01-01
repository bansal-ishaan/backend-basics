// Import Router from express to create modular routes
import { Router } from "express";

// Import all user-related controllers
import {
  registerUser,
  loginUser,
  refreshAccessToken,
  logoutUser,
  changeCurrentPassword,
  updateAccountDetails,
  getCurrentUser,
  updateUserAvatar,
  updateUserCoverImage,
  getUserChannelProfile,
  getWatchHistory,
} from "../controllers/user.controller.js";

// Import multer upload middleware for file handling
import { upload } from "../middlewares/multer.middleware.js";

// Import JWT verification middleware
import { verifyJWT } from "../middlewares/auth.middleware.js";

// Create a router instance
const router = Router();

/* -------------------- PUBLIC ROUTES -------------------- */

// Register new user with avatar and cover image upload
router.route("/register").post(
  upload.fields([
    { name: "avatar", maxCount: 1 },      // avatar image
    { name: "coverImage", maxCount: 1 },  // cover image
  ]),
  registerUser
);

// Login user (email/username + password)
router.route("/login").post(loginUser);

// Refresh access token using refresh token cookie
router.route("/refresh-token").post(refreshAccessToken);

/* -------------------- PROTECTED ROUTES -------------------- */

// Logout current user
router.route("/logout").post(verifyJWT, logoutUser);

// Change current user's password
router.route("/change-password").post(verifyJWT, changeCurrentPassword);

// Get current logged-in user details
router.route("/current-user").get(verifyJWT, getCurrentUser);

// Update account details (name, email, etc.)
router.route("/update-account").patch(verifyJWT, updateAccountDetails);

// Update user avatar image
router
  .route("/avatar")
  .patch(
    verifyJWT,                  // ensure user is authenticated
    upload.single("avatar"),    // upload single avatar image
    updateUserAvatar
  );

// Update user cover image
router
  .route("/cover-image")
  .patch(
    verifyJWT,                      // ensure user is authenticated
    upload.single("coverImage"),    // upload single cover image
    updateUserCoverImage
  );

// Get watch history of current user
router.route("/watch-history").get(verifyJWT, getWatchHistory);

/* -------------------- PUBLIC PROFILE ROUTES -------------------- */

// Get a user's public channel/profile by username
router.route("/channel/:username").get(getUserChannelProfile);

/* -------------------- EXPORT ROUTER -------------------- */

// Export router to be mounted in app.js
export default router;
