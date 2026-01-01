// Import mongoose to define schema and model
import mongoose from "mongoose";

// Import JWT for token generation
import jwt from "jsonwebtoken";

// Import bcrypt for password hashing & comparison
import bcrypt from "bcrypt";

// Define User schema (structure of user documents)
const userSchema = new mongoose.Schema(
  {
    // Unique username for the user
    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true, // faster search
    },

    // User email (used for login)
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },

    // Full name of the user
    fullName: {
      type: String,
      required: true,
      trim: true,
      index: true,
    },

    // Cloudinary URL for avatar image
    avatar: {
      type: String,
      required: true,
    },

    // Optional cover image URL
    coverImage: {
      type: String,
    },

    // Watch history references Video documents
    watchHistory: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Video",
      },
    ],

    // Hashed password (never store plain password)
    password: {
      type: String,
      required: [true, "Password is required"],
      select: false, // do not return password by default
    },

    // Stores the latest valid refresh token
    refreshToken: {
      type: String,
    },
  },
  {
    timestamps: true, // adds createdAt & updatedAt
  }
);

/* -------------------- PRE-SAVE HOOK -------------------- */

// Hash password before saving user to database
userSchema.pre("save", async function (next) {
  // If password is not modified, skip hashing
  if (!this.isModified("password")) return next();

  // Hash the password with salt rounds
  this.password = await bcrypt.hash(this.password, 10);

  next();
});

/* -------------------- SCHEMA METHODS -------------------- */

// Compare input password with hashed password
userSchema.methods.isPasswordCorrect = async function (password) {
  return bcrypt.compare(password, this.password);
};

// Generate short-lived access token
userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      username: this.username,
      email: this.email,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    }
  );
};

// Generate long-lived refresh token
userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
    }
  );
};

// Export User model
// Used throughout controllers for DB operations
export const User = mongoose.model("User", userSchema);
