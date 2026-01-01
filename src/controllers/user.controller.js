// Wrapper to automatically catch async errors and forward them to error middleware
import { asyncHandler } from "../utils/asyncHandler.js";

// Custom error class for consistent API errors
import ApiError from "../utils/ApiError.js";

// User mongoose model
import { User } from "../models/user.models.js";

// Utility function to upload files to Cloudinary
import { uploadOnCloudinary } from "../utils/Cloudinary.js";

// Standard API response format
import { ApiResponse } from "../utils/ApiResponse.js";

import jwt from "jsonwebtoken";
/*
  REGISTER USER CONTROLLER

  Flow:
  1. Extract user data from request body
  2. Validate required fields
  3. Check if user already exists
  4. Validate avatar upload
  5. Upload images to Cloudinary
  6. Create user in database
  7. Remove sensitive fields from response
  8. Send success response
*/

const generateAcessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(500, "Error generating tokens");
  }
};

const registerUser = asyncHandler(async (req, res) => {
  // 1️⃣ Extract user details from request body
  const { fullName, email, username, password } = req.body;
  console.log("email:", email);

  // 2️⃣ Validate: all fields must be present and non-empty
  if (
    [fullName, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }

  // 3️⃣ Check if user already exists (by email OR username)
  const existedUser = await User.findOne({
    $or: [{ email }, { username }],
  });

  if (existedUser) {
    throw new ApiError(409, "User with given email or username already exists");
  }

  // 4️⃣ Get local file paths from multer
  // req.files is added by multer middleware
  const avatarLocalPath = req.files?.avatar?.[0]?.path;
  // const coverImageLocalPath = req.files?.coverImage?.[0]?.path;

  let coverImageLocalPath;
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files?.coverImage?.[0]?.path;
  }

  // Avatar is mandatory
  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar is required");
  }

  // 5️⃣ Upload images to Cloudinary
  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = coverImageLocalPath
    ? await uploadOnCloudinary(coverImageLocalPath)
    : null;

  // Avatar upload must succeed
  if (!avatar) {
    throw new ApiError(400, "Failed to upload avatar image");
  }

  // 6️⃣ Create user document in MongoDB
  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    username: username.toLowerCase(), // normalize username
    password, // password should be hashed in model pre-save hook
  });

  // 7️⃣ Fetch created user without sensitive fields
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering the user");
  }

  // 8️⃣ Send success response
  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User registered successfully"));
});
const loginUser = asyncHandler(async (req, res) => {
  // Login logic here
  const { email, password, username } = req.body;
  if (!username || !email) {
    throw new ApiError(400, "Username and email are required");
  }
  const user = await User.findOne({
    $or: [{ email }, { username }],
  });
  if (!user) {
    throw new ApiError(404, "User not found");
  }
  const isPasswordValid = await user.isPasswordCorrect(password);
  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid password");
  }
  const { accessToken, refreshToken } = await generateAcessAndRefreshTokens(
    user._id
  );
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );
  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { user: loggedInUser, accessToken, refreshToken },
        "User logged in successfully"
      )
    );
  const options = {
    httpOnly: true,
    secure: true,
  };
  return res
    .status(200)
    .cookie("refreshToken", refreshToken, options)
    .cookie("accessToken", accessToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User logged in successfully"
      )
    );
});
const logoutUser = asyncHandler(async (req, res) => {
  // Logout logic here
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: undefined,
      },
    },

    {
      new: true,
    }
  );
  const options = {
    httpOnly: true,
    secure: true,
  };
  return res
    .status(200)
    .clearCookie("refreshToken", options)
    .clearCookie("accessToken", options)
    .json(new ApiResponse(200, {}, "User logged out successfully"));
});
const refreshAcessToken = asyncHandler(async (req, res) => {
  // Refresh token logic here
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;
  if (!incomingRefreshToken) {
    throw new ApiError(401, "Refresh token is required");
  }
  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      async (err, decoded) => {
        if (err) {
          throw new ApiError(401, "Invalid refresh token");
        }
        const user = await User.findById(decoded._id);
        if (!user) {
          throw new ApiError(404, "User not found");
        }
        if (user.refreshToken !== incomingRefreshToken) {
          throw new ApiError(401, "Refresh token does not match");
        }
        const options = {
          httpOnly: true,
          secure: true,
        };
        const { at, rt } = await generateAcessAndRefreshTokens(user._id);
        return res
          .status(200)
          .cookie("refreshToken", rt, options)
          .cookie("accessToken", at, options)
          .json(
            new ApiResponse(
              200,
              { accessToken: at, refreshToken: rt },
              "Access token refreshed successfully"
            )
          );
      }
    );
  } catch (error) {
    throw new ApiError(401, error.message || "Invalid refresh token");
  }
});
const changeCurrentPassword = asyncHandler(async (req, res) => {
  // Change password logic here
  const { oldPassword, newPassword } = req.body;
  const user = await User.findById(req.user._id);
  const isPasswordValid = await user.isPasswordCorrect(oldPassword);
  if (!isPasswordValid) {
    throw new ApiError(401, "Old password is incorrect");
  }
  user.password = newPassword;
  await user.save({ validateBeforeSave: false });
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, "Current user fetched successfully"));
});

const updateAccountDetails = asyncHandler(async (req, res) => {
  // Update account details logic here
  const { fullName, email } = req.body;
  if (!fullName || !email) {
    throw new ApiError(400, "Full name and email are required");
  }
  User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        fullName,
        email,
      },
    },
    {
      new: true,
    }
  ).select("-password -refreshToken");
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Account details updated successfully"));
});

const updateUserAvatar = asyncHandler(async (req, res) => {
  // Update user avatar logic here
  const avatarLocalPath = req.file?.path;
  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar image is required");
  }
  const avatar = await uploadOnCloudinary(avatarLocalPath);
  if (!avatar) {
    throw new ApiError(500, "Failed to upload avatar image");
  }
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        avatar: avatar.url,
      },
    },
    {
      new: true,
    }
  ).select("-password -refreshToken");
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Avatar updated successfully"));
});

const updateUserCoverImage = asyncHandler(async (req, res) => {
  // Update user cover image logic here
  const coverImageLocalPath = req.file?.path;
  if (!coverImageLocalPath) {
    throw new ApiError(400, "Cover image is required");
  }
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);
  if (!coverImage) {
    throw new ApiError(500, "Failed to upload cover image");
  }
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        coverImage: coverImage.url,
      },
    },
    {
      new: true,
    }
  ).select("-password -refreshToken");
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Cover image updated successfully"));
});

const getUserChannelProfile = asyncHandler(async (req, res) => {
  // Get user channel profile logic here
  const { username } = req.params;
  if (!username.trim()) {
    throw new ApiError(400, "Username is required");
  }
  const channel = User.aggregate([
    {
      $match: { username: username?.toLowerCase() },
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "channel",
        as: "subscribers",
      },
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "subscriber",
        as: "subscribedTo",
      },
    },
    {
      $addFields: {
        subscribersCount: { $size: "$subscribers" },
        channelsSubscribedToCount: { $size: "$subscribedTo" },
        isSubscribed: {
          if: { $in: [req.user?._id || null, "$subscribers.subscriber"] },
          then: true,
          else: false,
        },
      },
    },
    {
      $project: {
        fullName: 1,
        username: 1,
        email: 1,
        avatar: 1,
        coverImage: 1,
        subscribersCount: 1,
        channelsSubscribedToCount: 1,
        isSubscribed: 1,
      },
    },
  ]);
  if (!channel || channel.length === 0) {
    throw new ApiError(404, "Channel not found");
  }
  return res
    .status(200)
    .json(
      new ApiResponse(200, channel[0], "Channel profile fetched successfully")
    );
});
const getWatchHistory = asyncHandler(async (req, res) => {

  // Get watch history logic here
  const user = await User.aggregate([
    {
      $match: {
        _id: new mongoose.Types.ObjectId(req.user._id),
      },
    },
    {
      $lookup: {
        from: " videos",
        localField: "watchHistory",
        foreignField: "_id",
        as: "watchHistory",
        pipeline: [
          {
            $lookup: {
              from: "users",
              localField: "owner",
              foreignField: "_id",
              as: "owner",
              pipeline: [
                {
                  $project: {
                    fullName: 1,
                    username: 1,
                    avatar: 1,
                  },
                },
              ],
            },
          },
          {
            $addFields: {
              $first: "$owner",
            },
          },
        ],
      },
    },
  ]);
  return res.
    status(200)
    .json(
      new ApiResponse(
        200,
        user[0].watchHistory,
        "Watch history fetched successfully"
      )
    );
});


export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAcessToken,
  getCurrentUser,
  changeCurrentPassword,
  updateAccountDetails,
  updateUserAvatar,
  updateUserCoverImage,
  getUserChannelProfile,
  getWatchHistory   
};
