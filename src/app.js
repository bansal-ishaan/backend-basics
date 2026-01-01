// Import express to create the server instance
import express from "express";

// Import cookie-parser to read cookies from incoming requests
// Required for refresh tokens stored in cookies
import cookieParser from "cookie-parser";

// Import cors to allow frontend-backend communication
import cors from "cors";

// Create the express application instance
// This `app` is later imported in index.js
const app = express();

/* -------------------- GLOBAL MIDDLEWARES -------------------- */

// Enable CORS (Cross-Origin Resource Sharing)
// This allows frontend (different origin) to talk to backend
// `credentials: true` is REQUIRED for cookies & auth headers
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "http://localhost:3000", // allowed frontend origin
    credentials: true, // allow cookies & authorization headers
  })
);

// Parse incoming JSON requests
// Without this, req.body will be undefined for JSON payloads
// Limit is increased to handle large payloads (images, base64, etc.)
app.use(
  express.json({
    limit: "50mb", // max size of JSON body
  })
);

// Parse URL-encoded data (form submissions)
// `extended: true` allows nested objects in forms
app.use(
  express.urlencoded({
    extended: true,
    limit: "50mb",
  })
);

// Serve static files from the "public" folder
// Example: public/temp/image.jpg → accessible directly
app.use(express.static("public"));

// Parse cookies from request headers
// Makes cookies available as req.cookies
// Mandatory for refresh-token based auth
app.use(cookieParser());

/* -------------------- ROUTES -------------------- */

// Import user-related routes
import userRouter from "./routes/user.routes.js";

// Register user routes with API versioning
// All user routes will start with: /api/v1/users
// Example: /api/v1/users/login
app.use("/api/v1/users", userRouter);

/* -------------------- OPTIONAL: HEALTH CHECK -------------------- */
// Useful for deployment, monitoring, load balancers
// app.get("/health", (req, res) => {
//   res.status(200).json({ status: "OK" });
// });

/* -------------------- EXPORT APP -------------------- */

// Export the configured app
// index.js will import this and call app.listen()
export default app;
