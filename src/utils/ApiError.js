// ApiError is a custom error class
// It extends the built-in JavaScript Error class
class ApiError extends Error {

  // Constructor receives HTTP status code, message, extra errors, and optional stack
  constructor(
    statusCode, // HTTP status code (400, 401, 404, 500, etc.)
    message = "Something went wrong", // default error message
    errors = [], // additional error details (validation errors, etc.)
    stack = "" // optional custom stack trace
  ) {
    // Call the parent Error constructor with the message
    super(message);

    // Attach HTTP status code to the error
    this.statusCode = statusCode;

    // Standard API response structure
    this.data = null;      // no data in error responses
    this.message = message;
    this.success = false;

    // Extra error information (array or object)
    this.errors = errors;

    // If a custom stack trace is provided, use it
    if (stack) {
      this.stack = stack;
    } else {
      // Capture stack trace and exclude constructor for cleaner output
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

// Export ApiError so it can be thrown anywhere in the app
// Example: throw new ApiError(401, "Unauthorized access")
export default ApiError;
