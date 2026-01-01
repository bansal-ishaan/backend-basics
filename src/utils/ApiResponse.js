// ApiResponse is a utility class used to standardize
// all successful API responses across the backend
class ApiResponse {

  // Constructor accepts HTTP status, actual data, and an optional message
  constructor(
    statusCode, // HTTP status code (200, 201, etc.)
    data,       // response payload (object, array, null)
    message = "Success" // default success message
  ) {
    // Attach HTTP status code
    this.statusCode = statusCode;

    // Attach response data
    this.data = data;

    // Attach response message
    this.message = message;

    // Automatically determine success based on status code
    // 2xx and 3xx → success true
    // 4xx and 5xx → success false
    this.success = statusCode >= 200 && statusCode < 400;
  }
}

// Export ApiResponse for use in controllers
// Example usage:
// res.status(200).json(new ApiResponse(200, user, "User fetched"))
export { ApiResponse };
