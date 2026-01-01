// asyncHandler is a higher-order function
// It takes a controller function as input
const asyncHandler = (fn) => {
  
  // It returns a new middleware function
  // This function matches Express middleware signature
  return (req, res, next) => {
    
    // Promise.resolve ensures that:
    // - async functions
    // - functions returning promises
    // - even sync functions
    // are all handled uniformly
    Promise.resolve(fn(req, res, next))
      
      // If any error occurs inside the controller,
      // it is caught here and passed to Express
      // This forwards the error to the global error handler
      .catch((error) => next(error));
  };
};

// Exporting asyncHandler for use in routes
// Example usage: router.post("/login", asyncHandler(loginUser))
export { asyncHandler };
