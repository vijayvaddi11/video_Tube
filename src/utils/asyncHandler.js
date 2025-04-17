//middleware 

//try and catch
const asyncHandler = (fn) => {
  return async (req, res, next) =>{
    try {
      await fn(req,res,next)
    
    } catch(error) {
      res.status(error.code || 500).json({
        success: false,
        message:error.message
      })
  }
  };
};


export { asyncHandler };


//middleware using promisses

// const asyncHandler = (requestHandler) => {
//   return async (req, res, next) => {
//     Promise.resolve(requestHandler(req,res,next)).
//       catch((err) => next(err))
//   }
// };


