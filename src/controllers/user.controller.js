import { asyncHandler } from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js"
import { User } from "../models/user.model.js";
import {uplodOnCloudinary} from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import jwt from "jsonwebtoken"
import { response } from "express";

const generateAccessandRefreshtokens = async (userId)=>{
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAcessToken()
    const refreshToken = user.generateRefreshToken()
    
    user.refreshToken = refreshToken
    await user.save({ validateBeforeSave: false })
    
    return{accessToken,refreshToken}

  } catch (error) {
    throw new ApiError(500,"something went wrong while generat")
  } 
}



 

const registerUser = asyncHandler(async (req, res) => {
  const { username, fullname, email, password } = req.body;

  if ([username, fullname, email, password].some((field) => !field?.trim())) {
    throw new ApiError(400, `all fields are required`);
  }
  

  /*const usernameExists = await User.findOne({ username: req.body.username });
  const emailExists = await User.findOne({ email: req.body.email });
  if (usernameExists && emailExists)
    return res.status(400).send("Username and email already taken");
  if (emailExists) return res.status(400).send("Email already taken");
  if (usernameExists) return res.status(400).send("Username already taken");*/

  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(400, "User with email or username alredy exist");
  }

  const avatarLocalPath = req.files?.avatar?.[0]?.path;
  const coverImageLocalPath = req.files?.coverImage?.[0]?.path;

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required");
  }

  const avatar = await uplodOnCloudinary(avatarLocalPath);
  const coverImage = await uplodOnCloudinary(coverImageLocalPath);

  if (!avatar) {
    throw new ApiError(400, "Avatar upload failed");
  }

  const user = await User.create({
    fullname,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  if (!createdUser) {
    throw new ApiError(505, "Something Went Wrong while regestring the user");
  }

  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User Registerd successfully"));
});



const loginUser = asyncHandler(async (req, res) => {
  const { username, email, password} = req.body;

  if (!(username || email)) {
    throw new ApiError(400,"username or email is required")
  }
  
  const user = await User.findOne({
    $or:[{username},{email}]
  })

  if (!user) {
   throw new ApiError(404,"user does not exist")
  }

  const isPasswordValid = await user.isPasswordCorrect(password)

  if (!isPasswordValid) {
    throw new ApiError(401, "invalid user credentials");
  }

  
  const { refreshToken, accessToken } = await generateAccessandRefreshtokens(user._id)
  
  const loggedInUser = await User.findById(user._id).
    select("-password -refreshToken")
  
  const options = {
    httpOnly: true,
    secure:true
  }

  return res
    .status(201)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200, {
          user:loggedInUser,accessToken,refreshToken
        },
        "User logged in successfully"
      )
    )
  
  
  


})



const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(req.user._id,
    {
    $set: {
      refreshToken: undefined
    }
    },
    { 
    new:true
    })
  
  const options = {
    httpOnly: true,
    secure:true
  }

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200),{},"User Logged Out Successfully")
  

})



const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

  if (!incomingRefreshToken) {
    throw new ApiError(401, "auauthorized request")
  }

  try {
    const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
  
    const user = await User.findById(decodedToken?._id)
  
    if (!user) {
      throw new ApiError(401, "invalid refresh token");
    }
  
    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or used");
    }
  
    const options = {
      httpOnly: true,
      secure:true
    }
  
    const {accessToken,newRefreshToken} = await generateAccessandRefreshtokens(user._id)
  
    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(new ApiResponse(
        200,
        { accessToken, refreshToken: newRefreshToken },
        "Access token Refreshed"
      ));
  } catch (error) {
    throw new ApiError(401, console.error?.message || "invalid refresh token")
  }


})


const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body
  
  const user = await User.findById(req.user?._id)
  
  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)
  
  if (!isPasswordCorrect) {
    throw new ApiError(400, "Invalid old password")
  }

  user.password = newPassword
  await user.save({ validateBeforeSave: false })
  
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"))


})


const getCurrentUser = asyncHandler(async (req, res) => {
  return res.status(200)
    .json(200, req.user, "current user fetched successfully");
})

//update text based data
const updateAccountDetails = asyncHandler(async (req, res) => {
  const { fullname, email } = req.body;//give what ever fields we want to update
  
  if (!fullname || !email) {
    throw new ApiError(400, "All fields are required")
  }

  const user = User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        fullname: fullname,
        email:email
      }
    },
    {new:true}
  ).select("-password")

  return res
    .status(200)
    .json(new ApiResponse(200, user, "account details uploaded successfully"));
})

const updateUserAvatar = asyncHandler(async (req, res) => {
  
  const avatarLocalPath = req.file?.path

  if (!avatarLocalPath) {
    throw new ApiError(400,"Avatar file is missing")
  }

  const avatar = await uplodOnCloudinary(avatarLocalPath)

  if (!avatar.url) {
    throw new ApiError(400, "Error while uploading on avatar");
  }

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        avatar:avatar.url
      }
    },
    {new:true}
  ).select("-password")

  return response
    .status(200)
    .json(new ApiResponse(200, user, "avatar updated successfully"));
})


const updateUserCoverImage = asyncHandler(async (req, res) => {
  const CoverImageLocalPath = req.file?.path;

  if (!CoverImageLocalPath) {
    throw new ApiError(400, "Cover image file is missing");
  }

  const CoverImage = await uplodOnCloudinary(CoverImageLocalPath);

  if (!CoverImage.url) {
    throw new ApiError(400, "Error while uploading on Cover image");
  }

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        CoverImage: CoverImage.url,
      },
    },
    { new: true }
  ).select("-password");

  return response
    .status(200)
    .json(new ApiResponse(
      200,
      user,
      "cover image updated successfully"
    ));
});

export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateAccountDetails,
  updateAccountDetails,
  updateUserCoverImage,
};

 


  