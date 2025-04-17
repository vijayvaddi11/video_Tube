import { v2 as cloudinary } from "cloudinary";
import fs from "fs";

/*const uplodOnClodinary =(async function (localFilePath) {
  cloudinary.config({
    cloud_name: process.env.CLOUD_NAME,
    api_key: process.env.CLOUD_API_KEY,
    api_secret: process.env.CLOUDINARY_SECRET, // Click 'View API Keys' above to copy your API secret
  });
  
  try{
  const resonse = await cloudinary.uploader.upload(localFilePath,{
  public_id:"auto"
  })
  console.log("file sucessyully saved in cloudinary",response.url)
  return response;
  
  }catch(error){
  fs.unlinkSync(localFilePath)
  return null;
  }
  
})();*/

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUDINARY_SECRET, // Click 'View API Keys' above to copy your API secret
});

const uplodOnCloudinary = async (localFilePath) => {
  try {
    if (!localFilePath) return null
    //upload file on cloudinary
    const response=await cloudinary.uploader.upload(localFilePath, {
      resource_type:"auto"
    })
    //file uploded succesfully
    //console.log("file is uploded on cloudinary", response.url)
    return response;
  } catch (error) {
    fs.unlinkSync(localFilePath)// remove the locally saved temporary file as the upload operation got failed
    return null;
  }
};


export {uplodOnCloudinary}