import {v2 as cloudinary} from 'cloudinary';
import { response } from 'express';
import fs from 'fs';

// Configuration
    cloudinary.config({ 
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME , 
        api_key: process.env.CLOUDINARY_API_KEY , 
        api_secret: process.env.CLOUDINARY_API_SECRET
    });

    const uploadOnCloudinary = async (localFilePath)=>{
        try{
            if(!localFilePath){
                return null;
            }
            // Upload file to Cloudinary
          const response =  await cloudinary.uploader.upload(localFilePath, {
                resource_type: "auto",
            })
            // console.log("File uploaded to Cloudinary successfully",response.url);
            fs.unlinkSync(localFilePath); // Remove file from local uploads folder
            return response;
        }
        catch(error){
            // remove file from local uploads folder
            fs.unlinkSync(localFilePath);
            
            return null;
        }
    }


    export {uploadOnCloudinary};