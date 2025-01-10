import mongoose from 'mongoose';

export const connectDB = async (uri) => {
  try {
    await mongoose.connect(uri)
    console.log("connect db successful");
    
  } catch (error) {
    console.log(error);
  }
}