import mongoose,{Schema} from 'mongoose';

const userSchema = new Schema({
    email :{
      type: String,
      required: true,
      unique: true,
    },
    password:{
      type: String,
      required: true,
      minLenght: 6,
      maxlenght: 30,
    },
    name:{
      type: String,
      required: true,
      minLenght:3,
      maxlenght:30,
    },
    role:{
      type: String,
      enum: ['admin', 'user'],
      default: 'user'
    },
    avatar:{
      type: String,
      default: '../upload/avatar.jpg',
    },
    refreshToken: { type: String },
},{timestamps: true,versionKey: false })

export default mongoose.model("User", userSchema);