import { generateToken } from '../lib/utils.js';
import User from '../models/user.model.js';
import bcrypt from 'bcryptjs';
import cloudinary from '../lib/cloudinary.js';

export const signup = async (req,res) =>{
    const {fullName,email,password} = req.body;
    try {
        if(!fullName || !email || !password){
            return res.status(400).json({message: 'Please fill all fields'})
        }

        if(password.length < 6){
            return res.status(400).json({message: 'Password must be atleast 6 characters long'})
        }

        const user = await User.findOne({email})

        if(user){
            return res.status(400).json({message: 'Email already exists'})
        }

        const salt = await bcrypt.genSalt(10);

        const hashedPassword = await bcrypt.hash(password,salt);

        const newUser = new User({
            fullName,
            email,
            password: hashedPassword
        })

        if(newUser){
            generateToken(newUser._id,res);
            await newUser.save();
            res.status(201).json({_id: newUser._id, fullName: newUser.fullName, email: newUser.email,profilePic: newUser.profilePic,});
        }else{
            res.status(400).json({message: 'User not created'})
        }
    } catch (error) {
        console.log("Error in signup: ",error.message)
        res.status(500).json({message: 'Something went wrong'})
    }
}

export const login = async (req,res) =>{
    const {email,password} = req.body;
    try {
        if(!email || !password){
            return res.status(400).json({message: 'Please fill all fields'})
        }

        const user = await User.findOne({email})

        if(!user){
            return res.status(400).json({message: 'Invalid credentials'})
        }

        const isMatch = await bcrypt.compare(password,user.password);

        if(!isMatch){
            return res.status(400).json({message: 'Invalid credentials'})
        }

        generateToken(user._id,res);
        res.status(200).json({_id: user._id, fullName: user.fullName, email: user.email,profilePic: user.profilePic,});
    } catch (error) {
        console.log("Error in login: ",error.message)
        res.status(500).json({message: 'Something went wrong'})
    }
}

export const logout = async (req,res) =>{
    try {
        res.cookie('jwt',"",{maxAge: 0});
        res.status(200).json({message: 'Logged out successfully'})
    } catch (error) {
        console.log("Error in logout: ",error.message)
        res.status(500).json({message: 'Something went wrong'})
    }
}

export const updateProfile = async (req,res) =>{
    try {
        const {profilePic} = req.body;
        const userId = req.user._id;

        if(!profilePic){
            return res.status(400).json({message: 'Please select an image'})
        }

        const uploadResponse = await cloudinary.uploader.upload(profilePic);

        const updatedUser = await User.findByIdAndUpdate(userId,{profilePic: uploadResponse.secure_url},{new: true});

        res.status(200).json(updatedUser);
    } catch (error) {
        console.log("Error in updateProfile: ",error.message)
        res.status(500).json({message: 'Something went wrong'})
    }
}

export const checkAuth = async (req,res) =>{
    try {
        res.status(200).json(req.user);
    } catch (error) {
        console.log("Error in checkAuth: ",error.message)
        res.status(500).json({message: 'Something went wrong'})
    }
}