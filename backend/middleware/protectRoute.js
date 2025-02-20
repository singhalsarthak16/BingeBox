import jwt from "jsonwebtoken"
import { ENV_VARS } from "../config/envVars.js";
import { User } from "../models/user.model.js";


export const protectRoute = async (req , res, next) => {
    try {
        const token = req.cookies["jwt-bingebox"]

        if(!token){
            return res.status(401).json({succes : false, message : "Unautorized - No Token Provided"})
        }
        const decoded = jwt.verify(token, ENV_VARS.JWT_SECRET);
        if(!decoded){
            return res.status(401).json({succes : false, message : "Unautorized - Invalid token"})
        }

        const user = await User.findById(decoded.userId).select("-password");
        if(!user){
            return res.status(401).json({succes : false, message : "User not found"})
        }

        req.user = user;

        next();

    } catch (error) {
        console.log("Error in protectRoute middleware: ", error.message);
        res.status(500).json({succes : false, message : "Internal Server Error"})

    }
}