import express from 'express';
import { signin, signup, getAll, getByEmail, getCurrentUser, refreshToken, logout } from '../controllers/auth';
import { admin } from '../middleware/auth';

const router = express.Router();

router.post("/auth/signup",signup)
router.post("/auth/signin",signin)
router.get("/auth/getall",admin,getAll)
router.get("/auth/getByEmail",admin,getByEmail)
router.get("/auth/getCurrentUser",getCurrentUser)
router.post("/auth/refreshToken",refreshToken)
router.post("/auth/logout",logout)

export default router;