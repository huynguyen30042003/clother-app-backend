import express from 'express';
import authRouter from './routers/auth';
import { connectDB } from './config/db';
import dotenv from "dotenv";
import morgan from "morgan";
import cors from 'cors';

const app = express();
dotenv.config()
// middleware
app.use(express.json());
app.use(cors());
app.use(morgan("tiny"))

// connect db
connectDB(process.env.DB_URI)

// routes
app.use('/api/v1', authRouter);

app.get('/',(req, res) => res.json("api clother app"))
export const viteNodeApp = app;
