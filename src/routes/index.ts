import express from "express";
import user from "./user";
import crypto from "./crypto";

const router = express.Router();

router.use("/user", user);
router.use("/crypto", crypto);

export default router;
