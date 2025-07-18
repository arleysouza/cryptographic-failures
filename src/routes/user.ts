import {Router} from "express";
import { getEncryptedProfile, loginSecure, register, registerSecure } from "../controllers/user.controller";
import { authentication } from "../middlewares";

const router = Router();

router.post("/register", register);
router.post("/register-secure", registerSecure);
router.post("/login-secure", loginSecure);
router.post("/profile-encrypted", authentication, getEncryptedProfile);

export default router;