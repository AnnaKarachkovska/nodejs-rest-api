const express = require('express');
const router = express.Router();

const { register, login, getCurrent, logout, updateSubscription, updateAvatar, verify, verifyRepeat } = require("../../controllers/auth")
const { authenticate, joiAuthValidation, upload } = require("../../middlewares")

router.post("/register", joiAuthValidation.register, register);

router.post("/login", joiAuthValidation.register, login);

router.get("/current", authenticate, getCurrent);

router.post("/logout", authenticate, logout);

router.patch("/users", authenticate, joiAuthValidation.subscription, updateSubscription);

router.patch("/users/avatars", authenticate, upload.single("avatar"), updateAvatar);

router.get("/users/verify/:verificationToken", verify);

router.post("/users/verify", joiAuthValidation.verify, verifyRepeat);

module.exports = router;