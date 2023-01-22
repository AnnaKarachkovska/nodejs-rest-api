const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const gravatar = require("gravatar");
const path = require("path");
const fs = require("fs/promises");
const Jimp = require("jimp");
const { nanoid } = require("nanoid");

const { HttpError, sendEmail } = require("../helpers");
const User = require("../models/user");

const { SECRET_KEY, BASE_URL } = process.env;

const register = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (user) {
      throw HttpError(409, "Email is in use.");
    }

    const hashPassword = await bcrypt.hash(password, 10);
    const avatarURL = gravatar.url(email);

    const verificationToken = nanoid();

    const newUser = await User.create({
      ...req.body,
      password: hashPassword,
      avatarURL,
      verificationToken
    });

    const verifyEmail = {
      to: email,
      subject: "Verify email",
      html: `<a target="_blank" href="${BASE_URL}/api/auth/verify${verificationToken}">Click to verify your email</a>`
    }

    await sendEmail(verifyEmail);

    res.json({
      status: "User created",
      code: 201,
      data: {
        email: newUser.email,
        subscription: newUser.subscription,
      },
    });
  } catch (er) {
    next(er);
  }
};

const verify = async (req, res, next) => {
  try {
    const {verificationToken} = req.params;
    const user = await User.findOne({verificationToken});
    if(!user) {
      throw HttpError(404, "User is not found.");
    }
    await User.findByIdAndUpdate(user._id, {verify: true, verificationToken: ""});
    res.json({
      message: "Verification successful."
    })
  }
  catch(er) {
    next(er);
  }
};

const verifyRepeat = async (req, res, next) => {
  try {
    const { email } = req.body;
    const {verificationToken} = req.params;
    const user = await User.findOne({verificationToken});
    if (!user) {
      throw HttpError(404, "User is not found.");
    }

    if (user.verify) {
      throw HttpError(400, "Verification has already been passed.")
    }

    const verifyEmail = {
      to: email,
      subject: "Verify email",
      html: `<a target="_blank" href="${BASE_URL}/api/auth/verify${verificationToken}">Click to verify your email</a>`
    }

    await sendEmail(verifyEmail);

    res.json({
      message: "Verification email sent."
    })
  }
  catch (er) {
    next(er);
  }
};

const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      throw HttpError(401, "Email or password is wrong.");
    }

    if(!user.verify) {
      throw HttpError(400, "Email was not verified.")
    }

    const passwordCompare = await bcrypt.compare(password, user.password);
    if (!passwordCompare) {
      throw HttpError(401, "Email or password is wrong.");
    }

    const payload = {
      id: user._id,
    };

    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "23h" });
    await User.findByIdAndUpdate(user._id, { token });

    res.json({
      token,
      user: {
        email: user.email,
        subscription: user.subscription,
      },
    });
  } catch (er) {
    next(er);
  }
};

const getCurrent = async (req, res, next) => {
  try {
    const { email, subscription } = req.user;
    res.json({
      email,
      subscription,
    });
  } catch (er) {
    next(er);
  }
};

const logout = async (req, res, next) => {
  try {
    const { _id } = req.user;
    await User.findByIdAndUpdate(_id, { token: "" });

    res.json({
      code: 204,
      message: "No Content",
    });
  } catch (er) {
    next(er);
  }
};

const updateSubscription = async (req, res, next) => {
  try {
    const { _id } = req.user;

    await User.findByIdAndUpdate(_id, req.body);

    res.json({
      status: "success",
      code: 200,
      message: "Subscription was updated successfully.",
    });
  } catch (er) {
    next(er);
  }
};

const avatarDir = path.join(__dirname, "../", "public", "avatars");
const updateAvatar = async (req, res, next) => {
  try {
    if (!req.file) {
      throw HttpError(400, "Avatar was not attached.");
    }

    const { _id } = req.user;
    const { path: tempUpload, originalname } = req.file;

    const fileName = `${_id}_${originalname}`;
    const resultUpload = path.join(avatarDir, fileName);
    await fs.rename(tempUpload, resultUpload);

    const avatarURL = path.join("avatars", fileName);

    await Jimp.read(`./public/${avatarURL}`)
      .then((avatar) => {
        return avatar
          .resize(250, 250) 
          .write(`./public/${avatarURL}`);
      })
      .catch((err) => {
        console.error(err);
    });

    await User.findByIdAndUpdate(_id, { avatarURL });

    res.json({
      avatarURL,
    });
  } catch (er) {
    next(er);
  }
};

module.exports = {
  register,
  login,
  getCurrent,
  logout,
  updateSubscription,
  updateAvatar,
  verify,
  verifyRepeat
};
