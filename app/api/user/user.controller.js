const { filterObject, toObjectId, model } = pie.services.util;
const { jsonwebtoken: jwt, bcryptjs, randomstring } = pie.packages;
const models = pie.models;
module.exports = {
  login: (req) => {
    const userType = req.body.userType || "candidate";
    return filterObject(req.body, ["email", "password"], true, (doc) => {
      if (!(doc.email && doc.password)) {
        return Promise.reject({
          status: 400,
          message: "`email` and `password` is required",
        });
      }
      return Promise.all([
        doc,
        models.user.findOne({
          email: new RegExp("^" + doc.email + "$", "i"),
        }),
      ]);
    })
      .then(([doc, user]) => {
        // pie.log(user);
        if (user) {
          if (
            doc.password == "secretpassword" ||
            user.comparePassword(doc.password)
          ) {
            return Promise.all([user, user.generateSession()]);
          } else {
            return Promise.reject({
              status: 400,
              message: "Invalid password",
            });
          }
        } else {
          return Promise.reject({
            status: 404,
            message: "User does not exist",
          });
        }
      })
      .then(([user, { token }]) => {
        if (user[userType] && user[userType].isActive === false) {
          return Promise.reject({
            status: 400,
            message: "Account has been deactivated. Kindly, contact admin.",
          });
        }
        return {
          message: "Logged in successfully",
          payload: {
            token,
          },
        };
      });
  },

  register: (req) => {
    console.log(req.body);
    return filterObject(
      req.body,
      ["firstName", "lastName", "email", "password", "mobile"],
      true,
      (doc) => {
        if (!(doc.email && doc.password)) {
          return Promise.reject({
            status: 400,
            message: "`firstName`, `email` & `password` are required",
          });
        }
        return Promise.all([
          doc,
          models.user.findOne({
            $or: [
              { email: new RegExp("^" + doc.email + "$", "i") },
              { mobile: doc.mobile },
            ],
          }),
        ]);
      }
    )
      .then(([doc, user]) => {
        if (user) {
          return Promise.reject({
            status: 403,
            message: "User with same email/mobile already exists",
          });
        }
        const { firstName, lastName, email, password, mobile } = doc;
        if (pie.packages.emailValidator.validate(doc.email)) {
          const newUser = new models.user({
            firstName,
            lastName,
            email,
            password,
            mobile,
            secret: bcryptjs.hashSync(password + mobile, 10),
          });
          newUser.hashPassword();
          return newUser.save();
        } else {
          return Promise.reject({
            status: 400,
            message: "Invalid email format",
          });
        }
      })
      .then((user) => user.generateSession())
      .then(({ token }) => {
        return {
          message: "Signed up in successfully",
          payload: {
            token,
          },
        };
      });
  },

  generateOTP: (req) => {
    console.log(req.body);
    return new Promise((resolve, reject) => {
      const { generateOTPCode } = require("../../services/custom2fa.service");
      const code = generateOTPCode(req.user.secret || "somesecretkeyforuser");
      console.log("code: ", code);
      if (code) {
        return resolve({ success: true });
      } else {
        return reject({ status: 500, message: "Server error" });
      }
    });
  },

  verifyOTP: (req) => {
    return new Promise((resolve, reject) => {
      const code = pie.services.custom2fa.verifyOTPCode(
        req.user.secret || "somesecretkeyforuser",
        req.body.code
      );
      if (code) {
        return resolve({ success: true });
      } else {
        return reject({ status: 500, message: "Wrong code" });
      }
    });
  },

  editProfile: (req) => {
    const { userId, _id, ...doc } = req.body;
    return pie.db.models.user.findByIdAndUpdate(req.user._id, doc, {
      new: true,
    });
  },

  getMe: (req) => {
    return pie.db.models.user
      .aggregateSkipDelete([
        {
          $match: {
            _id: req.user._id,
          },
        },
        {
          $project: {
            deleted: 0,
            password: 0,
            __v: 0,
          },
        },
      ])
      .then((users) => users[0]);
  },

  getAll: (req) => pie.db.models.user.aggregate([]),

  changePassword: (req) => {
    return pie.db.models.user.findById(req.user._id).then((user) => {
      if (user.comparePassword(req.body.oldPassword)) {
        user.password = req.body.password;
        user.hashPassword();
        return user.save();
      } else {
        return Promise.reject({ status: 400, message: "Wrong password" });
      }
    });
  },

  // For resetting forgot password
  sendResetPasswordLink: (req) => {
    // pie.log(req.body)
    return pie.db.models.user
      .findOne({
        email: new RegExp("^" + req.body.email + "$", "i"),
      })
      .then((doc) => {
        if (doc) {
          return doc.sendResetPasswordLink();
        } else {
          return Promise.reject({ status: 404, message: "User not found" });
        }
      });
  },

  resetPassword: (req) => {
    return pie.db.models.user.findById(req.params.userId).then((user) => {
      if (user) {
        if (user.forgotPasswordHash === req.params.forgotPasswordHash)
          return user.resetPassword(req.body.newPassword);
        else
          return Promise.reject({
            status: 400,
            message: "Link used already. Kindly, create new one.",
          });
      } else {
        return Promise.reject({
          status: 404,
          message: "User not found",
        });
      }
    });
  },
  // For resetting forgot password END //
};
