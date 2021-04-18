const { jsonwebtoken: jwt, bcryptjs, randomstring } = pie.packages;
const { tokenSecret } = pie.config;

const hasher = (password) => {
  return bcryptjs.hashSync(password, 10);
};

module.exports = (connection) => {
  return {
    schema: {
      firstName: {
        type: String,
        // default: ""
        required: true,
      },
      lastName: {
        type: String,
        default: "",
      },
      email: {
        type: String,
        default: null,
      },
      password: {
        type: String,
        required: true,
      },
      forgotPasswordHash: {
        type: String,
        default: null,
      },
      mobile: {
        type: String,
        required: true,
      },
      secret: {
        type: String,
        required: true,
      }
    },
    options: {
      timestamps: true,
    },
    statics: {
      getSession(auth, ...args) {
        return new Promise((resolve, reject) => {
          if (auth.split(" ")[0] == "Bearer") {
            jwt.verify(auth.split(" ")[1], tokenSecret, (err, decoded) => {
              if (err) {
                return reject({
                  status: 403,
                  message: err.message || "Invalid token",
                });
              }
              this.findById(decoded.user)
                .select("-password")
                .then((user) => {
                  if (user) {
                    // let accessLevel = req.headers['access-level'];
                    let accessLevel = null;
                    if (
                      !accessLevel ||
                      (accessLevel == "admin" && user.isAdmin)
                    ) {
                      return resolve(user);
                    } else {
                      return reject({
                        status: 401,
                        message: "Not allowed",
                      });
                    }
                  } else {
                    return reject({
                      status: 403,
                      message: "Invalid user",
                    });
                  }
                })
                .catch((err) => {
                  return reject({
                    status: 500,
                    message: err.message || "Unknown error occurred",
                  });
                });
            });
          } else {
            return reject({
              status: 403,
              message: "Invalid token",
            });
          }
        });
      },
    },
    methods: {
      comparePassword(password) {
        return bcryptjs.compareSync(password, this.password);
      },
      hashPassword() {
        console.log(this.password);
        this.password = hasher(this.password);
      },
      generateSession() {
        let token = jwt.sign(
          {
            user: this._id,
          },
          tokenSecret,
          {
            expiresIn: 60 * 60 * 24 * 30,
          }
        );
        return Promise.resolve({
          token,
        });
      },
      changePassword(oldPassword, newPassword) {
        return promise.then(() => {
          if (!this.password || this.comparePassword(oldPassword)) {
            this.password = newPassword;
            this.hashPassword();
            return this.save();
          } else {
            return Promise.reject({
              status: 405,
              message: "Old password does not match",
            });
          }
        });
      },
      sendResetPasswordLink() {
        const forgotPasswordHash = randomstring.generate({
          length: 6,
          charset: "number",
        });
        this.forgotPasswordHash = forgotPasswordHash;
        return this.save().then(() => {
          const link =
            "http://localhost:3000/reset-password/" +
            forgotPasswordHash +
            "/" +
            this._id;

          pie.services.mailer.sendMail({
            from: '"Custom2fa" <rajdhami273@gmail.com>', // sender address
            to: this.email, // list of receivers
            subject: "Forgot password", // Subject line
            html: '' 
          });
        });
      },
      resetPassword(newPassword) {
        return new Promise((resolve, reject) => {
          this.forgotPasswordHash = null;
          this.password = newPassword;
          this.hashPassword();
          return resolve(this.save());
        });
      },
    },

    plugins: [
      [
        pie.packages.mongooseSequence(connection),
        { id: "user_id_counter", inc_field: "userId" },
      ],
    ],
  };
};
