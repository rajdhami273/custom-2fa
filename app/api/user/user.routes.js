module.exports = (user) => {
  return {
    options: {
      defaultRoutes: false,
    },
    routes: [
      {
        action: "POST",
        path: "/login",
        resolve: user.login,
      },
      {
        action: "POST",
        path: "/register",
        resolve: user.register,
      },
      {
        action: "POST",
        path: "/generate-code",
        before: [pie.middlewares.auth()],
        resolve: user.generateOTP,
      },
      {
        action: "POST",
        path: "/verify-code",
        before: [pie.middlewares.auth()],
        resolve: user.verifyOTP,
      },
      //   {
      //     action: "GET",
      //     path: "/all",
      //     before: [
      //       // pie.middlewares.auth()
      //     ],
      //     resolve: user.getAll,
      //   },
      {
        action: "GET",
        path: "/me",
        before: [pie.middlewares.auth()],
        resolve: user.getMe,
      },
      {
        action: "PUT",
        path: "/edit-profile",
        before: [pie.middlewares.auth()],
        resolve: user.editProfile,
      },
      {
        action: "PUT",
        path: "/change-password",
        before: [pie.middlewares.auth()],
        resolve: user.changePassword,
      },

      // Forgot password
      {
        action: "PUT",
        path: "/send-reset-password-link",
        before: [
          // pie.middlewares.auth()
        ],
        resolve: user.sendResetPasswordLink,
      },
      {
        action: "PUT",
        path: "/reset-password/:forgotPasswordHash/:userId",
        before: [
          // pie.middlewares.auth()
        ],
        resolve: user.resetPassword,
      },
      // Forgot password END
    ],
  };
};
