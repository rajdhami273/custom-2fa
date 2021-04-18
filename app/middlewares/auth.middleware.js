module.exports = function (...args) {
  return ({ req, next, reject }) => {
    // For optional authorization
    if (!req.headers.authorization) {
      if (args.length > 0 && args.indexOf("optional") >= 0) {
        return next();
      } else {
        return reject({
          status: 403,
          message: "Token not provided",
        });
      }
    }
    let optionalIndex = args.indexOf("optional");
    if (optionalIndex >= 0) {
      args.splice(optionalIndex, 1);
    }

    let auth = req.headers.authorization;
    pie.models.user
      .getSession(auth, ...args)
      .then((user) => {
        req.user = user;
        next();
      })
      .catch((err) => {
        return reject({
          message: err.message || "Unknow error occured",
        });
      });
  };
};
