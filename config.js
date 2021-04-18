module.exports = {
  PORT: parseInt(process.env.PORT) || 3048,
  mongoUrl: "mongodb://localhost:27017/custom2fa",
  tokenSecret: "custom2fasecret",
  //email
  mailerCredentials: {
    user: "",
    pass: "",
  },
  serverAddress: "smtp.gmail.com", // "smtp.gmail.com",
  // port: 587, // (TLS)
  // port: 465, // (SSL)
  // TLSORSSLrequired: "yes",
};
