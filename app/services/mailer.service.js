const nodemailer = require("nodemailer");

let transporter = nodemailer.createTransport({
  host: pie.config.serverAddress,
  port: 587, //587,
  secure: !true, // true for 465, false for other ports
  auth: pie.config.mailerCredentials,
});

// send mail with defined transport object
let params = {
  from: '"Custom-2FA" <rajdhami273@gmail.com>', // sender address
  to: "rajdhami273@gmail.com", // list of receivers
  subject: "Hello ✔", // Subject line
  text: "Hello world?", // plain text body
};

module.exports = {
  sendMail: (overrideParams) => {
    const newParams = Object.assign({}, params, overrideParams);
    return transporter.sendMail(newParams);
  },
};
