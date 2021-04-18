const { jsonwebtoken: jwt, bcryptjs, randomstring } = pie.packages;
const crypto = require("crypto");
const fn = {
  /**
   *** Description:
   * This method generates a TOTP based on user's secret and current time
   *** Input:
   * User's Secret key
   *** Output:
   * TOTP
   **/
  generateOTPCode: (secret) => {
    // Length of TOTP
    var length = 6;

    // Counter using Time in Epoch format (1000 is for converting milliseconds to seconds and Step size is 30 seconds).
    var counter = Math.floor(Date.now() / 1000 / 30);
    console.log("counter: ", counter);

    // Creating HMAC_SHA1 using the secret key of user
    var hmac = crypto.createHmac("sha1", secret);
    console.log("hmac: ", hmac);

    // Convering the counter into Bytes (required for giving to HMAC as message)
    var counterBytes = new Array(8).fill(0);
    for (var i = counterBytes.length - 1; i >= 0; i--) {
      counterBytes[i] = counter & 0xff;
      counter = counter >> 8;
    }
    console.log("counterBytes: ", counterBytes);

    // Giving the Counter in Byte format to the HMAC_SHA1 for creating the token
    var token = hmac.update(new Buffer(counterBytes)).digest("hex");
    console.log("token: ", token);

    // Getting the token as Bytes
    var tokenBytes = [];
    for (var i = 0; i < token.length; i += 2) {
      tokenBytes.push(parseInt(token.substr(i, 2), 16));
    }
    console.log("tokenBytes: ", tokenBytes);

    // truncate to 4 bytes
    var offset = tokenBytes[19] & 0xf;
    console.log("offset: ", offset);
    var ourCode =
      ((tokenBytes[offset] & 0x7f) << 24) |
      ((tokenBytes[offset + 1] & 0xff) << 16) |
      ((tokenBytes[offset + 2] & 0xff) << 8) |
      (tokenBytes[offset + 3] & 0xff);

    // Type casting the ourCode: Number to String
    ourCode += "";
    console.log("Unprocessed TOTP code: ", ourCode);

    // Truncate the code to given length
    ourCode = ourCode.substr(ourCode.length - length);

    // Padding 0s if the generated code length is smaller than desired length i.e., 6
    while (ourCode.length < length) {
      ourCode = "0" + ourCode;
    }

    console.log("TOTP code: ", ourCode);
    return ourCode;
  },

  /**
   *** Description:
   * This method verifies a user entered TOTP based on user's secret
   *** Input:
   * User's Secret key
   * User entered code
   *** Output:
   * True (if code matches)
   * False (if code does not match)
   **/
  verifyOTPCode: (secret, code) => {
    if (fn.generateOTPCode(secret) == code) {
      return true;
    }
    return false;
  },
};
module.exports = fn;
