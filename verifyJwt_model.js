//allows access to .env file for environment variable declaration
//require('dotenv').config({path:'C:/ErvaAPI/API_Prod_Build/.env'});
require('dotenv').config();

const jwt = require("jsonwebtoken");
const { resolve } = require('path');

function verifyJwt(token) {
  return new Promise((resolve, reject) => {
    if (token) {
      jwt.verify(token, process.env.JWT_SECRET_KEY, (err, result) => {
        if(err) {
          if(err.message = "jwt expired") resolve({"errorCode":498, "error":"token expired"})
          resolve({"errorCode":401, "error":"invalid token"});
        };
        if(result) resolve({"result":result});
      });
    }
    else {resolve({"errorCode":401, "error":"invalid token"});};
  });
};

function _verifyJwt(token) {
  return new Promise((resolve) => {
    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, result) => {
      if(err) {
        let message;
        switch (err.name) {
          case "TokenExpiredError":
            message = "Your account verification token has expired. Please contact the system administrator to resend the acconut verification email.";
            break;
          case "JsonWebTokenError":
            message = "The server was presented with an invalid account verification token.";
            break;
          default: message = "An error occured while attempting to verify your account.";
        };
        resolve({verified:false, error:message})
      }
      if(result) resolve({verified:true, "result":result})
    });
  });
};

module.exports = {
  verifyJwt,
  _verifyJwt
}
