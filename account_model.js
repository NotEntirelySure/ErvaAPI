//allows access to .env file for environment variable declaration
require('dotenv').config();
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const QRCode = require('qrcode');
const verifyJwt_model = require('./verifyJwt_model');
const email_model = require('./email_model');
const Pool = require('pg').Pool
const pool = new Pool({
  user: process.env.API_BASE_USER_ACCOUNT,
  host: process.env.API_BASE_HOST_URL,
  database: process.env.API_BASE_DATABASE_NAME,
  password: process.env.API_BASE_DATABASE_PASSWORD,
  port: process.env.API_BASE_PORT_NUMBER,
});

function login(loginValues) {
  return new Promise(async(resolve, reject) => { 
    try {
      const secretQuery = `
        SELECT convert_from(decrypt(users_otp_key::bytea, '${process.env.DATABASE_PASSWORD_ENCRYPTION_KEY}', 'aes'), 'SQL_ASCII')
        FROM users
        WHERE users_email=$1;`;
      const secretRequest = await pool.query(secretQuery,[loginValues.username.toLowerCase()]);
      if (secretRequest.rows.length === 0) resolve({
        success:false,
        errorCode:401,
        errorMessage:"Your username, password, or one-time password is incorrect."})
      if (secretRequest.rows.length > 0) {
        const isVerified = speakeasy.totp.verify({
          secret:secretRequest.rows[0].convert_from,
          encoding: 'base32',
          token:loginValues.otp
        });
        if (isVerified) {
          try {
            const userQuery = `
              SELECT
                users_id,
                users_first_name,
                users_last_name,
                users_email,
                users_enabled,
                users_verified,
                at.at_name
              FROM users
              INNER JOIN accounttypes AS at
              ON users.users_fk_type=at.at_id
              WHERE users_email=$1 AND users_password=crypt($2, users_password);`;
            const userInfo = await pool.query(userQuery,[loginValues.username, loginValues.password]);
            if (userInfo.rowCount > 0) {
              if (!userInfo.rows[0].users_verified) resolve({
                success:false,
                errorCode:601,
                errorMessage:"account not verified"
              });
              if (!userInfo.rows[0].users_enabled) resolve({
                success:false,
                errorCode:402,
                errorMessage:"account disabled"
              });
              if (userInfo.rows[0].users_enabled && userInfo.rows[0].users_verified) {
                const payload = {
                  "id":userInfo.rows[0].users_id,
                  "type":userInfo.rows[0].users_fk_type
                };
                const token = jwt.sign(payload, process.env.JWT_SECRET_KEY, {expiresIn: "1d"});
                resolve({success:true, jwt:token});
              };
            };
            if (userInfo.rowCount === 0) resolve({
              success:false,
              errorCode:401,
              errorMessage:"Your username, password, or one-time password is incorrect."});
          }
          catch (err) {
            resolve({
              success:false,
              errorCode:401,
              errorMessage:"authentication error"
            });
          };
        }
        if (!isVerified) resolve({
          success:false,
          errorCode:401,
          errorMessage:"Your username, password, or one-time password is incorrect."})
      };
    }
    catch (err) {
      resolve({
        success:false,
        errorCode:401,
        errorMessage:"authentication error"
      });
    };
  }); 
};

function register(registrationValues) {
  return new Promise(async(resolve, reject) => {
    try {
      const isVerified = speakeasy.totp.verify({
        secret: registrationValues.otpsecret,
        encoding: 'base32',
        token:registrationValues.otp
      });
      if (!isVerified) resolve({
        success:false,
        code:601,
        message:"invalid OTP code"
      });
      if (isVerified) {
        const userExists = await pool.query(`SELECT(EXISTS(SELECT FROM users WHERE users_email=$1))`,[registrationValues.email.toLowerCase()]);
        if (userExists.rows[0].exists) {
          email_model.sendAccountExistsEmail(registrationValues.email.toLowerCase());
          resolve({success:true});
        }
        if (!userExists.rows[0].exists) {
          const userValues = [
            registrationValues.fname,
            registrationValues.lname,
            registrationValues.email.toLowerCase(),
            registrationValues.password,
            registrationValues.otpsecret
          ];
          const userQuery = `
            INSERT INTO users (
              users_first_name,
              users_last_name,
              users_email,
              users_password,
              users_created_at,
              users_fk_role,
              users_fk_type,
              users_otp_key,
              users_enabled,
              users_verified
            )
            VALUES (
              $1,
              $2,
              $3,
              crypt($4, gen_salt('bf')),
              (SELECT NOW()),
              2,
              4,
              encrypt($5, '${process.env.DATABASE_PASSWORD_ENCRYPTION_KEY}', 'aes'),
              'true',
              'false'
            );`
          pool.query(userQuery, userValues, (error) => {
            if (error) reject(error)
            email_model.sendVerifyEmail(registrationValues.email.toLowerCase())
            resolve({success:true})
          })
        }
      }
    }
    catch(err) {
      console.log(err);
      resolve({
        success:false,
        code:500,
        message:"an internal server error occured while attempting to register your account."
      });
    };
  });
};

function generateQr() {
  const secret = speakeasy.generateSecret();
  const otpAuthUrl = speakeasy.otpauthURL({ secret: secret.ascii, label: 'E.R.V.A.'});
  return new Promise((resolve, reject) => {
    QRCode.toDataURL(otpAuthUrl, (err, data_url) => {
      if(err) reject(err)
      resolve({
        qrcode:data_url,
        secret:secret
      });
    });
  });
};

function verifyAccount(token) {
  return new Promise(async(resolve,reject) => {
    try {
      if (!token) reject({"code":500,"error":"No verification token presented to the server."});
      if (token) {
        const tokenIsValid = await verifyJwt_model._verifyJwt(token);
        if (!tokenIsValid.verified) {
          switch (tokenIsValid.error) {
            case "jwt expired":
              reject({
                success:false,
                code:403,
                error:"Verification token has expired."
              });
              break;
            case "jwt malformed":
              reject({
                success:false,
                code:498,
                error:"The server was presented with an invalid token"
              });
              break;
            default: reject({
              success:false,
              code:498,
              error:"An error occured while attempting to verify the account."
            });
          };
        };
        if (tokenIsValid.verified && tokenIsValid.result.type !== "emailVerification") reject({
          success:false,
          code:498,
          error:"The server was presented with an invalid token"
        });
        if (tokenIsValid.verified && tokenIsValid.result.type === "emailVerification"){
          pool.query(`UPDATE users SET users_verified='true' WHERE users_email=$1`,[tokenIsValid.result.email], (error) => {
            if (error) reject({
              success:false,
              code:500,
              message:"An error occured verifying account."})
            resolve({success:true});
          });
        };
      }
    }
    catch (err) {
      console.log(err);
      resolve({
        succes:false,
        code:500,
        error:"An internal server error occured while attempting to verify your account."
      });
    };
  });
};

function forgotPassword(email) {
  return new Promise(resolve => {
    const response = {
      success: true,
      message: 'Your password reset request was successfully submitted. If the account exists, an email will be sent to the provided email address with a link to reset your password.'
    }
    try {
      pool.query('SELECT * FROM forgot_password($1)',
        [email.toLowerCase()],
        (error, results) => {
          if (results.rowCount > 0) {
            const payload = {
              id:results.rows[0].id,
              email:results.rows[0].email
            }
            const resetToken = jwt.sign(payload, results.rows[0].password, {expiresIn: "1h"});
            email_model.sendForgotEmail(email.toLowerCase(),resetToken)
            resolve(response);
          };
        }
      );
      resolve(response);
    }
    catch (error){resolve({success:false, message:"An error occured when processing your requesnt. Please try again later. If the problem persists, contact the system administrator."})}
  });
}

function resetPassword(data) {
  return new Promise(async(resolve) => {
    try {
      if (data.newPassword !== data.confirmPassword) resolve({success:false, message:"The provided passwords do not match"});
      const userId = jwt.decode(data.resetToken).id;
      if (!userId) resolve({success:false, message:"The server was presented with an invalid token"})
      if (userId) {
        const jwtSignature = await pool.query('SELECT users_password FROM users WHERE users_id=$1',[userId]);
        jwt.verify(data.resetToken, jwtSignature.rows[0].users_password, (err, result) => {
          if (err) {
            switch(err.name) {
              case "TokenExpiredError": 
                resolve({success:false, message:"The password reset token has expired."});
                break;
              case "JsonWebTokenError":
                resolve({success:false, message:"The server was presented with an invalid token"});
                break;
              default: resolve({success:false, message:"The server was presented with an invalid token"});
            };
          };
          if (result) {
            pool.query(
              `UPDATE users
              SET users_password=crypt($1, gen_salt('bf'))
              WHERE users_id=$2;`,
              [data.newPassword, userId],
              (error,result) => {
                if (error) resolve({success:false,message:"an error occured while attemting to change your password."})
                resolve({success:true, message:"Your password was successfully changed."})
            });
          };
        });
      };
    }
    catch (error) {
      console.log(error);
      resolve({success:false, message:"An unexpected error occured."})};
  });
};

function setApiKey(userId, apiKey) {
  return new Promise((resolve, reject) => {
    pool.query(`
      UPDATE users
      SET users_api_key=encrypt($1, '${process.env.DATABASE_PASSWORD_ENCRYPTION_KEY}', 'aes')
      WHERE users_id=$2;
      `,[userId, apiKey], (result, error) => {
        if (error) reject({"code":500})
        resolve({"code":200})
    });
  });
};

function getApiKey(token) {
  return new Promise(async(resolve, reject) => {
    const isVerified = await verifyJwt_model._verifyJwt(token);
    if (isVerified.verified === false) resolve(isVerified.error);
    if (isVerified.verified === true) {
      try { 
        pool.query(`
          SELECT convert_from(decrypt(users_api_key::bytea, '${process.env.DATABASE_PASSWORD_ENCRYPTION_KEY}', 'aes'), 'SQL_ASCII')
          FROM users
          WHERE users_id=$1
          `,[isVerified.result.id], (error, result) => {
              if (error) reject({"code":500})
              resolve({"code":200,"apiKey":result.rows[0].convert_from})
            }
        );
      }
      catch {reject({"code":500})}
    }  

  });
};

module.exports = {
  generateQr,
  login,
  register,
  verifyAccount,
  forgotPassword,
  resetPassword,
  setApiKey,
  getApiKey
}