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

function adminLogin(credentials) {
  return new Promise((resolve, reject) => {
    
    // resolve({
    //   success:false,
    //   errorCode:401,
    //   errorMessage:"Invalid username, password, or OTP"
    // });

    const payload = {
      "id":1,
      "type":3
    }
    const token = jwt.sign(payload, process.env.JWT_SECRET_KEY, {expiresIn: "1d"});
    resolve({
      success:true,
      jwt:token
    });
  })
};

function login(loginValues) {
  return new Promise(async(resolve, reject) => { 
    try {
      const secretQuery = `
        SELECT convert_from(decrypt(users_otp_key::bytea, '${process.env.DATABASE_PASSWORD_ENCRYPTION_KEY}', 'aes'), 'SQL_ASCII')
        FROM users
        WHERE users_email=$1;`;
      const secretRequest = await pool.query(secretQuery,[loginValues.user.toLowerCase()]);
      if (secretRequest.rows.length === 0) {resolve({"error":401,"message":"authentication error"})}
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
            const userValues = [loginValues.user,loginValues.pass]
            const userInfo = await pool.query(userQuery,userValues);
            if (userInfo.rowCount > 0) {
              if (!userInfo.rows[0].users_verified) resolve({"error":601,"message":"account not verified"})
              if (userInfo.rows[0].users_enabled && userInfo.rows[0].users_verified) {
                const payload = {
                  "id":userInfo.rows[0].users_id,
                  "type":userInfo.rows[0].users_fk_type
                }
                const token = jwt.sign(payload, process.env.JWT_SECRET_KEY, {expiresIn: "1d"});
                resolve({"jwt":token});
              }
              if (!userInfo.rows[0].users_enabled && userInfo.rows[0].users_verified) resolve({"error":402,"message":"account disabled"})
            }
            if (userInfo.rowCount === 0) resolve({"error":401,"message":"authentication error"})
          }
          catch (err) {resolve({"error":401,"message":"authentication error"})}
        }
        if (!isVerified) resolve({"error":401,"message":"otp authentication error"})
      }
    }
    catch (err) {resolve({"error":401,"message":"authentication error 66"})}
   }) 
}

function register(registrationValues) {
  return new Promise(async(resolve, reject) => {
    const isVerified = speakeasy.totp.verify({
      secret: registrationValues.otpsecret,
      encoding: 'base32',
      token: registrationValues.otp
    });
    if (!isVerified) {resolve({"code":601,"message":"invalid OTP code"})}
    if (isVerified) {
      const userExists = await pool.query(`SELECT(EXISTS(SELECT FROM users WHERE users_email=$1))`,[registrationValues.email.toLowerCase()]);
      if (userExists.rows[0].exists) {
        email_model.sendAccountExistsEmail(registrationValues.email.toLowerCase())
        resolve({"code":200})
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
          resolve({"code":200})
        })
      }
    }
  })
}

function generateQr() {
  const secret = speakeasy.generateSecret();
  const otpAuthUrl = speakeasy.otpauthURL({ secret: secret.ascii, label: 'E.R.V.A.', algorithm: 'sha512' });
  return new Promise((resolve, reject) => {
    QRCode.toDataURL(otpAuthUrl, (err, data_url) => {
      if(err) reject(err)
      resolve({"qrcode":data_url,"secret":secret});
    });
  });
};

function verifyAccount(token) {
  return new Promise(async(resolve,reject) => {
    if (!token) reject({"code":500,"error":"No verification token presented to the server."});
    if (token) {
      const tokenIsValid = await verifyJwt_model.verifyJwtInternal(token);
      if (!tokenIsValid.verified) {
        switch (tokenIsValid.error) {
          case "jwt expired":
            reject({"code":403,"error":"Verification token has expired."})
            break;
          case "jwt malformed":
            reject({"code":498,"error":"The server was presented with an invalid token"});
            break;
          default: reject({"code":498,"error":"An error occured while attempting to verify the account."})
        } 
      }
      if (tokenIsValid.verified && tokenIsValid.result.type !== "emailVerification") reject({"code":498,"error":"The server was presented with an invalid token"})
      if (tokenIsValid.verified && tokenIsValid.result.type === "emailVerification"){
        pool.query(`UPDATE users SET users_verified='true' WHERE users_email=$1`,[tokenIsValid.result.email], (error) => {
          if (error) reject({"code":500,"message":"an error occured verifying account."})
          resolve({"code":200});
        });
      };
    }
  });
};

function forgotPassword(email) {
  return new Promise(async(resolve) => {
    const userExists = await pool.query(`SELECT(EXISTS(SELECT FROM users WHERE users_email=$1))`,[email.toLowerCase()]);
    if (!userExists.rows[0].exists) resolve();
    if (userExists.rows[0].exists) {
      //sign JWT with user's encrypted password to create one time use JWT. If the password is reset, the encrypted password value will be different, and the JWT verify will fail.
      const userValues = await pool.query('SELECT users_id, users_email, users_password FROM users WHERE users_email=$1',[email.toLowerCase()])
      const payload = {
        userId:userValues.rows[0].users_id,
        userEmail:userValues.rows[0].users_email
      }
      const resetToken = jwt.sign(payload, userValues.rows[0].users_password, {expiresIn: "1h"});
      email_model.sendForgotEmail(email.toLowerCase(),resetToken)
      resolve();
    }
  })
}

function resetPassword(resetToken, newPassword) {
  return new Promise(async(resolve) => {
    const userId = jwt.decode(resetToken).userId
    if (userId === null) resolve({"code":498,"error":"The server was presented with an invalid token"})
    if (userId !== null) {
      const jwtSignature = await pool.query('SELECT users_password FROM users WHERE users_id=$1',[userId]);
      jwt.verify(resetToken, jwtSignature.rows[0].users_password, (err, result) => {
        if (err) resolve({"code":498,"error":"The server was presented with an invalid token"})
        if (result) {
          pool.query("UPDATE users SET users_password=crypt($1, gen_salt('bf'))",[newPassword],(error,result) => {
            if (error) resolve({"code":500,"message":"an error occured while attemting to change password."})
            resolve({"code":200})
          });
        };
      });
    };
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
    const isVerified = await verifyJwt_model.verifyJwtInternal(token);
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
  adminLogin,
  generateQr,
  login,
  register,
  verifyAccount,
  forgotPassword,
  resetPassword,
  setApiKey,
  getApiKey
}