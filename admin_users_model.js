//allows access to .env file for environment variable declaration
require('dotenv').config();
const path = require('path');
const fs = require("fs");
const jwt = require("jsonwebtoken");
const Pool = require('pg').Pool
const pool = new Pool({
  user: process.env.API_BASE_USER_ACCOUNT,
  host: process.env.API_BASE_HOST_URL,
  database: process.env.API_BASE_DATABASE_NAME,
  password: process.env.API_BASE_DATABASE_PASSWORD,
  port: process.env.API_BASE_PORT_NUMBER,
});

function getUsers() {
  return new Promise((resolve, reject) => {
    pool.query(`
      SELECT
        u.users_id,
        u.users_first_name,
        u.users_last_name,
        u.users_email,
        u.users_created_at,
        u.users_enabled,
        u.users_verified,
        r.roles_id,
        r.roles_name,
        at.at_id,
        at.at_name
      FROM users AS u
      LEFT JOIN roles AS r
      ON r.roles_id=u.users_fk_role
      LEFT JOIN accounttypes AS at
      ON at.at_id=u.users_fk_type;`,
      (error, results) => {
        if (error) reject(error)
        const users = results.rows.map(row => ({
          id: row.users_id,
          firstName: row.users_first_name,
          lastName: row.users_last_name,
          email: row.users_email,
          createdAt: new Date(row.users_created_at),
          enabled: row.users_enabled,
          verified:row.users_verified,
          role: {
            id: row.roles_id,
            name: row.roles_name,
          },
          accountType: {
            id: row.at_id,
            name: row.at_name,
          }
          }));
        resolve (users);
      }
    );
  });
};

function updateUser(userData) {
  return new Promise((resolve, reject) => {
    pool.query(
      `UPDATE users
      SET
        users_first_name=$2,
        users_last_name=$3,
        users_enabled=$4,
        users_fk_role=$5,
        users_fk_type=$6
      WHERE users_id=$1;`,
      [
        userData.id,
        userData.firstName,
        userData.lastName,
        userData.enabled,
        userData.role.id,
        userData.accountType.id
      ],
      (error) => {
        if (error) {
          console.log(error);
          resolve({
            success: false,
            userId: userData.id,
            errorCode: error.code,
            errorMessage: error.detail
          });
        };
        resolve({
          success: true,
          userId: userData.id
        });
      }
    );
  });
};

function deleteUser(userId) {
  
  return new Promise((resolve, reject) => {
    pool.query(
      'DELETE FROM users WHERE users_id=$1;',
      [userId],
      (error, result) => {
        if (error) {
          const errorResult = {success: false};
          if (error.code === "23503") {
            errorResult.errorCode = "23503";
            errorResult.errorMessage = "User could not be deleted. User is still referenced in permissions table. Remove user\'s permissions and try again.";
          }
          else {
            errorResult.errorCode = error.code;
            errorResult.errorMessage = error.detail;
          };
          resolve(errorResult);
        };
        resolve({success:true});
    });
  });
};

function getRoles() {
  return new Promise((resolve, reject) => {
    pool.query(
      'SELECT * FROM roles;',
      (error, result) => {
        if (error) reject(error);
        const roles = result.rows.map(entry => (
          {
            id:entry.roles_id,
            name:entry.roles_name
          }
        ))
        resolve(roles);
      });
  });
};

function getAccountTypes() {
  return new Promise((resolve, reject) => {
    pool.query(
      'SELECT * FROM accounttypes;',
      (error, result) => {
        if (error) reject(error);
        const accountType = result.rows.map(entry => (
          {
            id:entry.at_id,
            name:entry.at_name
          }
        ))
        resolve(accountType);
      });
  });
};

function addPermissions(permissions) {
  const executeQuery = async element => {
    return new Promise((resolve, reject) => {
      pool.query(
        `INSERT INTO facilitypermissions (fp_fk_user, fp_fk_facility) VALUES ($1, $2);`,
        [element.userId, element.facilityId],
        (error, results) => {
          if (error) resolve({
              success:false,
              userId:element.userId,
              errorCode:error.code,
              errorMessage:error.message
            });
          resolve({
            success:true,
            userId:element.userId
          });
        }
      );
    });
  };
  return new Promise(async (resolve, reject) => {
    const results = await Promise.all(permissions.map(async element => {
      try {
        const result = await executeQuery(element);
        return result;
      }
      catch (error) {
        console.log(error);
      };
    }));
    resolve(results);
  });
};

function deletePermissions(permissions) {
  const executeQuery = async element => {
    return new Promise((resolve, reject) => {
      pool.query(
        `DELETE FROM facilitypermissions WHERE fp_id=$1`,
        [element.permissionId],
        (error, results) => {
          if (error) {
            resolve({
              success:false,
              permissionId:element.permissionId,
              errorCode:error.code,
              errorMessage:error.message
            });
          };
          resolve({
            success:true,
            permissionId:element.permissionId
          });
        });
    });
  };
  return new Promise(async (resolve, reject) => {
    const results = await Promise.all(permissions.map(async element => {
      try {
        const result = await executeQuery(element);
        return result;
      }
      catch (error) {
        console.log(error);
      };
    }));
    resolve(results);
  });
};

module.exports = {
  getUsers,
  updateUser,
  getRoles,
  getAccountTypes,
  deleteUser,
  addPermissions,
  deletePermissions
}