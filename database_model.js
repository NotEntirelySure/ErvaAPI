//allows access to .env file for environment variable declaration
require('dotenv').config();
const images_model = require("./images_model");
const jwt = require("jsonwebtoken");
const Pool = require('pg').Pool
const pool = new Pool({
  user: process.env.API_BASE_USER_ACCOUNT,
  host: process.env.API_BASE_HOST_URL,
  database: process.env.API_BASE_DATABASE_NAME,
  password: process.env.API_BASE_DATABASE_PASSWORD,
  port: process.env.API_BASE_PORT_NUMBER,
});

function getOffices(token) {
  return new Promise((resolve, reject) => {
    if(!token) {reject({"errorCode":401, "error":"No JWT provided"})}
    if (token) {
      jwt.verify(token, process.env.JWT_SECRET_KEY, async(err, result) => {
        if(err) reject({"errorCode":401, "error":err});
        if(result) {
          const userOffices = await pool.query(`
          SELECT DISTINCT
            o.offices_id,
            o.offices_name,
            o.offices_address,
            o.offices_city,
            o.offices_state,
            o.offices_zip,
            o.offices_lat,
            o.offices_long
          FROM facilitypermissions as fp
          INNER JOIN facilities AS f ON f.facilities_id=fp.fp_fk_facility
          INNER JOIN offices AS o ON o.offices_id=f.facilities_fk_offices
          WHERE fp.fp_fk_user=${result.id};
          `);
          let officesArray = []
          if (userOffices.rows.length > 0) {
            for (let i=0;i<userOffices.rows.length;i++) {
              officesArray.push({
                "id":userOffices.rows[i].offices_id,
                "name":userOffices.rows[i].offices_name,
                "address":userOffices.rows[i].offices_address,
                "city":userOffices.rows[i].offices_city,
                "state":userOffices.rows[i].offices_state,
                "zip":userOffices.rows[i].offices_zip,
                "lat":userOffices.rows[i].offices_lat,
                "long":userOffices.rows[i].offices_long
              });
            };
          };
          resolve(officesArray);
        };
      });
    };
  });
};

function getFacilitiesByUser(token, officeId) {
  return new Promise((resolve, reject) => {
    if(!token) reject({"errorCode":401, "error":"No JWT provided"});
    if (token) {
      jwt.verify(token, process.env.JWT_SECRET_KEY, async(err, result) => {
        if(err) {reject({"errorCode":401, "error":err});}
        if(result) {
          const userFacilities = await pool.query(`
            SELECT DISTINCT
              f.facilities_id,
              f.facilities_name,
              f.facilities_address,
              f.facilities_city,
              f.facilities_state,
              f.facilities_zip,
              f.facilities_lat,
              f.facilities_long,
              f.facilities_image,
              f.facilities_code
            FROM facilities AS f
            INNER JOIN facilitypermissions AS fp ON fp.fp_fk_facility=f.facilities_id
            WHERE fp.fp_fk_user=${result.id}
            AND f.facilities_fk_offices=${officeId};
          `);
          let facilitiesArray = [];
          if (userFacilities.rows.length > 0) {
            for (let i=0;i<userFacilities.rows.length;i++) {
              const image = images_model._getImage("facilities", userFacilities.rows[i].facilities_image)
              facilitiesArray.push({
                "facilityId":userFacilities.rows[i].facilities_id,
                "name":userFacilities.rows[i].facilities_name,
                "address":userFacilities.rows[i].facilities_address,
                "city":userFacilities.rows[i].facilities_city,
                "state":userFacilities.rows[i].facilities_state,
                "zip":userFacilities.rows[i].facilities_zip,
                "lat":userFacilities.rows[i].facilities_lat,
                "long":userFacilities.rows[i].facilities_long,
                "image":image,
                "code":userFacilities.rows[i].facilities_code
              })
            }
          }
          resolve(facilitiesArray);
        };
      });
    };
  });
};

function getBlueprintsByUser(token, facilityId) {
  
  return new Promise((resolve, reject) => {
    if(!token) {reject({"errorCode":401, "error":"No JWT provided"})}
    if (token) {
      jwt.verify(token, process.env.JWT_SECRET_KEY, async(err, result) => {
        if (err) reject({"errorCode":401, "error":err});
        if (result) {
          const userBlueprints = await pool.query(`
            SELECT
              blueprint_id,
              blueprint_fk_facility_id,
              blueprint_name,
              blueprint_image
            FROM blueprints
            INNER JOIN facilitypermissions AS fp ON fp.fp_fk_facility=blueprints.blueprint_fk_facility_id
            WHERE fp.fp_fk_user=${result.id}
            AND blueprint_fk_facility_id=${facilityId};
          `);
          const blueprintsArray = [];
          if (userBlueprints.rows.length > 0) {
            for (let i=0;i<userBlueprints.rows.length;i++) {
              const image = images_model._getImage("blueprints", userBlueprints.rows[i].blueprint_image)
              blueprintsArray.push({
                "id":userBlueprints.rows[i].blueprint_id,
                "name":userBlueprints.rows[i].blueprint_name,
                "code":userBlueprints.rows[i].blueprint_code,
                "image":image
              })
            }
          }
          resolve(blueprintsArray);
        }
      })
    }
  })

}

function getUserPermissions(userId) {
  
  return new Promise((resolve, reject) => {
    pool.query(
      `SELECT 
        fp.fp_id,
        fp.fp_fk_facility,
        f.facilities_name,
        f.facilities_city
        FROM facilitypermissions AS fp
        INNER JOIN facilities AS f ON fp.fp_fk_facility=f.facilities_id
        WHERE fp.fp_fk_user=$1;
      `,
      [userId],
      (error, results) => {
        if (error) reject(error);
        const permissions = results.rows.map(row => (
          {
            permissionId: row.fp_id,
            facilityId: row.fp_fk_facility,
            facilityName: row.facilities_name,
            facilityCity: row.facilities_city
          }
        ));
      
        resolve(permissions);
      }
    );
  });
};

module.exports = {
  getOffices,
  getFacilitiesByUser,
  getBlueprintsByUser,
  getUserPermissions
}