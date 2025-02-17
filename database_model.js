//allows access to .env file for environment variable declaration
//require('dotenv').config({path:'C:/ErvaAPI/API_Prod_Build/.env'});
require('dotenv').config();
const images_model = require("./images_model");
const jwt = require("jsonwebtoken");
const { _verifyJwt } = require('./verifyJwt_model');
const Pool = require('pg').Pool
const pool = new Pool({
  user: process.env.API_BASE_USER_ACCOUNT,
  host: process.env.API_BASE_HOST_URL,
  database: process.env.API_BASE_DATABASE_NAME,
  password: process.env.API_BASE_DATABASE_PASSWORD,
  port: process.env.API_BASE_PORT_NUMBER,
});

function getUserInfo(token) {
  return new Promise(async (resolve, reject) => {
    if(!token) resolve([{id:-1, name:''}])
    if (token) {
      const isAuth = await _verifyJwt(token);
      if (!isAuth.verified) resolve([{id:-1, name:''}]);
      if (isAuth.verified) {
        pool.query(`
          SELECT 
            users_id,
            users_first_name,
            users_last_name,
            users_email,
            users_fk_type
          FROM users
          WHERE users_id=$1
        `,
        [isAuth.result.id],
        (error, results) => {
          if (error) resolve([{id:-1, name:''}])
          resolve({
            id:results.rows[0].users_id,
            firstName:results.rows[0].users_first_name,
            lastName:results.rows[0].users_last_name,
            email:results.rows[0].users_email,
            type:results.rows[0].users_fk_type
          });
        });
      };
    };
  });
};

function getOrganizations(token) {
  return new Promise(async (resolve, reject) => {
    if(!token) resolve([{id:-1, name:'no token'}])
    if (token) {
      const isAuth = await _verifyJwt(token);
      if (!isAuth.verified) resolve([{id:-1, name:'not verified'}]);
      if (isAuth.verified) {
        pool.query(`
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
            WHERE fp.fp_fk_user=$1;
        `,
        [isAuth.result.id],
        (error, results) => {
          if (error) resolve([{id:-1, name:'error'}]);
          const organizations = results.rows.map(org => (
            {
              id:org.offices_id,
              name:org.offices_name,
              address:org.offices_address,
              city:org.offices_city,
              state:org.offices_state,
              zip:org.offices_zip
            }
          ));
          resolve(organizations);
        }
        );
      };
    };
  });
};

function getFacilitiesByUser(token, organizationsId) {
  return new Promise(async (resolve, reject) => {
    if(!token) reject({"errorCode":401, "error":"No JWT provided"});
    if (token) {
      const isAuth = await _verifyJwt(token);
      if(!isAuth.verified) {reject({"errorCode":401, "error":err});}
      if(isAuth.verified) {
        pool.query(`
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
          WHERE fp.fp_fk_user=$1
          AND f.facilities_fk_offices=$2;
        `,
        [isAuth.result.id, organizationsId],
        (error, results) => {
          if(error) reject({error:500, message:error});
          const facilities = results.rows.map(facility => {
            const image = images_model.getImage("facility", facility.facilities_image);
            return (
              {
                "id":facility.facilities_id,
                "name":facility.facilities_name,
                "address":facility.facilities_address,
                "city":facility.facilities_city,
                "state":facility.facilities_state,
                "zip":facility.facilities_zip,
                "lat":facility.facilities_lat,
                "long":facility.facilities_long,
                "image":image,
                "code":facility.facilities_code
              }
            );
          });
          resolve(facilities);
        });
      };
    };
  });
};

function getBlueprintsByUser(token, facilityId) {  
  return new Promise(async (resolve, reject) => {
    if(!token) reject({"errorCode":401, "error":"No JWT provided"});
    if (token) {
      const isAuth = await _verifyJwt(token);
      if(!isAuth.verified) reject({"errorCode":403, "error":"Forbidden"});
      if(isAuth.verified) {
        pool.query(
          `SELECT
            b.blueprint_id,
            b.blueprint_fk_facility_id,
            b.blueprint_name,
            b.blueprint_image
          FROM blueprints as b
          INNER JOIN facilitypermissions AS fp ON fp.fp_fk_facility=b.blueprint_fk_facility_id
          WHERE fp.fp_fk_user=$1
          AND b.blueprint_fk_facility_id=$2;
          `,
          [ isAuth.result.id, facilityId ],
          (err, results) => {
            if (err) reject({"errorCode":500, "error":"Internal server error"});
            const blueprints = results.rows.map(blueprint => ({
              "id":blueprint.blueprint_id,
              "name":blueprint.blueprint_name,
              "code":blueprint.blueprint_code,
              "image":images_model.getImage("blueprint", blueprint.blueprint_image)
            }));
           resolve(blueprints);
          }
        );
      };
    };
  });
};

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

function getComponents (token) {
  return new Promise(async (resolve, reject) => {
    if (!token) reject({"errorCode":401, "error":"No JWT provided"});
    if (token) {
      const isAuth = await _verifyJwt(token);
      if(!isAuth.verified) reject({"errorCode":403, "error":"Forbidden"});
      if(isAuth.verified) {
        pool.query(
          `SELECT 
            mc.component_id,
            cc.category_name,
            mc.component_type,
            mc.component_name,
            mc.component_icon,
            mc.component_color
          FROM map_components AS mc 
          JOIN component_categories AS cc ON mc.component_category=cc.category_id;`,
          (error, results) => {
            if (error) reject(error.message);
            const icons = new Set(results.rows.map(component => component.component_icon));
            const svgData = []
            icons.forEach(icon => {
              const data = images_model.getImage("svg", icon);
              svgData.push(data);
            });
            const components = results.rows.map(component => ({
              componentId: component.component_id,
              categoryName: component.category_name, 
              componentType: component.component_type,
              componentName: component.component_name,
              componentIcon: component.component_icon,
              componentColor: component.component_color,
            }));
            console.log({
              components:components,
              svgData:svgData
            })
            resolve({
              components:components,
              svgData:svgData
            });
          }
        );
      };
    };
  });
};

function getMapComponents (token, facilityId) {
  return new Promise(async (resolve, reject) => {
    if (!token) reject({"errorCode":401, "error":"No JWT provided"});
    if (token) {
      const isAuth = await _verifyJwt(token);
      if(!isAuth.verified) reject({"errorCode":403, "error":"Forbidden"});
      if(isAuth.verified) {
        pool.query(
          'SELECT * FROM get_map_components($1,$2)',
          [ isAuth.result.id, facilityId ],
          (error, results) => {
            if (error) reject({success:false, message:error.message});
            resolve(results.rows);
          }
        );
      };
    };
  });
};

function addMapComponent (token, component) {
  return new Promise(async (resolve, reject) => {
    if (!token) reject({"errorCode":401, "error":"No JWT provided"});
    if (token) {
      const isAuth = await _verifyJwt(token);
      if(!isAuth.verified) reject({"errorCode":403, "error":"Forbidden"});
      if(isAuth.verified) {
        pool.query(
          `INSERT INTO component_locations (
            location_component_id,
            location_facility_id,
            location_lat,
            location_long,
            location_floor
            ) 
          VALUES ($1,$2,$3,$4,$5);`,
          [ 
            component.componentId,
            component.facilityId,
            component.lat,
            component.long,
            component.floor 
          ],
          (error, results) => {
            if (error) reject({success:false, message:error.message});
            resolve({success:true});
          }
        );
      };
    };
  });
};

function deleteMapComponent (token, componentId) {
  return new Promise(async (resolve, reject) => {
    if (!token) reject({"errorCode":401, "error":"No JWT provided"});
    if (token) {
      const isAuth = await _verifyJwt(token);
      if(!isAuth.verified) reject({"errorCode":403, "error":"Forbidden"});
      if(isAuth.verified) {
        pool.query(
          'DELETE FROM component_locations WHERE location_id=$1',
          [ componentId ],
          (error, results) => {
            if (error) reject({success:false, message:error.message});
            resolve({success:true});
          }
        );
      };
    };
  });
};
module.exports = {
  getUserInfo,
  getOrganizations,
  getFacilitiesByUser,
  getBlueprintsByUser,
  getUserPermissions,
  getComponents,
  getMapComponents,
  addMapComponent,
  deleteMapComponent
};
