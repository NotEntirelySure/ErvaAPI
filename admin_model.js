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

function getOrganizations() {
  return new Promise((resolve, reject) => {
    pool.query('SELECT * FROM offices;', (error, results) => {
      if (error) reject(error);
      const orgs = results.rows.map(org => (
        {
          id:org.offices_id,
          image:org.offices_image,
          name:org.offices_name,
          address:org.offices_address,
          city:org.offices_city,
          state:org.offices_state,
          zip:org.offices_zip
        }
      ));
      resolve(orgs);
    });
  }); 
};

function addOrganization(data) {
  return new Promise((resolve, reject) => {
    pool.query(`
      INSERT INTO offices(
        offices_name,
        offices_address,
        offices_city,
        offices_state,
        offices_zip
      )
      VALUES ($1,$2,$3,$4,$5);`, 
      [
        data.name,
        data.address,
        data.city,
        data.state,
        data.zip,
      ],
      (error, results) => {
        if (error) {
          resolve({
            success:false,
            errorCode:error.code,
            errorMessage:error.detail
          })
        };
        resolve({success:true});
      }
    );
  }); 
};

function editOrganization(data) {
  return new Promise((resolve, reject) => {
    pool.query(`
      UPDATE offices
      SET
        offices_name=$1,
        offices_address=$2,
        offices_city=$3,
        offices_state=$4,
        offices_zip=$5,
        offices_lat=$6,
        offices_long=$7,
        offices_image=$8
      WHERE offices_id=$9;`, 
      [
        data.name,
        data.address,
        data.city,
        data.state,
        data.zip,
        data.lat,
        data.long,
        data.image,
        data.id
      ],
      (error) => {
        if (error) {
          resolve({
            success:false,
            errorCode:error.code,
            errorMessage:error.detail

          })
        };
        resolve({success:true});
      }
    );
  }); 
};

function deleteOrganization(data) {
  return new Promise((resolve, reject) => {
    pool.query(
      'DELETE FROM offices WHERE offices_id=$1;', 
      [data.id],
      (error, results) => {
        if (error) {
          resolve({
            success:false,
            errorCode:error.code,
            errorMessage:error.detail
          })
        };
        resolve({success:true});
      }
    );
  }); 
};

function getFacilities() {
  return new Promise((resolve, reject) => {
    pool.query(
      `SELECT * FROM facilities;`,
      (error, result) => {
        if (error) reject(error);
        const facilitiesArray = result.rows.map(row => {
          return (
            {
              "id":row.facilities_id,
              "name":row.facilities_name,
              "address":row.facilities_address,
              "city":row.facilities_city,
              "state":row.facilities_state,
              "zip":row.facilities_zip,
              "organization":row.facilities_fk_offices,
              "lat":row.facilities_lat,
              "long":row.facilities_long,
              "image":row.facilities_image,
              "code":row.facilities_code
            }
          );
        });
        
        resolve(facilitiesArray);
      }
    );
  });
};

function addFacility(data) {
  return new Promise((resolve, reject) => {
    pool.query(`
      INSERT INTO facilities (
        facilities_name,
        facilities_fk_offices,
        facilities_address,
        facilities_city,
        facilities_state,
        facilities_zip,
        facilities_lat,
        facilities_long,
        facilities_image,
        facilities_code
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10);`, 
      [
        data.name,
        data.organization,
        data.address,
        data.city,
        data.state,
        data.zip,
        data.lat,
        data.long,
        data.image,
        data.code
      ],
      (error) => {
        if (error) {
          resolve({
            success:false,
            errorCode:error.code,
            errorMessage:error.detail
        })}
        resolve({success:true});
      }
    );
  }); 
};

function editFacility(data) {
  return new Promise((resolve, reject) => {
    pool.query(`
      UPDATE facilities
      SET
        facilities_name=$1,
        facilities_fk_offices=$2,
        facilities_address=$3,
        facilities_city=$4,
        facilities_state=$5,
        facilities_zip=$6,
        facilities_lat=$7,
        facilities_long=$8,
        facilities_image=$9,
        facilities_code=$10
      WHERE facilities_id=$11;`, 
      [
        data.name,
        data.organization,
        data.address,
        data.city,
        data.state,
        data.zip,
        data.lat,
        data.long,
        data.image,
        data.code,
        data.id
      ],
      (error, result) => {
        if (error) resolve({
          success:false,
          errorCode:error.code,
          errorMessage:error.detail
        })
        resolve({success:true});
      }
    );
  }); 
};

function deleteFacility(data) {
  return new Promise((resolve, reject) => {
    pool.query(
      'DELETE FROM facilities WHERE facilities_id=$1;', 
      [data.id],
      (error) => {
        if (error) resolve({
          success:false,
          errorCode:error.code,
          errorMessage:error.detail
        })
        resolve({success:true});
      }
    );
  }); 
};

function getBlueprints() {
  return new Promise((resolve, reject) => {
    pool.query(
      'SELECT * FROM blueprints;',
      (error, results) => {
        if (error) reject([{
          success:false,
          errorCode:error?.code,
          errorMessage:error.detail
        }]
        );
        if (results.rowCount < 1) resolve([{
          success:true,
          id:0,
          facilityId:0,
          name:"No blueprint records",
          image:"-"
        }]);
        if (results.rowCount > 0) {
          const blueprints = results.rows.map(blueprint => (
            {
              id:blueprint.blueprint_id,
              facilityId:blueprint.blueprint_fk_facility_id,
              name:blueprint.blueprint_name,
              image:blueprint.blueprint_image
            }
          ));
          resolve(blueprints);
        };
        reject({
          success:false,
          errorCode:500,
          errorMessage:"An unknown error occurred."
        });
      }
    );
  });
};

async function addBlueprint(blueprintData) {
  return new Promise((resolve, reject) => {
    pool.query(
      `INSERT INTO blueprints (
        blueprint_fk_facility_id,
        blueprint_name,
        blueprint_image
      )
      VALUES ($1, $2, $3);`,
      [
        blueprintData.facility,
        blueprintData.name,
        blueprintData.image
      ],
      (error, results) => {
        if (error) resolve({
          success:false,
          errorCode:error.code,
          errorMessage:error.message
        });
        resolve({success:true});
      }
    );
  });
};
async function editBlueprint(blueprintData) {
  return new Promise((resolve, reject) => {
    pool.query(
      `UPDATE blueprints
      SET 
        blueprint_fk_facility_id=$1,
        blueprint_name=$2,
        blueprint_image=$3
      WHERE blueprint_id=$4;`,
      [
        blueprintData.facility,
        blueprintData.name,
        blueprintData.image,
        parseInt(blueprintData.id)
      ],
      error => {
        if (error) resolve({
          success:false,
          errorCode:error.code,
          errorMessage:error.message
        });
        resolve({success:true});
      }
    );
  });
};

async function deleteBlueprint(blueprintData) {
  return new Promise((resolve, reject) => {
    pool.query(
      'DELETE FROM blueprints WHERE blueprint_id=$1',
      [blueprintData.id],
      error => {
        if (error) resolve({
          success:false,
          errorCode:error.code,
          errorMessage:error.message
        });
        resolve({success:true});
      }
    );
  });
};

module.exports = {
  getOrganizations,
  addOrganization,
  editOrganization,
  deleteOrganization,
  getFacilities,
  addFacility,
  editFacility,
  deleteFacility,
  getBlueprints,
  addBlueprint,
  editBlueprint,
  deleteBlueprint
};