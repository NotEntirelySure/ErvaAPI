
//not tested working, but probably works.
const addPermission = (userId, facilityId) => {
  return new Promise(function(resolve, reject) { 
    pool.query(`
      INSERT INTO facilitypermissions (
        fp_fk_user,
        fp_fk_facility,
        fp_fk_office
      )
      VALUES (
        ${userId},
        ${facilityId},
        (
          SELECT facilities_fk_offices
          FROM facilities
          WHERE facilities_id=${facilityId}
        )
      );`, (error, results) => {
      if (error) {
        reject(error)
      }
      resolve(results);
    })
  })
}