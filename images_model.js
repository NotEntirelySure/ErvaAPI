const fs = require("fs");

function getImage(type, name) {
  return new Promise((resolve, reject) => {
    let directory;
    switch (type) {
      case 'blueprint':
        directory = 'blueprints';
        break;
      case 'facility':
        directory = 'facilities';
        break;
    };
    if (!directory) resolve ({
      success:false,
      message:'invalid image type or no type specified.'
    });
    const dirExists = fs.existsSync(`../${directory}/${name}`);
    if (dirExists) {
      const imageData = fs.readFileSync(`../${directory}/${name}`, 'base64');
      resolve ({
        name: name,
        data: imageData,
        success: true
      });
    };
    if (!dirExists) {
      const imageData = fs.readFileSync(`../${directory}/default.jpg`, 'base64');
      resolve ({
        name: "default.jpg",
        data: imageData,
        success: false,
        message:'image not found'
      });
    };
  });
};

function getImageList(type) {
  return new Promise((resolve, reject) => {
    let directory;
    switch (type) {
      case 'blueprint':
        directory = 'blueprints';
        break;
      case 'facility':
        directory = 'facilities';
        break;
    };
    const files = fs.readdirSync(`../${directory}`);
    const fileStats = files.map(fileName => {
      const stats = fs.statSync(`../${directory}/${fileName}`);
      return ({
        name:fileName,
        createdAt:stats.birthtime,
        size:stats.size
      });
    });
    resolve(fileStats);
  });
};

function uploadImage(imageData) {
  return new Promise ((resolve, reject) => {
    try {
      let searchValue, directory;
      switch (imageData.type) {
        case 'blueprint':
          directory = 'blueprints';
          break;
        case 'facility':
          directory = 'facilities';
          break;
      };
      
      const dirExists = fs.existsSync(`../${directory}/${imageData.name}`);
      if (dirExists) {
        resolve({
          success:false,
          errorCode:409,
          errorMessage:`A file with the name ${imageData.name} already exists.`
        });
      };

      switch (imageData.name.split('.')[1]) {
        case 'png':
          searchValue = 'data:image/png;base64,';
          break;
        case 'jpg':
        case 'jpeg':
          searchValue = 'data:image/jpeg;base64,';
          break;
      };
      

      const imageBuffer = Buffer.from(imageData.data.replace(searchValue,''), 'base64');
      fs.writeFileSync(`../${directory}/${imageData.name}`, imageBuffer, {encoding: 'binary'});
      resolve({success:true});
    }
    catch (error) {
      resolve({
        success:false,
        errorCode:error.code,
        errorMessage:error.message
      });
    };
  });
};

function deleteImage(type, name) {
  return new Promise ((resolve, reject) => {
    let directory;
    switch (type) {
      case 'blueprint':
        directory = 'blueprints';
        break;
      case 'facility':
        directory = 'facilities';
        break;
    };
    fs.unlink(`../${directory}/${name}`, error => {
      if (error) { 
        resolve({
          success:false,
          errorCode: error.errno,
          errorMessage:error.errno === -4058 ? `Error: the file ${name} does not exist or cannot be found.`:error.message
        })
      };
      resolve({success:true});
    });
  });
};

module.exports = {
  getImage,
  getImageList,
  uploadImage,
  deleteImage
};