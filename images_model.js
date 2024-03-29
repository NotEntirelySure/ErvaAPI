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
    const dirExists = fs.existsSync(`../ErvaAPI/${directory}/${name}`);
    if (dirExists) {
      try {
        const imageData = fs.readFileSync(`../ErvaAPI/${directory}/${name}`, 'base64');
        resolve ({
          name: name,
          data: imageData,
          success: true
        });
      }
      catch (error){
        resolve ({
          name: name,
          message:'an error occured while retrieving image',
          success: false
        });
      };
    };
    if (!dirExists) {
      try {
        const imageData = fs.readFileSync(`../ErvaAPI/${directory}/default.jpg`, 'base64');
        resolve ({
          name: "default.jpg",
          data: imageData,
          success: false,
          message:'image not found'
        });
      }
      catch (error){
        resolve ({
          name: name,
          message:'an error occured while retrieving image',
          success: false
        });
      };
    };
  });
};


module.exports = { getImage };