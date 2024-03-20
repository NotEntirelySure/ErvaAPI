//allows access to .env file for environment variable declaration
require('dotenv').config();

const https = require('https');
const fs = require('fs');
const express = require('express');
const { graphqlHTTP } = require("express-graphql");
const { buildSchema } = require("graphql");
const cors = require('cors');
const app = express().use('*', cors());

const account_model = require('./account_model');
const admin_model = require('./admin_model');
const admin_users_model = require('./admin_users_model');
const verifyJwt_model = require('./verifyJwt_model');
const database_model = require('./database_model');
const email_model = require('./email_model');
const images_model = require('./images_model')

const types = fs.readFileSync('./graphql/types.graphql', 'utf-8');
const queries = fs.readFileSync('./graphql/queries.graphql', 'utf-8');
const mutations = fs.readFileSync('./graphql/mutations.graphql', 'utf-8');

const schema = buildSchema(`
  ${types}
  ${queries}
  ${mutations}
`);

const resolvers = {
  verifyAdmin: () => {
    /*
      The reason why this just returns true, is because the thinking is that if a request can reach this function,
      it has passed the check in the requestAuth() function. That function checks to see if the token is valid
      and that its type is 3 (admin). Since a request can reach here, it has been verified as being an admin token.
    */
    return({isAuth:true});
  },
  getQr: async () => {
    const qr = await account_model.generateQr();
    return qr;
  },
  getUsers: async () => {
    const users = await admin_users_model.getUsers();
    return users;
  },
  getRoles: async () => {
    const roles = await admin_users_model.getRoles();
    return roles;
  },
  getImage: async ({type, name}) => {
    const image = await images_model.getImage(type, name);
    return image;
  },
  getImageList: async ({ type }) => {
    const imageList = await images_model.getImageList(type);
    return imageList;
  },
  getAccountTypes: async () => {
    const accountTypes = await admin_users_model.getAccountTypes();
    return accountTypes;
  },
  getOrganizations: async () => {
    const orgs = await admin_model.getOrganizations();
    return orgs;
  },
  getFacilities: async () => {
    const facilities = await admin_model.getFacilities();
    return facilities;
  },
  getBlueprints: async () => {
    const blueprints = await admin_model.getBlueprints();
    return blueprints;
  },
  getUserPermissions: async ({ userId }) => {
    const permissions = await database_model.getUserPermissions(userId);
    return permissions;
  },
  sendVerificationEmail: async ({ address }) => {
    const sendEmail = await email_model.sendVerifyEmail(address);
    return sendEmail;
  },
  //Mutations
  deleteUser: async ({ userId }) => {
    const deleteUser = await admin_users_model.deleteUser(userId);
    return deleteUser;
  },
  addUserPermissions: async ({ addValues }) => {
    if (addValues.length > 0) {
      const addPermissions = await admin_users_model.addPermissions(addValues);
      return addPermissions;
    };
    return [{
      success: true,
      userId:-1
    }];
  },
  deleteUserPermissions: async ({ deleteValues }) => {
    if (deleteValues.length > 0) {
      const deletePermissions = await admin_users_model.deletePermissions(deleteValues);
      return deletePermissions;
    };
    return [{
      success: true,
      permissionId: -1
    }];
  },
  updateUser: async ({ userData }) => {
    const updateUser = await admin_users_model.updateUser(userData);
    return updateUser;
  },
  modOrganization: async ({ orgData }) => {
    switch (orgData.action) {
      case "add":
        const addOrg = await admin_model.addOrganization(orgData);
        return addOrg;
      case "edit":
        const editOrg = await admin_model.editOrganization(orgData);
        return editOrg;
      case "delete":
        const deleteOrg = await admin_model.deleteOrganization(orgData);
        return deleteOrg;
    };
  },
  modFacility: async ({ facilityData }) => {
    switch (facilityData.action) {
      case "add":
        const addFacility = await admin_model.addFacility(facilityData);
        return addFacility;
      case "edit":
        const editFacility = await admin_model.editFacility(facilityData);
        return editFacility;
      case "delete":
        const deleteFacility = await admin_model.deleteFacility(facilityData);
        return deleteFacility;
    };
  },
  modImage: async ({ imageData }) => {
    switch (imageData.action) {
      case "upload":
        const uploadImage = await images_model.uploadImage(imageData);
        return uploadImage;
      case "delete":
        const deleteImage = await images_model.deleteImage(imageData.type, imageData.name);
        return deleteImage;
    };
  },
  modBlueprint: async ({ blueprintData }) => {
    switch (blueprintData.action) {
      case "add":
        const addBlueprint = await admin_model.addBlueprint(blueprintData);
        return addBlueprint;
      case "edit":
        const editBlueprint = await admin_model.editBlueprint(blueprintData);
        return editBlueprint;
      case "delete":
        const deleteBlueprint = await admin_model.deleteBlueprint(blueprintData);
        return deleteBlueprint;
    };
  }
};

async function requestAuth(req, res, next) {
  if (req) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).send('Unauthorized');
    const token = authHeader.split(' ')[1];
    const tokenValidation = await verifyJwt_model._verifyJwt(token);
    if (tokenValidation.verified && tokenValidation.result.type === 3) next();
    else {return res.status(401).send('Unauthorized');};
  };
};

app.use(express.json({limit:'2mb'}))
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', process.env.API_ACCESS_ORIGIN);
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Access-Control-Allow-Headers');
  next();
});

app.post('/api/adminlogin', (req, res) => {
  account_model.adminLogin(req.body)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error));
});

app.use(
  "/api",
  requestAuth,
  graphqlHTTP({
    schema: schema,
    rootValue: resolvers,
    graphiql: true,
  })
);



app.get('/getqr', (req, res) => {
  account_model.generateQr()
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error));
});

app.get('/getusers', (req, res) => {
  admin_model.getUsers()
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error));
});

app.get('/sendemail', (req, res) => {
  email_model.sendEmail()
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error));
});

app.post('/register', (req, res) => {
  account_model.register(req.body)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error));
});

app.post('/login', (req, res) => {
  account_model.login(req.body)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error));
});

app.post('/forgotpassword', (req, res) => {
  account_model.forgotPassword(req.body.email)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error));
});

app.post('/resetpassword', (req, res) => {
  account_model.resetPassword(req.body.resetToken,req.body.newPassword)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error));
});

app.post('/verifyjwt', (req, res) => {
  verifyJwt_model.verifyJwt(req.body.token)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error));
});

app.post('/verifyaccount', (req, res) => {
  account_model.verifyAccount(req.body.token)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error));
});

app.post('/getapikey', (req, res) => {
  account_model.getApiKey(req.body.token)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

app.post('/getoffices', (req, res) => {
  database_model.getOffices(req.body.token)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

app.post('/getfacilities', (req, res) => {
  database_model.getFacilitiesByUser(req.body.token, req.body.office)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

app.post('/getblueprints', (req, res) => {
  database_model.getBlueprints(req.body.token, req.body.facility)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

//admin functions
app.get('/users/getall', (req, res) => {
  admin_users_model.getUsers()
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

app.delete('/users/delete', (req, res) => {
  admin_users_model.deleteUser(req.body)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

app.get('/offices/getall', (req, res) => {
  admin_model.getOffices()
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

app.post('/offices/add', (req, res) => {
  admin_model.addOffice(req.body)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

app.post('/offices/edit', (req, res) => {
  admin_model.editOffice(req.body)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

app.delete('/offices/delete', (req, res) => {
  admin_model.deleteOffice(req.body)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

app.get('/facilities/getall', (req, res) => {
  admin_model.getFacilities()
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

app.post('/facilities/add', (req, res) => {
  admin_model.addFacility(req.body)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

app.post('/facilities/edit', (req, res) => {
  admin_model.editFacility(req.body)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

app.delete('/facilities/delete', (req, res) => {
  admin_model.deleteFacility(req.body)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

app.get('/facilities/getimagelist', (req, res) => {
  images_model.getImageList('facilities')
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

app.get('/facilities/getimage/:imageName', (req, res) => {
  images_model.getImage({category:'facilities', imageName:req.params.imageName})
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

app.post('/facilities/uploadimage', (req, res) => {
  images_model.uploadImage(req.body)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

app.delete('/facilities/deleteimage', (req, res) => {
  images_model.deleteImage('facilities',req.body)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error))
});

app.listen(process.env.API_BASE_LISTENING_PORT, () => {
  console.log(`App running on port ${process.env.API_BASE_LISTENING_PORT}.`)
})

// https.createServer(
//   {
//     pfx:fs.readFileSync('C:/ErvaAPI/APICert.pfx'),
//     passphrase:'14ug5YO@vb_=7iXr'
//   },
//   app
// ).listen(process.env.API_BASE_LISTENING_PORT, () => {console.log(`Secure API running on port ${process.env.API_BASE_LISTENING_PORT}.`)})