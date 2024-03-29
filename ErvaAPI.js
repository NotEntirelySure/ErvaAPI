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
  verifyAccess: () => {
    /*
      The reason why this just returns true, is because the thinking is that if a request can reach this function,
      it has passed the check in the requestAuth() function. That function checks to see if the token is valid
      and that its type is correct. Since a request can reach here, it has been verified as being an valid token.
    */
    return {isAuth:true};
  },
  getUserInfo: async ({ jwt }) => {
    const info = await database_model.getUserInfo(jwt);
    return info;
  },
  getOrganizations: async ({ jwt }) => {
    const organizations = await database_model.getOrganizations(jwt);
    return organizations;
  },
  getFacilities: async ({ jwt, organizationId }) => {
    const facilities = await database_model.getFacilitiesByUser(jwt, organizationId);
    return facilities;
  },
  getBlueprints: async ({ jwt, facilityId }) => {
    const blueprints = await database_model.getBlueprintsByUser(jwt, facilityId);
    return blueprints;
  }
};

async function requestAuth(req, res, next) {
  if (req) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).send('Unauthorized');
    const token = authHeader.split(' ')[1];
    const tokenValidation = await verifyJwt_model._verifyJwt(token);
    if (tokenValidation.verified) next();
    else {return res.status(403).send('Forbidden');};
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

app.post('/api/login', (req, res) => {
  account_model.login(req.body)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error));
});

app.get('/api/getqr', (req, res) => {
  account_model.generateQr()
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error));
});

app.post('/api/register', (req, res) => {
  account_model.register(req.body)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error));
});

app.post('/api/verifyaccount', (req, res) => {
  account_model.verifyAccount(req.body.token)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error));
});

app.post('/api/forgotpassword', (req, res) => {
  account_model.forgotPassword(req.body.email)
    .then(response => res.status(200).send(response))
    .catch(error => res.status(500).send(error));
});

app.post('/api/resetpassword', (req, res) => {
  account_model.resetPassword(req.body)
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

app.get('/sendemail', (req, res) => {
  email_model.sendEmail()
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