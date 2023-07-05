const Client = require('node-radius-client');
const {
  dictionaries: {
    rfc2865: {
      file,
      attributes,
    },
  },
} = require('node-radius-utils');
 
const client = new Client({
  host: '127.0.0.1',
  dictionaries: [
    file,
  ],
});
 
client.accessRequest({
  secret: 'testing123',
  attributes: [
    [attributes.USER_NAME, 'alice'],
    [attributes.USER_PASSWORD, 'hello1234'],
  ],
}).then((result) => {
  console.log('result', result);
}).catch((error) => {
  console.log('error', error);
});

