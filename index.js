const express = require('express')
const session = require('express-session')
const morgan = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16).toString('hex')
const cookies = require('cookie-parser')
// const JwtStrategy = require('passport-jwt').Strategy
// const fortune = require('fortune-teller')
// const scryptMcf = require('scrypt-mcf')
const JwtStrategy = require('passport-jwt').Strategy
const fortune = require('fortune-teller')
// const scryptMcf = require('scrypt-mcf')
const axios = require('axios')
const dotenv = require('dotenv')
const scryptMcf = require('scrypt-mcf')
const Issuer = require('openid-client').Issuer
const OpenIDConnectStrategy = require('openid-client').Strategy
const openid = require('openid-client')
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

dotenv.config()

async function main() {

  const users = [
  ]

  const thirdParty = [
  ]

  const findByUsername = function(username) {
    for (let i = 0; i < users.length; i++){
      const user = users[i]
      if (user.username == username){
        return user
      }
    }
    return null
  }

  const findThirdParty = function(email) {
    for (let i =0; i < thirdParty.length; i++){
      const userEmail = thirdParty[i]
      if (userEmail == email){
        return userEmail
      }
    }
    return null
  }

  // use database on file to facilitate!

  const app = express()
  const port = 3000

  async function verify(toVerify, user){  
    return await scryptMcf.verify(toVerify, user.password)
  }

  passport.use('username-password', new LocalStrategy(
    {
      usernameField: 'username',
      passwordField: 'password',
      session: false
    },
    function (username, password, done) {
      const user = findByUsername(username);
      
      if (user == null) return done(null, false)

      verify(password, user).then(
        result => {
          if (user && user.password && result) {
            return done(null, user) // first argument is the error, user is added to the request!
          }
          return done(null, false)
        }
      )
    }
  ))

  passport.use('jwt', new JwtStrategy(
    {
      secretOrKey: jwtSecret,
      jwtFromRequest: (req) => {
        if (req && req.cookies){
          return req.cookies.jwt
        }
        return null
      } 
    }, (jwt_payload, done) => {
      const user = findByUsername(jwt_payload.sub)

      if (user){
        return done(null, user)
      }

      const thirdParty = findThirdParty(jwt_payload.sub)
      console.log("Verifying third party cookie login.")
      console.log(thirdParty)
      if (thirdParty){
        return done(null, thirdParty)
      }

      return done(null, false)
    }
    
  ))

  // RADIUS
  passport.use('local-radius', new LocalStrategy(
    {
      usernameField: 'username',
      passwordField: 'password',
      session: false
    },
    function (username, password, done) {
      
      client.accessRequest({
        secret: 'testing123',
        attributes: [
          [attributes.USER_NAME, username],
          [attributes.USER_PASSWORD, password],
        ],
      }).then((result) => {
        console.log('result', result);
        if (result['code'] == 'Access-Accept'){
          const user = {username: username, password: password}
          thirdParty.push(username)
          return done(null, user)
        }
        else {
          return done(null, false)
        }
      }).catch((error) => {
        console.log('error', error);
        return done(null, false)
      });
    }
  ))

  // OPENID
  // 1. Download the issuer configuration from the well-known openid configuration (OIDC discovery)
  const oidcIssuer = await Issuer.discover(process.env.OIDC_PROVIDER)

  // 2. Setup an OIDC client/relying party.
  const oidcClient = new oidcIssuer.Client({
    client_id: process.env.OIDC_CLIENT_ID,
    client_secret: process.env.OIDC_CLIENT_SECRET,
    redirect_uris: [process.env.OIDC_CALLBACK_URL],
    response_types: ['code'] // code is use for Authorization Code Grant; token for Implicit Grant
  })

  // 3. Configure the strategy.
  passport.use('oidc', new OpenIDConnectStrategy({
    client: oidcClient,
    usePKCE: false // We are using standard Authorization Code Grant. We do not need PKCE.
  }, (tokenSet, userInfo, done) => {
    if (tokenSet === undefined || userInfo === undefined) {
      return done('no tokenSet or userInfo')
    }
    return done(null, userInfo)
  }))

  app.use(express.urlencoded({extended: true})) // needed to retrieve html form fields
  
  // We will store in the session the complete passport user object
  passport.serializeUser(function (user, done) {
    return done(null, user)
  })

  // The returned passport user is just the user object that is stored in the session
  passport.deserializeUser(function (user, done) {
    return done(null, user)
  })


  app.use(passport.initialize())
  
  app.use(morgan('dev'))
  app.use(session({
    secret: require('crypto').randomBytes(32).toString('base64url'), // This is the secret used to sign the session cookie. We are creating a random base64url string with 256 bits of entropy.
    resave: false, // Default value is true (although it is going to be false in the next major release). We do not need the session to be saved back to the session store when the session has not been modified during the request.
    saveUninitialized: false // Default value is true (although it is going to be false in the next major release). We do not need sessions that are "uninitialized" to be saved to the store
  }))
  app.use(cookies(jwtSecret))

  app.get('/', passport.authenticate('jwt', {failureRedirect: '/unauthorized', session: false}),(req, res) => {

    res.send(fortune.fortune())
  })

  app.get('/unauthorized', (req, res) => {
    res.sendFile('unauthorized.html', {root: __dirname})
  })

  app.get('/login', (req, res) => {
    res.sendFile('login.html', {root: __dirname})
  })

  app.get('/login_radius', (req, res) => {
    res.sendFile('login_radius.html', {root: __dirname})
  })

  app.get('/signup', (req, res) => {
    res.sendFile('signup.html', {root: __dirname})
  })

  app.get('/username_exists', (req, res) => {
    res.sendFile('username_exists.html', {root: __dirname})
  })

  app.get('/oidc/login',
    passport.authenticate('oidc', { scope: 'openid email profile' })
  )

  app.get('/oidc/cb', passport.authenticate('oidc', { failureRedirect: '/login', failureMessage: true }), (req, res) => {
    /**
   * Create our JWT using the req.user.email as subject, and set the cookie.
   */
    // just copy and paste or invoke the function you used for creating the JWT for a user logging in with username and password. The only difference is that now the sub claim will be set to req.user.email
    console.log(".........")
    console.log("NSAA Exam")
    console.log(".........")
    console.log("email: ", req.user.email)
    console.log("given name: ", req.user.given_name)
    console.log("family_name: ", req.user.family_name)
    console.log(".........")
    const email = req.user.email
    const jwtClaims = {
      sub: email,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week
      role: 'user'
    }

    if (findThirdParty(email) == null){
      thirdParty.push(email)
    }

    // the actual token
    const token = jwt.sign(jwtClaims, jwtSecret)

    res.cookie('jwt', token.toString(), {httpOnly: true, secure: true})
    res.redirect('/')

    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for later verifying the signature): ${jwtSecret.toString('base64')}`)
  })


  app.post('/signup', (req, res) => {
    username = req.body.username
    password = req.body.password
    
    if (findByUsername(username)){
      res.redirect('/username_exists')
    }
    // >= 3s (logN >= 20)
    scryptMcf.hash(password, {
      scryptParams: {
        logN: 18,
        r: 8,
        p: 1
      }
    }).then(value => {
      users.push({username: username, password: value})
      res.redirect('/login')
    })
  })

  // RADIUS
  app.post('/login_radius', passport.authenticate('local-radius', {failureRedirect: '/login_radius', session: false}),
  (req, res) => {
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week
      role: 'user'
    }

    // the actual token
    const token = jwt.sign(jwtClaims, jwtSecret)

    res.cookie('jwt', token.toString(), {httpOnly: true, secure: true})
    res.redirect('/')

    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for later verifying the signature): ${jwtSecret.toString('base64')}`)
  }) 

  app.post('/login', passport.authenticate('username-password', {failureRedirect: '/login', session: false}),
  (req, res) => {
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week
      role: 'user'
    }

    // the actual token
    const token = jwt.sign(jwtClaims, jwtSecret)

    res.cookie('jwt', token.toString(), {httpOnly: true, secure: true})
    res.redirect('/')

    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for later verifying the signature): ${jwtSecret.toString('base64')}`)
  })

  app.get('/logout', (req, res) => {
    res.clearCookie('jwt')
    res.redirect('/login')
  })

  // OAUTH
  app.get('/oauth2cb', async (req, res) => { // watchout the async definition here. It is necessary to be able to use async/await in the route handler
    /**
     * 1. Retrieve the authorization code from the query parameters
     */
    const code = req.query.code // Here we have the received code
    if (code === undefined) {
      const err = new Error('no code provided')
      err.status = 400 // Bad Request
      throw err
    }

    /**
     * 2. Exchange the authorization code for an actual access token at OUATH2_TOKEN_URL
     */
    const tokenResponse = await axios.post(process.env.OAUTH2_TOKEN_URL, {
      client_id: process.env.OAUTH2_CLIENT_ID,
      client_secret: process.env.OAUTH2_CLIENT_SECRET,
      code
    })

    console.log(tokenResponse.data) // response.data contains the params of the response, including access_token, scopes granted by the use and type.

    // Let us parse them ang get the access token and the scope
    const params = new URLSearchParams(tokenResponse.data)
    const accessToken = params.get('access_token')
    const scope = params.get('scope')

    // if the scope does not include what we wanted, authorization fails
    if (scope !== 'user:email') {
      const err = new Error('user did not consent to release email')
      err.status = 401 // Unauthorized
      throw err
    }

    /**
     * 3. Use the access token to retrieve the user email from the USER_API endpoint
     */
    const userDataResponse = await axios.get(process.env.USER_API, {
      headers: {
        Authorization: `Bearer ${accessToken}` // we send the access token as a bearer token in the authorization header
      }
    })
    console.log(userDataResponse.data)
    
    /**
     * 4. Create our JWT using the github email as subject, and set the cookie.
     */
    // just copy and paste or invoke the function you used for creating the JWT for a user logging in with username and password.
    const email = userDataResponse.data[0].email 
    const jwtClaims = {
      sub: email,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week
      role: 'user'
    }

    if (findThirdParty(email) == null){
      thirdParty.push(email)
    }

    // the actual token
    const token = jwt.sign(jwtClaims, jwtSecret)

    res.cookie('jwt', token.toString(), {httpOnly: true, secure: true})
    res.redirect('/')

    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for later verifying the signature): ${jwtSecret.toString('base64')}`)
  })


  app.listen(port, () =>{
    console.log(`App listening at http://127.0.0.1:${port}`)
  })
}

main().catch(e => {console.log(e)})