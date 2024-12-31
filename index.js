const { MongoClient, ServerApiVersion, MongoCursorInUseError } = require('mongodb');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const rateLimit = require('express-rate-limit');

// Configure rate limiting for login attempts
const loginLimiterAdmin = rateLimit({
  windowMs: 15 * 1000, // 15 second
  max: 5, // Max 5 attempts within the 15-minute window
  message: "Too many login attempts, please try again later in 15 seconds.",
});

// Configure rate limiting for login attempts
const loginLimiterSecurity = rateLimit({
  windowMs: 15 * 1000, // 15 second
  max: 5, // Max 5 attempts within the 15-minute window
  message: "Too many login attempts, please try again later in 15 seconds.",
});

// Configure rate limiting for login attempts
const loginLimiterHost = rateLimit({
  windowMs: 15 * 1000, // 15 second
  max: 5, // Max 5 attempts within the 15-minute window
  message: "Too many login attempts, please try again later in 15 seconds.",
});

const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Welcome To Group 1 Visitor Management System',
            version: '1.0.0'
        },
        components: {  // Add 'components' section
            securitySchemes: {  // Define 'securitySchemes'
                bearerAuth: {  // Define 'bearerAuth'
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            }
        }
    },
    apis: ['./index.js'],
};

const swaggerSpec = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
const saltRounds = 10;
const { v4: uuidv4 } = require('uuid');
const uri = "mongodb+srv://akmalfadzrin1111:12345@cluster0.jp8lpn0.mongodb.net/";

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  await client.connect();
  await client.db("admin").command({ ping: 1 });
  console.log("You successfully connected to MongoDB!");

  app.use(express.json());
  app.listen(port, () => {
    console.log(`Server listening at http://localSecurity:${port}`);
  });

  app.get('/', (req, res) => {
    res.send('Welcome to the Security Management System');
  });

  
  /**
 * @swagger
 * /registerAdmin:
 *   post:
 *     summary: Register a new admin
 *     description: Register a new admin user with required details and password user policy
 *     tags:
 *       - Admin
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               phoneNumber:
 *                 type: string
 *               role:
 *                 type: string
 *                 enum: [Admin]
 *             required:
 *               - username
 *               - password
 *               - name
 *               - email
 *               - phoneNumber
 *               - role
 *     responses:
 *       '200':
 *         description: Admin registration successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 */
  app.post('/registerAdmin', async (req, res) => {
    let data = req.body;
    res.send(await registerAdmin(client, data));
  }); 

  /**
 * @swagger
 * /loginAdmin:
 *   post:
 *     summary: Authenticate admin
 *     description: Login with admin credentials
 *     tags:
 *       - Admin
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '500':
 *         description: Admin login successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */
  app.post('/loginAdmin',loginLimiterAdmin, async (req, res) => {
    let data = req.body;
    res.send(await loginAdmin(client, data));
  });

  /**
 * @swagger
 * /loginSecurity:
 *   post:
 *     summary: Authenticate security personnel
 *     description: Login with security personnel credentials
 *     tags:
 *       - Security
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '500':
 *         description: Security personnel login successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */
  app.post('/loginSecurity',loginLimiterSecurity, async (req, res) => {
    let data = req.body;
    res.send(await loginSecurity(client, data));
  });

  /**
 * @swagger
 * /loginHost:
 *   post:
 *     summary: Authenticate Host
 *     description: Login for Host
 *     tags:
 *       - Host
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '500':
 *         description: Visitor login successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */
  app.post('/loginhost', loginLimiterHost, async (req, res) => {
    let data = req.body;
    res.send(await loginHost(client, data));
  });

  /**
 * @swagger
 * /registerSecurity:
 *   post:
 *     summary: Register a new security personnel
 *     description: Register a new security personnel with required details and password user policy
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               phoneNumber:
 *                 type: string
 *             required:
 *               - username
 *               - password
 *               - name
 *               - phoneNumber
 *     responses:
 *       '200':
 *         description: Security personnel registration successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 */
  app.post('/registerSecurity', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;
    res.send(await register(client, data, mydata));
  });

  
  /**
 * @swagger
 * /registerHost:
 *   post:
 *     summary: Register a new host
 *     description: Register a new host with required details and password user policy
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               phoneNumber:
 *                 type: string
 *             required:
 *               - username
 *               - password
 *               - name
 *               - phoneNumber
 *     responses:
 *       '200':
 *         description: Host registration successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 */
  app.post('/registerHost', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;
    res.send(await register(client, data, mydata));
  });

  
 /**
 * @swagger
 * /readVisitors:
 *   get:
 *     summary: Read visitor information for the host
 *     description: Retrieve information for visitors created by the host
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Visitor information retrieved successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 */
app.get('/readVisitors', verifyToken, async (req, res) => {
  try {
    const data = req.user;

    // Check if the user has the 'Host' role
    if (data.role !== 'Host') {
      return res.status(401).json({ error: 'Unauthorized access' });
    }

    // Query the database to retrieve visitors created by the host
    const visitors = await client.db('assigment').collection('Records').find({ hostUsername: data.username }).toArray();

    return res.status(200).json(visitors);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});



  /**
 * @swagger
 * /readHost:
 *   get:
 *     summary: Dump all host data information (Admin role)
 *     description: Retrieve information of all hosts by Admin role
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Host information retrieved successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '500':
 *         description: Internal Server Error
 */

  app.get('/readHost', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await readHosts(client, data));
  });


  /**
 * @swagger
 * /issuePass:
 *   post:
 *     summary: Issue visitor pass by Host
 *     description: Issue a visitor pass and add visitor information to Records
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               newName:
 *                 type: string
 *               newPhoneNumber:
 *                 type: string
 *             required:
 *               - newName
 *               - newPhoneNumber
 *     responses:
 *       '200':
 *         description: Visitor pass issued successfully. PassIdentifier generated for the pass.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Visitor pass issued successfully. PassIdentifier: abc123"
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 */
  app.post('/issuePass', verifyToken, async (req, res) => {
    try {
      const data = req.user;
  
      if (data.role !== 'Host') {
        return res.status(401).json({ error: 'Unauthorized - Host access only' });
      }
  
      const { newName, newPhoneNumber } = req.body;
  
      const passIssueResult = await issueVisitorPass(data, newName, newPhoneNumber, client);
  
      if (passIssueResult.success) {
        return res.status(200).json({ message: 'Visitor pass issued successfully', passIdentifier: passIssueResult.passIdentifier });
      } else {
        return res.status(500).json({ error: 'Failed to issue visitor pass' });
      }
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
  });
  
 
 /**
 * @swagger
 * /retrievePass:
 *   get:
 *     summary: Retrieve visitor pass by PassIdentifier
 *     description: Retrieve a visitor pass using the PassIdentifier
 *     tags:
 *       - Visitor
 *     parameters:
 *       - in: query
 *         name: passIdentifier
 *         required: true
 *         description: PassIdentifier for the visitor's pass
 *     responses:
 *       '200':
 *         description: Visitor pass retrieved successfully
 *       '404':
 *         description: PassIdentifier not found or invalid
 */

app.get('/retrievePass', async (req, res) => {
  try {
    const passIdentifier = req.query.passIdentifier;

    // Search for the pass using the provided PassIdentifier
    const pass = await client.db('assigment').collection('Records').findOne({ passIdentifier });

    if (!pass) {
      return res.status(404).send('PassIdentifier not found or invalid');
    }

    const passInfo = {
      issueby: pass.hostUsername,
      passID: pass.passIdentifier,
      issueDate: pass.issueDate,
    };
    

    // Return the pass information if found
    return res.status(200).json(passInfo);
  } catch (error) {
    console.error(error);
    return res.status(500).send('Internal Server Error');
  }
});



/**
 * @swagger
 * /getHostContact/{passIdentifier}:
 *   get:
 *     summary: Retrieve host contact from visitor pass (Security role)
 *     description: Get the contact number of the host from the visitor pass using passIdentifier
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: passIdentifier
 *         required: true
 *         description: Unique identifier of the visitor pass
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Host contact retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 name:
 *                   type: string
 *                   description: Host's name
 *                 phoneNumber:
 *                   type: string
 *                   description: Host's phone number
 *       '401':
 *         description: Unauthorized - Access denied
 *       '404':
 *         description: Visitor pass not found
 *       '500':
 *         description: Internal Server Error
 */


app.get('/getHostContact/:passIdentifier', verifyToken, async (req, res) => {
  try {
    const data = req.user;
    const passIdentifier = req.params.passIdentifier;

    // Check if the user has the 'Security' role
    if (data.role !== 'Security') {
      return res.status(401).json({ error: 'Unauthorized access' });
    }

    // Query the database using passIdentifier to retrieve host contact info from the visitor pass
    const visitorPass = await client.db('assigment').collection('Records').findOne({ passIdentifier });

    if (!visitorPass) {
      return res.status(404).json({ error: 'Visitor pass not found' });
    }

    // Return only the host's contact information to the public
    const hostContact = {
      HostName: visitorPass.hostUsername,
      HostphoneNumber: visitorPass.hostPhoneNumber,
      date: visitorPass.issueDate,
    };

    return res.status(200).json(hostContact);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


/**
 * @swagger
 * /Deletehosts/{username}:
 *   delete:
 *     summary: Delete host by Security
 *     description: Delete a host by a security user
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: username
 *         required: true
 *         description: Username of the host to delete
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Host deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Deletion success message
 *       '401':
 *         description: Unauthorized - Access denied
 *       '404':
 *         description: Host not found
 *       '500':
 *         description: Internal Server Error
 */

app.delete('/Deletehosts/:username', verifyToken, async (req, res) => {
  try {
    const data = req.user;
    const { username } = req.params;

    const deletionResult = await deleteHostBySecurity(client, data, username);

    if (deletionResult === 'Host deleted successfully') {
      return res.status(200).json({ message: deletionResult });
    } else {
      return res.status(401).json({ error: deletionResult });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


/**
 * @swagger
 * /Deletesecurity/{username}:
 *   delete:
 *     summary: Delete security by Admin
 *     description: Delete a security user by an admin
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: username
 *         required: true
 *         description: Username of the security user to delete
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Security user deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Deletion success message
 *       '401':
 *         description: Unauthorized - Access denied
 *       '404':
 *         description: Security user not found
 *       '500':
 *         description: Internal Server Error
 */
app.delete('/Deletesecurity/:username', verifyToken, async (req, res) => {
  try {
    const data = req.user;
    const { username } = req.params;

    const deletionResult = await deleteSecurityByAdmin(client, data, username);

    if (deletionResult === 'Security user deleted successfully') {
      return res.status(200).json({ message: deletionResult });
    } else {
      return res.status(401).json({ error: deletionResult });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /registerTestHost:
 *   post:
 *     summary: Register a new host (No token authorization)
 *     description: Register a new host without requiring token authorization and password user policy
 *     tags:
 *       - Security
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               phoneNumber:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Host registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Registration success message
 *       '400':
 *         description: Invalid request body
 */
app.post('/registerTestHost', async (req, res) => {
  try {
    const mydata = req.body;
    const registrationResult = await registerHost(client, mydata);

    res.status(200).json({ message: registrationResult });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /deleteVisitor/{passIdentifier}:
 *   delete:
 *     summary: Delete visitor by Host
 *     description: Delete a visitor by a host user
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: passIdentifier
 *         required: true
 *         description: PassIdentifier of the visitor's pass to delete
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Visitor deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Deletion success message
 *       '401':
 *         description: Unauthorized - Access denied
 *       '404':
 *         description: Visitor not found
 *       '500':
 *         description: Internal Server Error
 */
app.delete('/deleteVisitor/:passIdentifier', verifyToken, async (req, res) => {
  try {
    const data = req.user;
    const passIdentifier = req.params.passIdentifier;

    // Check if the user has the 'Host' role
    if (data.role !== 'Host') {
      return res.status(401).json({ error: 'Unauthorized access' });
    }

    // Call the asynchronous function for deleting a visitor
    const deletionResult = await deleteVisitorByHost(passIdentifier);

    if (deletionResult.success) {
      return res.status(200).json({ message: 'Visitor deleted successfully' });
    } else if (deletionResult.notFound) {
      return res.status(404).json({ error: 'Visitor not found' });
    } else {
      return res.status(500).json({ error: 'Failed to delete visitor' });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

}

run().catch(console.error);

//To generate token
function generateToken(userProfile){
  return jwt.sign(
  userProfile,    //this is an obj
  'dinpassword',           //password
  { expiresIn: '2h' });  //expires after 2 hour
}

//Function to register admin
async function registerAdmin(client, data) {
  data.password = await encryptPassword(data.password);

  const passwordCheck = isStrongPassword(data.password);

  // Check if the password meets the password policy
  if (passwordCheck !== true) {
    return passwordCheck; // Return the array of error messages
  }
  
  const existingUser = await client.db("assigment").collection("Admin").findOne({ username: data.username });
  if (existingUser) {
    return 'Username already registered';
  } else {
    const result = await client.db("assigment").collection("Admin").insertOne(data);
    return "Admin registered successfully";
  }
}

// Function to login as Admin
async function loginAdmin(client, data) {
  const adminCollection = client.db("assigment").collection("Admin");
  // Find the admin user
  const match = await adminCollection.findOne({ username: data.username });

  if (match) {
    // Compare the provided password with the stored password
    const isPasswordMatch = await decryptPassword(data.password, match.password);

    if (isPasswordMatch) {
      console.clear(); // Clear the console
      const token = generateToken(match);
      return "You are logged in as Admin\n1) Register Security\n2) Dump or Read All Hosts Data\n3) Delete Security Account\n\nToken for " + match.name + ": " + token + "\n";
    } else {
      return "Wrong password";
    }
  } else {
    return "Admin not found";
  }
}

// Function to login as Security
async function loginSecurity(client, data) {
  const securityCollection = client.db("assigment").collection("Security");
  // Find the security user
  const match = await securityCollection.findOne({ username: data.username });

  if (match) {
    // Compare the provided password with the stored password
    const isPasswordMatch = await decryptPassword(data.password, match.password);

    if (isPasswordMatch) {
      console.clear(); // Clear the console
      const token = generateToken(match);
      return "You are logged in as Security\n1) register Host\n2) Retrieve Hosts PhoneNumber from Visitor Pass\n3) Delete Host Account\n\nToken for " + match.name + ": " + token + "\n";
    } else {
      return "Wrong password";
    }
  } else {
    return "Security user not found";
  }
}

// Function to login as Host
async function loginHost(client, data) {
  const hostCollection = client.db("assigment").collection("Host");
  // Find the host user
  const match = await hostCollection.findOne({ username: data.username });

  if (match) {
    // Compare the provided password with the stored password
    const isPasswordMatch = await decryptPassword(data.password, match.password);

    if (isPasswordMatch) {
      console.clear(); // Clear the console
      const token = generateToken(match);
      return "You are logged in as a Host User\n1) Read All Visitor\n2) Issue the Pass for Visitor\n3) Delete create Visitor\n\nToken for " + match.name + ": " + token + "\n";
    } else {
      return "Wrong password";
    }
  } else {
    return "Host user not found";
  }
}

// Function to issue a visitor pass
async function issueVisitorPass(userData, newName, newPhoneNumber, dbClient) {
  const passIdentifier = generatePassIdentifier(); // Implement this function

  const result = await dbClient.db('assigment').collection('Records').insertOne({
    name: newName,
    phoneNumber: newPhoneNumber,
    hostUsername: userData.username,
    hostPhoneNumber: userData.phoneNumber,
    issueDate: new Date(),
    passIdentifier: passIdentifier,
  });

  if (result.insertedId) {
    return { success: true, passIdentifier };
  } else {
    return { success: false };
  }
}

//Function to encrypt password
async function encryptPassword(password) {
  const hash = await bcrypt.hash(password, saltRounds); 
  return hash 
}


//Function to decrypt password
async function decryptPassword(password, compare) {
  const match = await bcrypt.compare(password, compare)
  return match
}

//Function to register security and visitor
async function register(client, data, mydata) {
  const securityCollection = client.db("assigment").collection("Security");
  const hostCollection = client.db("assigment").collection("Host");

  const tempSecurity = await securityCollection.findOne({ username: mydata.username });
  const tempHost = await hostCollection.findOne({ username: mydata.username });

  if (tempSecurity || tempHost) {
    return "Username already in use, please enter another username";
  }

  const passwordCheck = isStrongPassword(mydata.password);

  // Check if the password meets the password policy
  if (passwordCheck !== true) {
    return passwordCheck; // Return the array of error messages
  }

  if (data.role === "Admin") {
    const result = await securityCollection.insertOne({
      username: mydata.username,
      password: await encryptPassword(mydata.password),
      name: mydata.name,
      phoneNumber: mydata.phoneNumber,
      role: "Security",
      host: [],
    });

    return "Security registered successfully";
  }

  if (data.role === "Security") {
    const result = await hostCollection.insertOne({
      username: mydata.username,
      password: await encryptPassword(mydata.password),
      name: mydata.name,
      Security: data.username,
      phoneNumber: mydata.phoneNumber,
      role: "Host",
    });

    const updateResult = await securityCollection.updateOne(
      { username: data.username },
      { $push: { host: mydata.username } }
    );

    return "Host registered successfully";
  }
}

// Function to read host data only by Admin role
async function readHosts(client, data) {
  if (data.role === 'Admin') {
    const hosts = await client.db('assigment').collection('Host').find({}).toArray();
    return hosts;
  } else {
    return 'Unauthorized access';
  }
}

// Function to delete host by Security
async function deleteHostBySecurity(client, data, usernameToDelete) {
  if (data.role !== 'Security') {
    return 'Unauthorized access';
  }

  const hostCollection = client.db('assigment').collection('Host');
  const securityCollection = client.db('assigment').collection('Security');

  // Find the host user to be deleted
  const hostToDelete = await hostCollection.findOne({ username: usernameToDelete });
  if (!hostToDelete) {
    return 'Host not found';
  }

  // Delete the host user document
  const deleteResult = await hostCollection.deleteOne({ username: usernameToDelete });
  if (deleteResult.deletedCount === 0) {
    return 'Failed to delete host';
  }

  // Update the Security collection to remove the reference to the deleted host
  await securityCollection.updateMany(
    { host: usernameToDelete },
    { $pull: { host: usernameToDelete } }
  );

  return 'Host deleted successfully';
}

// Function to delete security by Admin
async function deleteSecurityByAdmin(client, data, usernameToDelete) {
  if (data.role !== 'Admin') {
    return 'Unauthorized access';
  }

  const securityCollection = client.db('assigment').collection('Security');

  // Find the security user to be deleted
  const securityToDelete = await securityCollection.findOne({ username: usernameToDelete });
  if (!securityToDelete) {
    return 'Security user not found';
  }

  // Delete the security user document
  const deleteResult = await securityCollection.deleteOne({ username: usernameToDelete });
  if (deleteResult.deletedCount === 0) {
    return 'Failed to delete security user';
  }

  return 'Security user deleted successfully';
}

async function registerHost(client, mydata) {
  const hostCollection = client.db("assigment").collection("Host");

  const tempHost = await hostCollection.findOne({ username: mydata.username });

  if (tempHost) {
    return "Username already in use, please enter another username";
  }

  const passwordCheck = isStrongPassword(mydata.password);

  // Check if the password meets the password policy
  if (passwordCheck !== true) {
    return passwordCheck; // Return the array of error messages
  }

  const result = await hostCollection.insertOne({
    username: mydata.username,
    password: await encryptPassword(mydata.password),
    name: mydata.name,
    phoneNumber: mydata.phoneNumber,
    role: "Host",
  });

  return "Test Host registered successfully";
}

// Asynchronous function to delete a visitor by Host
async function deleteVisitorByHost(passIdentifier) {
  try {
    // Query the database using passIdentifier to find the visitor's pass
    const visitorPass = await client.db('assigment').collection('Records').findOne({ passIdentifier });

    if (!visitorPass) {
      return { notFound: true };
    }

    // Delete the visitor's pass from the database
    const deleteResult = await client.db('assigment').collection('Records').deleteOne({ passIdentifier });

    return { success: deleteResult.deletedCount > 0 };
  } catch (error) {
    console.error(error);
    return { success: false };
  }
}

// Updated password policy check
function isStrongPassword(password) {
  const errors = [];

  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long.');
  }

  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter.');
  }

  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter.');
  }

  if (!/\d/.test(password)) {
    errors.push('Password must contain at least one digit.');
  }

  if (!/\W/.test(password)) {
    errors.push('Password must contain at least one special character.');
  }

  return errors.length === 0 ? true : errors;
}

function generatePassIdentifier() {
  return uuidv4(); // Generates a UUID (e.g., '1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed')
}

//to verify JWT Token
function verifyToken(req, res, next) {
  let header = req.headers.authorization;

  if (!header) {
    return res.status(401).send('Unauthorized');
  }

  let token = header.split(' ')[1];

  jwt.verify(token, 'dinpassword', function(err, decoded) {
    if (err) {
      console.error(err);
      return res.status(401).send('Invalid token');
    }

    req.user = decoded;
    next();
  });
}


