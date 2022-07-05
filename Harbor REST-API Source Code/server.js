
const express = require('express');
const app = express();
const path = require('path');
const logger = require('morgan');
const CLIENT_ID = '';
const CLIENT_SECRET = '';
const DOMAIN = 'facchiad493.us.auth0.com';
const {Datastore} = require('@google-cloud/datastore');
const bodyParser = require('body-parser');
const { auth } = require('express-openid-connect');

// cool thingymobobber, logs and colors server responses, very rad
app.use(logger('dev'));

// Set up auth0 and set it for the application
const config = {
    authRequired: false,
    auth0Logout: true,
    baseURL: 'https://deft-crawler-345920.wl.r.appspot.com',
    clientID: CLIENT_ID,
    issuerBaseURL: 'https://'+ DOMAIN,
    secret: CLIENT_SECRET
  };
app.use(auth(config));
app.use(function (req, res, next) {
    res.locals.user = req.oidc.user;
    next();
  });
  
const datastore = new Datastore({
    projectId: 'deft-crawler-345920',
  });
  
const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const jwtVerify = require('jsonwebtoken');
const { load } = require('@grpc/grpc-js');
// for get key, sets domain for auth0 for getting rsa/public key
var client = jwksRsa({
    jwksUri: `https://${DOMAIN}/.well-known/jwks.json`
});

// Citation for get key function from jsonwebtoken npm documentation
// Function for making call to use the .kid field to retrieve a jwts public/rsa key for verificication
// location: https://www.npmjs.com/package/jsonwebtoken 
// Found in the examples functions for jsonwebtoken.verify
function getKey(header, callback){
    client.getSigningKey(header.kid, function(err, key) {
      var signingKey = key.publicKey || key.rsaPublicKey;
      callback(null, signingKey);
    });
  }
const BOAT = "Boat"
const LOAD = "Load"
const USER = "User"

const router = express.Router();
const login = express.Router();

app.use(bodyParser.json());
app.enable('trust proxy');


function fromDatastore(item){
    item.id = item[Datastore.KEY].id;
    return item;
}
// Middleware from class notes.
const checkJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `https://${DOMAIN}/.well-known/jwks.json`
    }),
  
    // Validate the audience and the issuer.
    issuer: `https://${DOMAIN}/`,
    algorithms: ['RS256']
  });

  //Deals with when we log in through auth0, make user entity if not existing, return userid
async function handleUser(userName, email, userID){
    console.log("arguments are:"+userName+ " and "+email+" and "+ userID+"\n")
    const q = datastore.createQuery(USER).filter('userID', '=', userID);
    return datastore.runQuery(q).then((entities) => {
        var x = entities[0].map(fromDatastore);
        if (x.length < 1){
            console.log("didnt exits, creating \n")
            const new_user = {"name": userName, "email": email, "userID": userID }
            const new_key = datastore.key(USER);
            return datastore.save({ "key": new_key, "data": new_user }).then(() => {
                console.log("retunning"+new_user.userID);
                return new_user.userID; 
            });
        }
        else{
            console.log("already exists, returning: " + x[0].userID);
            return x[0].userID
        }
    })
}

  // The main page, either displays information for signing in, or a logged in users token and the logout hyperlink
router.get('/', async function (req, res){
    //console.log(req.oidc.user);
    if(req.oidc.isAuthenticated()){
        console.log("authenticated, running handle user\n");
        let userID = await handleUser(req.oidc.user.nickname, req.oidc.user.email, req.oidc.user.sub.split("|")[1]);
        res.send("<html> <body><h1>CS 493 Portfolio Assignment</h1> \
        <h1> Welcome!</h1><h2>id_token:</h2>\
         <p>  "+req.oidc.idToken+"</p>\
         <h2>User Id:</h2>\
         <p> "+userID+"</p>\
         <p>Watch out for the hidden endline character when copying and pasting the token into postman!</p>\
         <p>Logout: <a href=https://deft-crawler-345920.wl.r.appspot.com/logout> https://deft-crawler-345920.wl.r.appspot.com/logout <a/> </p>\
         </body></html>")
    }
    else{
        console.log("no token or bad authenitcation");
        res.send("<html> <body> <h1> User Information:</h1>\
        <p>Login: <a href=https://deft-crawler-345920.wl.r.appspot.com/login> https://deft-crawler-345920.wl.r.appspot.com/login <a/> </p>\
        <p> Logged out, No token for you!</p></body></html>")
    }
});

// Get all of the boats for a specific owner 
function get_boats_private(owner_id, req){
	let q = datastore.createQuery(BOAT).filter('owner', '=', owner_id).limit(5);
    let q2 = datastore.createQuery(BOAT).filter('owner', '=', owner_id);

    const results = {}
    if(Object.keys(req.query).includes("cursor")){
        q = q.start(req.query.cursor);
    }
	return datastore.runQuery(q).then( (entities) => {
        results.boats = entities[0].map(fromDatastore).filter((item)=>{return (item.owner === owner_id)})
        results.boats = results.boats.map((boat)=>{
            boat.self = req.protocol + "://" + req.get("host") + req.baseUrl+'/boats/'+boat.id;    
            if (boat.loads.length > 0 ){
                boat.loads.map((load)=>{
                    load.self = req.protocol + "://" + req.get("host")+'/loads/'+load.id;
                    return load;
                })
            }
            return boat;
        })
        if(entities[1].moreResults !== Datastore.NO_MORE_RESULTS ){
            results.next = req.protocol + "://" + req.get("host") + req.baseUrl +"/boats"+ "?cursor=" + encodeURIComponent(entities[1].endCursor);
        }
        return datastore.runQuery(q2).then((entities2) => {
            results.total_owned_boats = entities2[0].length
            return results;
        })
	});
}


// route to get all boats, calls public or private function depening on if authorization was good
router.get('/boats', async function(req, res){
    const accepts = req.accepts(['application/json']);
    if(!accepts){
        res.status(406).json({"Error": "This route only returns application/json data."})
        return
    }
    let owner_id = null;
    if(req.headers.authorization){
            jwtVerify.verify(req.headers.authorization.slice(7), getKey, function(err, decoded){
            if(err){
                const msg = {"Error": "Missing or Invalid JWT"}
                res.status(401).json(msg);       
            }
            else{
                owner_id = decoded.sub.split("|")[1]
                get_boats_private(owner_id, req).then((boats)=>{
                    res.status(200).json(boats);
                })
            }
        });
    }
    else{
        const msg = {"error": "Missing or Invalid JWT"}
            res.status(401).json(msg);
    }
});

//post_lodging(req.body.name, req.body.type, req.body.length, req.body.public, req.user.sub, req.user.name)
function post_boat(name, type, length, owner, req){
    var key = datastore.key(BOAT);
	const new_boat = {"name": name, "type": type, "length": length, "owner":owner, "loads": []};
	return datastore.save({"key":key, "data":new_boat}).then(() => {
        new_boat.id = key.id
        new_boat.self = req.protocol + "://" + req.get("host")+'/boats/'+ new_boat.id;
        return new_boat});
}

// route to post a boat to the database
router.post('/boats', function(req, res){
    const accepts = req.accepts(['application/json']);
    if(!accepts){
        res.status(406).json({"Error": "This route only returns application/json data."})
        return
    }
    let owner_id = null;
    if(req.get('content-type') !== 'application/json'){
        res.status(415).send('Server only accepts application/json data.')
    }
    if(!req.body.name || !req.body.type || !req.body.length){
        res.status(400).json({"Error" : "The request object is missing at least one of the required attributes"});
        return
    }
    if(req.headers.authorization){
        jwtVerify.verify(req.headers.authorization.slice(7), getKey, function(err, decoded){
            if(err){
                res.status(401).json({"Error": "Invalid or missing JWT"});
            }
            else{
                owner_id = decoded.sub.split("|")[1]
                post_boat(req.body.name, req.body.type, req.body.length, owner_id, req)
                .then( boat => {
                    res.status(201).json(boat);
                });
            }
        })
    }
    else{
        res.status(401).json({"Error": "Invalid or missing JWT"});
    }      
});

// deletes a boat from database, first checks if boat belongs to owner or if it even exists
function delete_boat(owner_id, boat_id){
    const key = datastore.key([BOAT, parseInt(boat_id, 10)]);
    return datastore.get(key).then((boat) => {
        if (boat[0] === undefined || boat[0] === null) {
            return "404";
        }
        if(boat[0].owner !== owner_id){
            return "403";
        }
        if(boat[0].loads.length > 0){
            let load_key;
            boat[0].loads.forEach(element => {
                load_key = datastore.key([LOAD, parseInt(element.id, 10)]);
                return datastore.get(load_key).then((load) => {
                    load[0].carrier = null;
                    return datastore.save({"key":load_key, "data":load[0]}).then(() =>{ 
                        return 
                    })
                });
            });
            return datastore.delete(key).then(() => { return "success"});
        }
        else{
            return datastore.delete(key).then(() => { return "success"});
        }
    })
}

// route to faciliate deleting a specifc boat, verifys header then proceeds
router.delete('/boats/:boat_id', function (req, res) {
    let owner_id = null;
    if(req.headers.authorization){
            jwtVerify.verify(req.headers.authorization.slice(7), getKey, function(err, decoded){
            if(err){
                    res.status(401).json({"Error": "Invalid or missing JWT"});}
            else{
                owner_id = decoded.sub.split("|")[1]
                delete_boat(owner_id, req.params.boat_id).then((message)=>{
                    if(message === "403"){
                        res.status(403).json({"Error":"You are forbidden from deleting this boat (not boat owner)"});
                    }
                    else if (message === "404"){
                        res.status(404).json({"Error":"Boat was not found"});
                    }
                    else{
                        res.status(204).end();
                    }
                })
            }
        });
    }
    else{
        res.status(401).json({"Error": "Invalid or missing JWT"});
    }
});

// helper function, removes carrier from load
async function remove_carrier(load_id){
    const key = datastore.key([LOAD, parseInt(load_id, 10)]);
    return datastore.get(key).then((entity) => {
        let newLoad = entity[0];
        newLoad.carrier = null;
        return datastore.save({ "key": key, "data": newLoad}).then(() => {
            return
        })
    })
}

// helper function, async removes carrier from all loads passed to it
async function reset_loads(old_loads){
    for (let load of old_loads){
        await remove_carrier(load.id);
    }
}

// replace an existing boat whith the new req info
function replace_boat(boat_id, req, owner_id){
    let newBoat;
    const key = datastore.key([BOAT, parseInt(boat_id, 10)]);
    return datastore.get(key).then(async (entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            return "404";
        }
        if(entity[0].owner !== owner_id){
            return "403";
        }
        newBoat = entity[0];
        newBoat.name = req.body.name;
        newBoat.type = req.body.type;
        newBoat.length = req.body.length;        
        // handle if the load we are replacing had a carrier....
        if (newBoat.loads.length > 0){
            let old_loads = newBoat.loads;
            newBoat.loads = [];
            await reset_loads(old_loads);
        }
        return datastore.save({ "key": key, "data": newBoat}).then(() => {
            newBoat.id = key.id.toString();
            newBoat.self = req.protocol + "://" + req.get("host")+'/boats/'+ newBoat.id;
            return newBoat 
        });
    })
}

// route to update a specifc load
router.put('/boats/:id', function(req, res){
    const accepts = req.accepts(['application/json']);
    if(!accepts){
        res.status(406).json({"Error": "This route only returns application/json data."})
        return
    }
    if(req.get('content-type') !== 'application/json'){
        res.status(415).send('Server only accepts application/json data.')
    }
    let owner_id = null;
    if(req.headers.authorization){
            jwtVerify.verify(req.headers.authorization.slice(7), getKey, function(err, decoded){
            if(err){
                    res.status(401).json({"Error": "Invalid or missing JWT"});}
            else{
                owner_id = decoded.sub.split("|")[1]
                if(!req.body.name || !req.body.type || !req.body.length){
                    res.status(400).json({"Error" : "The request object is missing at least one of the required attributes"});
                    return
                }
                replace_boat(req.params.id, req, owner_id).then((result)=>{
                    if (result !== "403" && result !== "404"){
                        res.status(200).json(result)
                    }
                    else if (result == "403"){
                        res.status(403).json({"Error" : "You are forbidden from replacing this boat"});
                    }
                    else{
                        res.status(404).json({"Error" : "No boat with this boat_id exists"});
                    }
                });
            }  
        })
    }
    else{
        res.status(401).json({"Error": "Invalid or missing JWT"});
    }
});

// set the carrier of a load
async function set_load_carrier(load_id, boat_id){
    const key = datastore.key([LOAD, parseInt(load_id, 10)]);
    return datastore.get(key).then((entity) => {
        let newLoad = entity[0];
        let goodid = boat_id;
        if(Number.isInteger(goodid)){
            goodid = goodid.toString();
        }
        newLoad.carrier = {"id": goodid};
        return datastore.save({ "key": key, "data": newLoad}).then(() => {
            return
        })
    })
}

// helper function, sets load carrier for array passed in
async function set_new_loads(new_loads, boat_id){
    for (let load of new_loads){
        await set_load_carrier(load.id, boat_id);
    }
}

// check if load has carrier or not
async function check_load(load_id){
    const key = datastore.key([LOAD, parseInt(load_id, 10)]);
    return datastore.get(key).then((entity) => {
        if (entity[0].carrier !== null){
            return false
        }
    })
}

// check all of the loads passed to it to see if they have no carrier
async function check_new_loads(new_loads){
    for (let load of new_loads){
        let result = await check_load(load.id);
        if (result === false){
            return false;
        }
    }
    return true;
}

// deletes a boat from database, first checks if boat belongs to owner or if it even exists
function update_boat(owner_id, req){
    let newBoat;
    const key = datastore.key([BOAT, parseInt(req.params.boat_id, 10)]);
    return datastore.get(key).then(async (entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            return "404";
        }
        if(entity[0].owner !== owner_id){
            return "403";
        }
        newBoat = entity[0];
        if(req.body.name){
            newBoat.name = req.body.name;
        }
        if(req.body.type){
            newBoat.type = req.body.type;
        }
        if(req.body.length){
            newBoat.length = req.body.length;
        }
        if(req.body.loads !== undefined){
            old_loads = newBoat.loads;
            let checkResult = await check_new_loads(req.body.loads);
            if (checkResult === false){
                return "403b"
            }
            await reset_loads(old_loads);
            await set_new_loads(req.body.loads, req.params.boat_id);
            newBoat.loads = req.body.loads.map((load)=>{
                let curId = load.id;
                if(Number.isInteger(load.id)){
                    curId = load.id.toString();
                }
                return {"id": curId }
            });
        }
        return datastore.save({ "key": key, "data": newBoat}).then(() => {
            newBoat.id = key.id.toString();
            newBoat.loads= newBoat.loads.map((load)=>{
                let newLoad = load;
                newLoad.self = req.protocol + "://" + req.get("host") + req.baseUrl+'/loads/'+load.id;
                return newLoad;
            })
            newBoat.self = req.protocol + "://" + req.get("host") + req.baseUrl+'/boats/'+ newBoat.id;
            return newBoat 
        });
    })
}

// replaces the passed in fields from req for the specified boat id
router.patch('/boats/:boat_id', function (req, res) {
    const accepts = req.accepts(['application/json']);
    if(!accepts){
        res.status(406).json({"Error": "This route only returns application/json data."})
        return
    }
    if(req.get('content-type') !== 'application/json'){
        res.status(415).send('Server only accepts application/json data.')
    }
    let owner_id = null;
    if(req.headers.authorization){
            jwtVerify.verify(req.headers.authorization.slice(7), getKey, function(err, decoded){
            if(err){
                    res.status(401).json({"Error": "Invalid or missing JWT"});}
            else{
                owner_id = decoded.sub.split("|")[1]
                update_boat(owner_id, req).then((message)=>{
                    if(message === "404"){
                        res.status(404).json({"Error":"Boat does not exist"});
                    }
                    else if (message === "403"){
                        res.status(403).json({"Error":"You are forbidden from editing this boat"});

                    }
                    else if (message === "403b"){
                        res.status(403).json({"Error":"One or more of the requested loads already has a carrier"});
                    }
                    else{
                        res.status(200).json(message);
                    }
                })
            }
        });
    }
    else{
        res.status(401).json({"Error": "Invalid or missing JWT"});
    }
});

// create a boat based off of params, adds to datastore
function post_load(volume, item, creation_date, req) {
    var key = datastore.key(LOAD);
    var self_url = req.protocol + "://" + req.get("host") + req.baseUrl+'/loads/';
    const new_load = { "volume": volume, "item": item, "creation_date": creation_date, "carrier": null};
    return datastore.save({ "key": key, "data": new_load}).then(() => {
        new_load.id = key.id;
        self_url = self_url + new_load.id;
        new_load.self = self_url;
        return new_load 
    });
}

// Route to faciliate creating a new load
router.post('/loads', function (req, res) {
    const accepts = req.accepts(['application/json']);
    if(!accepts){
        res.status(406).json({"Error": "This route only returns application/json data."})
        return
    }
    if(req.get('content-type') !== 'application/json'){
        res.status(415).send('Server only accepts application/json data.')
    }
    if(!req.body.volume || !req.body.item || !req.body.creation_date)
    {
        res.status(400).json({"Error" : "The request object is missing at least one of the required attributes"});
        return
    }
    post_load(req.body.volume, req.body.item, req.body.creation_date, req)
    .then(load => { res.status(201).json(load) });
});

// get all of the loads in the db, paginate in 5s.
function get_loads(req) {
    var q = datastore.createQuery(LOAD).limit(5);
    var q2 = datastore.createQuery(LOAD);

    const results = {};
    if(Object.keys(req.query).includes("cursor")){
        q = q.start(req.query.cursor);
    }
    return datastore.runQuery(q).then((entities) => {
        results.loads = entities[0].map(fromDatastore);
        results.loads = results.loads.map((load)=>{
            load.self = req.protocol + "://" + req.get("host") + req.baseUrl+'/loads/'+load.id;
            if (load.carrier !== null){
                load.carrier.self = req.protocol + "://" + req.get("host") + '/boats/'+load.carrier.id;
            }
            return load;
        })
        if(entities[1].moreResults !== Datastore.NO_MORE_RESULTS ){
            results.next = req.protocol + "://" + req.get("host") + req.baseUrl +'/loads'+ "?cursor=" + encodeURIComponent(entities[1].endCursor);
        }
        return datastore.runQuery(q2).then((entities2) => {
            results.total_loads = entities2[0].length
            return results;
        })
    });
}
// get all of the boats in datastore
router.get('/loads', function (req, res) {
    const accepts = req.accepts(['application/json']);
    if(!accepts){
        res.status(406).json({"Error": "This route only returns application/json data."})
        return
    }
    get_loads(req).then((results) => {
        res.status(200).json(results); 
    });
});

// get all user entities from datastore, map their entity id to it too
function get_users(){
    const q = datastore.createQuery(USER);
    return datastore.runQuery(q).then((entities) => {
        var x = entities[0].map(fromDatastore);
        return x;
    });
}

// route to get all of the users in the db
router.get('/users', function(req, res){
    const accepts = req.accepts(['application/json']);
    if(!accepts){
        res.status(406).json({"Error": "This route only returns application/json data."})
        return
    }
    get_users(req).then((results) => {
        res.status(200).json(results); 
    });
})

// removes a load from a boat
async function remove_load_from_boat (boat_id, load_id){
    const key = datastore.key([BOAT, parseInt(boat_id, 10)]);
    return datastore.get(key).then((entity) => {
        let newBoat = entity[0];
        let newLoads = entity[0].loads.filter(load => load.id != load_id);
        newBoat.loads = newLoads;
        return datastore.save({ "key": key, "data": newBoat}).then(() => {
            return
        })
    })
}

// replace a specific load with new req info
function replace_load(load_id, req){
    let newLoad;
    const key = datastore.key([LOAD, parseInt(load_id, 10)]);
    return datastore.get(key).then(async (entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            return undefined;
        }
        newLoad = entity[0];
        newLoad.item = req.body.item;
        newLoad.creation_date = req.body.creation_date;
        newLoad.volume = req.body.volume;
        // handle if the load we are replacing had a carrier....
        if (newLoad.carrier !== null ){
            let boat_id = newLoad.carrier.id;
            newLoad.carrier = null;
            await remove_load_from_boat(boat_id, load_id);
        }
        return datastore.save({ "key": key, "data": newLoad}).then(() => {
            newLoad.id = key.id.toString();
            newLoad.self = req.protocol + "://" + req.get("host")+'/loads/'+newLoad.id;
            return newLoad 
        });
    })
}

// route to update a specifc load
router.put('/loads/:id', function(req, res){
    const accepts = req.accepts(['application/json']);
    if(!accepts){
        res.status(406).json({"Error": "This route only returns application/json data."})
        return
    }
    if(req.get('content-type') !== 'application/json'){
        res.status(415).send('Server only accepts application/json data.')
    }
    if(!req.body.item || !req.body.creation_date || !req.body.volume){
        res.status(400).json({"Error" : "The request object is missing at least one of the required attributes"});
        return
    }
    replace_load(req.params.id, req).then((result)=>{
        if (result !== undefined){
            res.status(200).json(result)
        }
        else{
            res.status(404).json({"Error" : "No load with this load_id exists"});
        }
    })
});

// puts a load id in boats loads
async function add_load_to_boat(boat_id, load_id){
    const key = datastore.key([BOAT, parseInt(boat_id, 10)]);
    return datastore.get(key).then((entity) => {
        let newBoat = entity[0];
        let newLoads = entity[0].loads;
        newLoads.push({"id": load_id});
        newBoat.loads = newLoads;
        return datastore.save({ "key": key, "data": newBoat}).then(() => {
            return
        })
    })
}

// update the specified req fields of the load
function update_load(load_id, req){
    let newLoad;
    const key = datastore.key([LOAD, parseInt(load_id, 10)]);
    return datastore.get(key).then(async(entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            return undefined;
        }
        newLoad = entity[0];
        if(req.body.item){
            newLoad.item = req.body.item;
        }
        if(req.body.creation_date){
            newLoad.creation_date = req.body.creation_date;
        }
        if(req.body.volume){
            newLoad.volume = req.body.volume;
        }

        if(req.body.carrier !== undefined){
            //if were removing a carrier and the old one is not null, remove it from its boat
            if(newLoad.carrier !== null){
                await remove_load_from_boat(newLoad.carrier.id, load_id);
            }
            // now set our carrier to the new carrier
            newLoad.carrier = req.body.carrier;
            // if that new carrier was not null, we must add the load to the boats loads
            if (req.body.carrier !== null){
                await add_load_to_boat(req.body.carrier.id, load_id);
            }
            // We need our id to be a string or bad things will happen, make sure its a string
            if(Number.isInteger(newLoad.carrier.id)){
                newLoad.carrier.id = newLoad.carrier.id.toString();
            }
        }
        // once that is over with, save our load, build our self string, return
        return datastore.save({ "key": key, "data": newLoad}).then(() => {
            newLoad.id = key.id.toString();
            newLoad.self = req.protocol + "://" + req.get("host") + req.baseUrl+'/loads/' + newLoad.id;
            if(newLoad.carrier !== null){
                newLoad.carrier.self = req.protocol + "://" + req.get("host") + req.baseUrl+'/boats/' + newLoad.carrier.id;
            }
            return newLoad 
        });
    })
}

// route to update a specifc load
router.patch('/loads/:id', function(req, res){
    const accepts = req.accepts(['application/json']);
    if(!accepts){
        res.status(406).json({"Error": "This route only returns application/json data."})
        return
    }
    if(req.get('content-type') !== 'application/json'){
        res.status(415).send('Server only accepts application/json data.')
    }
    update_load(req.params.id, req).then((result)=>{
        if (result !== undefined){
            res.status(200).json(result)
        }
        else{
            res.status(404).json({"Error" : "No load with this load_id exists"});
        }
    })
});

// deletes a load and modifys corresponding boat
function delete_load(load_id){
    const load_key = datastore.key([LOAD, parseInt(load_id,10)]);
    return datastore.get(load_key).then((load) =>{
        if (load[0] === undefined || load[0] === null) {
            return "404";
        }
        if(load[0].carrier !== null){
            let boat_key = datastore.key([BOAT, parseInt(load[0].carrier.id, 10)]);
                return datastore.get(boat_key).then((boat) => {
                    let new_loads = boat[0].loads.filter(load_obj => load_obj.id !== load_id);
                    boat[0].loads = new_loads;
                    return datastore.save({"key":boat_key, "data":boat[0]}).then(() =>{ 
                        return datastore.delete(load_key)
                    })
                });
        }
        else{
            return datastore.delete(load_key);
        }
    })
}

// route to delete a specifc load
router.delete('/loads/:id', function(req, res){
    delete_load(req.params.id).then((result)=>{
        if (result !== "404"){
            res.status(204).end()
        }
        else{
            res.status(404).json({"Error" : "No load with this load_id exists"});
        }
    })
});

// confirms that loads exist, and that they are owned, and have no carriers before loading
function load_boat_confirmation(boat_key, load_key, type, owner_id){
    return datastore.get(boat_key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            return "404";
        }
        if(entity[0].owner !== owner_id){
            return "403"
        }
        return datastore.get(load_key).then((entity2) => {
            if (entity2[0] === undefined || entity2[0] === null) {
                return "404";
            }
            // if were loading and the carrier is occupied
            if (type === "load" && entity2[0].carrier !== null)
            {
                return "403";
            }
            //if were unloading and the carrier is null or the carrier is the wrong id
            if (type === "unload" && (entity2[0].carrier === null || entity2[0].carrier.id !== String(boat_key.id))){
                return "403"
            }
            return "204";
        })
    })   
}

// puts a load id on a boats loads
function load_boat(owner_id, boat_id, load_id){
    const boat_key = datastore.key([BOAT, parseInt(boat_id,10)]);
    const load_key = datastore.key([LOAD, parseInt(load_id,10)]);
    return load_boat_confirmation(boat_key, load_key, "load", owner_id).then(result =>{
        if (result === "404"){
            return "404";
        }
        if (result === "403"){
            return "403";
        }
        return datastore.get(boat_key)
        .then( (boat) => {
            if( typeof(boat[0].loads) === 'undefined'){
                boat[0].loads = [];
                // I don't think I need to do that....
            }
            boat[0].loads.push({"id": load_id});
            //before Im done, I need to set the load carrier for the load.
            return datastore.save({"key":boat_key, "data":boat[0]}).then(() =>{
                return datastore.get(load_key).then( (load) => {
                    let carrier_obj = {"id": boat_id}
                    load[0].carrier = carrier_obj;
                    return datastore.save({"key":load_key, "data":load[0]}).then(() =>{ 
                        return "good!"
                    })
                })
            });
        })
    })
}

// route for loading a boat
router.patch('/boats/:boat_id/loads/:load_id', function (req, res) {
    let owner_id = null;
    if(req.headers.authorization){
            jwtVerify.verify(req.headers.authorization.slice(7), getKey, function(err, decoded){
            if(err){
                    res.status(401).json({"Error": "Invalid or missing JWT"});}
            else{
                owner_id = decoded.sub.split("|")[1]
                load_boat(owner_id, req.params.boat_id, req.params.load_id).then((message)=>{
                    if(message === "403"){
                        res.status(403).json({"Error":"Either the load is already loaded or you are not authorized to load it"});
                    }
                    else if(message === "404"){
                        res.status(404).json({"Error":" Boat and/or Load Not found"});
                    }
                    else{
                        res.status(204).end();
                    }
                })
            }
        });
    }
    else{
        res.status(401).json({"Error": "Invalid or missing JWT"});
    }
});

// function to remove a specified load from a boat
function unload_boat(owner_id, boat_id, load_id){
    const boat_key = datastore.key([BOAT, parseInt(boat_id,10)]);
    const load_key = datastore.key([LOAD, parseInt(load_id,10)]); 
    return load_boat_confirmation(boat_key, load_key, "unload", owner_id).then(result =>{
        if (result === "404"){
            return "404";
        }
        if (result === "403"){
            return "403";
        }
        return datastore.get(boat_key).then((boat) => {
            let new_loads = boat[0].loads.filter(load_obj => load_obj.id !== load_id);
            boat[0].loads = new_loads;
            //before Im done, I need to set the load carrier for the load.
            return datastore.save({"key":boat_key, "data":boat[0]}).then(() =>{
                return datastore.get(load_key).then((load) => {
                    load[0].carrier = null;
                    return datastore.save({"key":load_key, "data":load[0]}).then(() =>{  
                    })
                })
            });
        })
    })
}

// route to remove a load from a boat
router.delete('/boats/:boat_id/loads/:load_id', function (req, res) {
    let owner_id = null;
    if(req.headers.authorization){
            jwtVerify.verify(req.headers.authorization.slice(7), getKey, function(err, decoded){
            if(err){
                    res.status(401).json({"Error": "Invalid or missing JWT"});}
            else{
                owner_id = decoded.sub.split("|")[1]
                unload_boat(owner_id, req.params.boat_id, req.params.load_id).then((message)=>{
                    if(message === "403"){
                        res.status(403).json({"Error":"Either load is not on the boat or you are forbidden to unload it"});
                    }
                    else if(message === "404"){
                        res.status(404).json({"Error":"Boat and/or Load Not Found"});
                    }
                    else{
                        res.status(204).end();
                    }
                })
            }
        });
    }
    else{
        res.status(401).json({"Error": "Invalid or missing JWT"});
    }
});

// get a specified boat
function get_boat(owner_id, boat_id, req){
    const key = datastore.key([BOAT, parseInt(boat_id, 10)]);
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            return "404";
        }
        if(entity[0].owner !== owner_id){
            return "403"
        }
        else{
            let mapped_boat = entity.map(fromDatastore);
            let url_loads = mapped_boat[0].loads.map( (load_object) =>{
                var self_url = req.protocol + "://" + req.get("host")+'/loads/'+load_object.id;
                load_object.self = self_url; 
                return load_object;
            })
            mapped_boat[0].loads = url_loads;
            mapped_boat[0].self = req.protocol + "://" + req.get("host") + req.baseUrl+'/boats/'+mapped_boat[0].id;
            return mapped_boat[0];
        }     
    });

}

// route to faciliate getting a specific boat
router.get('/boats/:boat_id', function (req, res) {
    const accepts = req.accepts(['application/json']);
    if(!accepts){
        res.status(406).json({"Error": "This route only returns application/json data."})
        return
    }
    if(req.headers.authorization){
        jwtVerify.verify(req.headers.authorization.slice(7), getKey, function(err, decoded){
        if(err){
                res.status(401).json({"Error": "Invalid or missing JWT"});}
        else{
            owner_id = decoded.sub.split("|")[1]
            get_boat(owner_id, req.params.boat_id, req).then((result)=>{
                if(result === "403"){
                    res.status(403).json({"Error":" You are forbidden from getting this boat (not boat owner)"});
                }
                else if(result === "404"){
                    res.status(404).json({"Error":"Boat Not found"});
                }
                else{
                    res.status(200).json(result);
                }
            })
        }
    });
}
else{
    res.status(401).json({"Error": "Invalid or missing JWT"});
}
});

// queries datastore for a specific boat
function get_load(id) {
    const key = datastore.key([LOAD, parseInt(id, 10)]);
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            return entity;
        }
        else{
            return entity.map(fromDatastore);
        }
    });
}

// route to faciliate getting a specific load
router.get('/loads/:load_id', function (req, res) {
    const accepts = req.accepts(['application/json']);
    if(!accepts){
        res.status(406).json({"Error": "This route only returns application/json data."})
        return
    }
    get_load(req.params.load_id).then(load => {
        // check if there were any results
        if (load[0] === undefined || load[0] === null){
            res.status(404).json({ 'Error': 'No load with this load_id exists'});
        } else {
            load[0].self = req.protocol + "://" + req.get("host") + req.baseUrl+'/loads/'+load[0].id;
            if (load[0].carrier !== null){
                load[0].carrier.self = req.protocol + "://" + req.get("host") + '/boats/'+load[0].carrier.id;
            }
            res.status(200).json(load[0]);
        }
    })
});

// 405 functions for unused routes
router.put('/boats', function (req, res){
    res.set('Accept', 'POST');
    res.status(405).end();
});

router.patch('/boats', function (req, res){
    res.set('Accept', 'POST');
    res.status(405).end();
});

router.delete('/boats', function (req, res){
    res.set('Accept', 'POST');
    res.status(405).end();
});

router.put('/loads', function (req, res){
    res.set('Accept', 'POST');
    res.status(405).end();
});

router.patch('/loads', function (req, res){
    res.set('Accept', 'POST');
    res.status(405).end();
});

router.delete('/loads', function (req, res){
    res.set('Accept', 'POST');
    res.status(405).end();
});

/* ------------- End Controller Functions ------------- */
app.use('/', router);
app.use('/login', login);

// Listen to the App Engine-specified port, or 8080 otherwise
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}...`);
});
