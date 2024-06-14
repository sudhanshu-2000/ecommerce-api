const express = require('express');
const app = express();
const admin = require('./admin-api-folder/admin');
const user = require('./user-api-folder/user');
app.use("/assets",express.static('assets'));
PORT= 4899;

app.use('/admin', admin);
app.use('/user', user); 

const listener = app.listen(PORT || 4500, () => {
  console.log("Your app is listening on port " + listener.address().port +" (ecommerce)");
});