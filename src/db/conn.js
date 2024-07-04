var mysql = require("mysql");
const con = mysql.createPool({
  connectionLimit: 10,
  host: "localhost",
  port: 3306,
  user: "root",
  password: "",
  database: "ecommerce",
  multipleStatements:true,
  timezone: 'utc'
});
con.getConnection((err) => {
  if (err) throw err;
  console.log("Database Connected");
});
module.exports = con;
// rmnkuuby_task
// 87@6C]m) 5e[~