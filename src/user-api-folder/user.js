const express = require("express");
const app = express.Router();
exports.app = app;
const con = require("../db/conn");
var jwt = require("jsonwebtoken");
var atob = require('atob');
const cors = require("cors");
app.use(cors());
require("dotenv").config();
SECRET_KEY_USER = ':3.*1>.<2e_1>&b:5.9x_d,86ac3b:-5%1$%?0$*c>4e7,6aa<e?3.8:<8%28<801?0c66d885!?%6@d:_2a_07-1!+c?+%@4$.?>c<d&?<a$b5:*^b9&-&70d-3&@<&&4^e?99$@:1<fdd@9?bc,-?5*d4e_1f6?%,.5c08c6b_1_^,%1.7:4<,341,d%9d-3e4%d6-9.-:f@+$bc5&!-@24e^7cac*+ee:@4>8-+@0!8*&0f<8<.$^&$b43f!d<-$@d3<+a5c_&19^4a2^_?c0d:_6c1+d*_a_:6:3c43.41^2:59ae%b_e&^-d4a$*4b8c+<0@!1a%59.<e3_:68-_e8+4%d!4-360$5%1@+&0!^?d6fcf,?_.8..-f62-+<,_!bf&>a+?f2*0c61!-^7__1448c:60*^?_!9&:1b7>d^@2fa78^2%44*--d.86a<b<8d681^bb5*396&dd_6.^.^$d2:!!<,8@5&^&+*32506658>!_fd8.04@&*5%-.6^4>e99_0ce*@f6$*-d?d4<5?*cd7-26a%&,!4%4904,a!4*12_+93c&+^$24ad_8974d-!.0a$:<:>9&7@&+.a!?0_%*<-69@a07-^_5ce.&cb>32a626,>@,6_6!:5+:2c_7<bc34%8-3^_4<,5%1-@7a,^>>0:+0:2&a^_^9_.b>::^&f+d+@?ded9d7,dc5?3:@1-??7@c0**47-a2c4b:%f&5-!>e_<95d<7.ff--_a-9b&ac:?,6332f!5_>>f>6c@1!:<<__:>0>.^>c@$935?+&--&->$f%23<fa4<44^,>c8-_@a@bd*:e7838*c!>b>,!9%b52!*<*?029.9-44%9@70!^.5bc%b&d4bb$@6&9@8!69+*4$,96<4816c&8+0e4a372e,<47+%5_^bbce-3^409-0f%44!:2e@5+-f3,8_d.de3d_7&a72:,*5-!-c255!&^.1@&:0e&$2!5c9+*e-+fd*+@6%7&0<>-0%c$d^4!-';
SECRET_KEY_VERIFY = ':3.*1>.<2e_1>&b:5.9x_d,86ac3b:-5%1$%?0$*c>4e7,6aa<e?3.6d885!?%6@d:_2a_07-1!+c?+%@4$.?>c<d&?<a$b5:*^b9&-&wetfghjdskf3&@<&&4^e?99$@:1<fdd@9?bc,-?5*d4e_1f6?%,.5c08c6b_1_^,%1.7:4<,341,d%9d-3e4%d6-9.-:f@+$bc5&!-@24e^7cac*+ee:@4>8-+@0!8*&0f<8<.$^&$b43f!d<-$@d3<+a5c_&19^4a2^_?c0d:_6c1+d*_a_:6:3c43.41^2:59ae%b_e&^-d4a$*4b8c+<0@!1a%59.<e3_:68-_e8+4%d!4-360$5%1@+&0!^?d6fcf,?_.8..-f62-+<,_!bf&>a+?f2*0c61!-^7__1448c:60*^?_!9&:1b7>d^@2fa78^2%44*--d.86a<b<8d681^bb5*396&dd_6.^.^$d2:!!<,8@5&^&+*32506658>!_fd8.04@&*5%-.6^4>e99_0ce*@f6$*-d?d4<5?*cd7-26a%&,!4%4904,a!4*12_+93c&+^$24ad_8974d-!.0a$:<:>9&7@&+.a!?0_%*<-69@a07-^_5ce.&cb>32a626,>@,6_6!:5+:2c_7<bc34%8-3^_4<,5%1-@7a,^>>0:+0:2&a^_^9_.b>::^&f+d+@?ded9d7,dc5?3:@1-??7@c0**47-a2c4b:%f&5-!>e_<95d<7.ff--_a-9b&ac:?,6332f!5_>>f>6c@1!:<<__:>0>.^>c@$935?+&--&->$f%23<fa4<44^,>c8-_@a@bd*:e7838*c!>b>,!9%b52!*<*?029.9-44%9@70!^.5bc%b&d4bb$@6&9@8!69+*4$,96<4816c&8+0e4a372e,<47+%5_^bbce-3^409-0f%44!:2e@5+-f3,8_d.de3d_7&a72:,*5-!-c255!&^.1@&:0e&$2!5c9+*e-+fd*+@6%7&0<>-0%c$d^4!-';
const bcrypt = require("bcrypt");
var bodyParser = require("body-parser");
var multer = require("multer");
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({
  limit: "50mb",
  extended: true,
  parameterLimit: 50000,
}));
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "image/deposit");
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + "-" + uniqueSuffix + ".png");
  },
});
const upload = multer({ storage: storage });
const fs = require('fs').promises;
const nodemailer = require("nodemailer");
const transporter = nodemailer.createTransport({
  host: "bond.herosite.pro",
  port: 465,
  secure: true,
  auth: {
    user: "otp@task.sparrowgames.in",
    pass: "_D~!Sve$kS-7",
  },
});
app.get('/get', (req, res) => {
  con.query("SELECT IFNULL(ul.`level_1`,0) as level_1,IFNULL(ul.`level_2`,0) as level_2,IFNULL(ul.`level_3`,0) as level_3,IFNULL(ul.`level_4`,0) as level_4,IFNULL(ul.`level_5`,0) as level_5,IFNULL(ul.`level_6`,0) as level_6,IFNULL(ul.`level_7`,0) as level_7,IFNULL(ul.`level_8`,0) as level_8,IFNULL(ul.`level_9`,0) as level_9 FROM `user_level` as ul WHERE ul.user_reffral = ?;", ['RVGtceVg'], (err, result) => {
    if (err) { throw err; }
    if (result) {
      let objectLength = Object.keys(result[0]).length;
      for (let index = 1; index <= objectLength; index++) {
        const element = result[0][index];

      }
    }
  })
});

app.post("/register", (req, res) => {
  let codecode = code();
  con.query("SELECT * FROM `user_details` WHERE `email` = ?;", [req.body.email], (err, result) => {
    if (err) throw err;
    if (result.length > 0) {
      res.status(302).json({
        error: true,
        status: false,
        message: "Email Id is Already Exist",
      });
    } else {
      con.query("SELECT * FROM `user_details` WHERE `mobile` = ?;", [req.body.mobile], (err, result) => {
        if (err) throw err;
        if (result.length > 0) {
          res.status(302).json({
            error: true,
            status: false,
            message: "Mobile Number is Already Exist",
          });
        } else {
          con.query("SELECT (IFNULL(MAX(uid),100000)) as id FROM user_details", (err, ides) => {
            if (err) throw err;
            if (result) {
              const hash = bcrypt.hashSync(
                req.body.password,
                bcrypt.genSaltSync(12)
              );
              if (req.body.reffer_by == "" || JSON.stringify(req.body.reffer_by) == "null") {
                con.query("INSERT INTO `user_details`(`mobile`, `username`, `password`,`email`, `uid`, `reffer_by`, `reffer_code`) VALUES (?,?,?,?,?,?,?)",
                  [req.body.mobile, req.body.user_name, hash, req.body.email, parseInt(ides[0].id) + 1, 'GJpQpVEO', codecode], (err, result) => {
                    if (err) throw err;
                    if (result) {
                      con.query("INSERT INTO `wallet`(`user_name`, `wallet_balance`) VALUES (?,?)", [req.body.mobile, 0]);
                      reffer(codecode, 'GJpQpVEO');
                      res.status(200).json({
                        error: false,
                        status: true,
                        message: "Registered Successfully",
                      });
                    }
                  }
                );
              } else {
                con.query("select * from user_details where `reffer_code` = ?", [req.body.reffer_by], (err, result) => {
                  if (err) throw err;
                  if (result.length > 0) {
                    con.query("INSERT INTO `user_details`(`mobile`, `username`, `password`, `email`, `uid`, `reffer_by`, `reffer_code`) VALUES (?,?,?,?,?,?,?)",
                      [req.body.mobile, req.body.user_name, hash, req.body.email, parseInt(ides[0].id) + 1, req.body.reffer_by, codecode], (err, result) => {
                        if (err) throw err;
                        if (result) {
                          con.query("SELECT MAX(`name`) as c FROM `level`", (err0, result0) => {
                            if (err0) { throw err0; }
                            if (result0[0].c == 1) {
                              reffer(codecode, 'GJpQpVEO');
                              con.query("INSERT INTO `wallet`(`user_name`, `wallet_balance`) VALUES (?,?)", [req.body.mobile, 0]);
                              res.status(200).json({
                                error: false,
                                status: true,
                                message: "Registered Successfully",
                              });
                            } else if (result0[0].c == 2) {
                              reffer2(codecode, req.body.reffer_by);
                              con.query("INSERT INTO `wallet`(`user_name`, `wallet_balance`) VALUES (?,?)", [req.body.mobile, 0]);
                              res.status(200).json({
                                error: false,
                                status: true,
                                message: "Registered Successfully",
                              });
                            } else if (result0[0].c == 3) {
                              reffer3(codecode, req.body.reffer_by);
                              con.query("INSERT INTO `wallet`(`user_name`, `wallet_balance`) VALUES (?,?)", [req.body.mobile, 0]);
                              res.status(200).json({
                                error: false,
                                status: true,
                                message: "Registered Successfully",
                              });
                            } else if (result0[0].c == 4) {
                              reffer4(codecode, req.body.reffer_by);
                              con.query("INSERT INTO `wallet`(`user_name`, `wallet_balance`) VALUES (?,?)", [req.body.mobile, 0]);
                              res.status(200).json({
                                error: false,
                                status: true,
                                message: "Registered Successfully",
                              });
                            } else if (result0[0].c == 5) {
                              reffer5(codecode, req.body.reffer_by);
                              con.query("INSERT INTO `wallet`(`user_name`, `wallet_balance`) VALUES (?,?)", [req.body.mobile, 0]);
                              res.status(200).json({
                                error: false,
                                status: true,
                                message: "Registered Successfully",
                              });
                            } else if (result0[0].c == 6) {
                              reffer6(codecode, req.body.reffer_by);
                              con.query("INSERT INTO `wallet`(`user_name`, `wallet_balance`) VALUES (?,?)", [req.body.mobile, 0]);
                              res.status(200).json({
                                error: false,
                                status: true,
                                message: "Registered Successfully",
                              });
                            } else if (result0[0].c == 7) {
                              reffer7(codecode, req.body.reffer_by);
                              con.query("INSERT INTO `wallet`(`user_name`, `wallet_balance`) VALUES (?,?)", [req.body.mobile, 0]);
                              res.status(200).json({
                                error: false,
                                status: true,
                                message: "Registered Successfully",
                              });
                            } else if (result0[0].c == 8) {
                              reffer8(codecode, req.body.reffer_by);
                              con.query("INSERT INTO `wallet`(`user_name`, `wallet_balance`) VALUES (?,?)", [req.body.mobile, 0]);
                              res.status(200).json({
                                error: false,
                                status: true,
                                message: "Registered Successfully",
                              });
                            } else {
                              reffer9(codecode, req.body.reffer_by);
                              con.query("INSERT INTO `wallet`(`user_name`, `wallet_balance`) VALUES (?,?)", [req.body.mobile, 0]);
                              res.status(200).json({
                                error: false,
                                status: true,
                                message: "Registered Successfully",
                              });
                            }
                          })
                        }
                      }
                    );
                  } else {
                    res.status(404).json({
                      error: true,
                      status: false,
                      message: "This refferal Code is not valid.",
                    });
                  }
                })
              }
            }
          });
        }
      }
      );
    }
  }
  );
});
app.post("/login", (req, res) => {
  if (typeof (req.body.password) == 'number') {
    res.status(302).json({
      error: true,
      status: false,
      message: "Password Must be require String value",
    });
  }
  else
    con.query(
      "select * from user_details where email = ?",
      [req.body.email],
      (err, result) => {
        if (err) throw err;
        if (result.length > 0) {
          const status = bcrypt.compareSync(
            req.body.password,
            result[0].password
          );
          if (status == true) {
            var token = jwt.sign(
              { username: result[0].email },
              SECRET_KEY_USER, { expiresIn: '1d' },
            );
            con.query("UPDATE `user_details` SET `is_active` = 'Y' WHERE `mobile` = ?", [req.body.email], (err, resulrt) => {
              if (err) { throw err; }
              if (resulrt) {
                res.status(200).json({
                  error: false,
                  status: true,
                  ID: result[0].uid,
                  username: result[0].username,
                  email: result[0].email,
                  message: "Login Successfully",
                  token,
                });
              }
            })
          } else {
            res.status(404).json({
              error: true,
              status: false,
              message: "Mobile Or Password is Wrong",
            });
          }
        } else {
          res.status(404).json({
            error: true,
            message: "Email id is Not Exist",
          });
        }
      }
    );
});
app.post("/logout", async (req, res) => {
  try {
    // Execute the update query asynchronously
    const [result, fields] = await queryAsync(
      "UPDATE `user_details` SET `is_active` = 'N' WHERE `email` = ?",
      [req.body.email]
    );
    // Check if any rows were affected by the update
    if (result && result.affectedRows > 0) {
      res.status(200).json({ error: false, status: true });
    } else {
      res.status(200).json({ error: false, status: false }); // No rows updated
    }
  } catch (error) {
    console.error("Error updating user details:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.post('/check-user-existence', async (req, res) => {
  try {
    const emailResult = await queryAsync("SELECT * FROM `user_details` WHERE `email` = ?;", [req.body.email]);

    if (emailResult.length > 0) {
      return res.status(200).json({
        error: true,
        status: false,
        message: "Email Id is Already Exist",
      });
    }

    const mobileResult = await new queryAsync("SELECT * FROM `user_details` WHERE `mobile` = ?;", [req.body.mobile]);

    if (mobileResult.length > 0) {
      return res.status(200).json({
        error: true,
        status: false,
        message: "Mobile Number is Already Exist",
      });
    }
    return res.status(200).json({
      error: false,
      status: true
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: true,
      status: false,
      message: "Internal Server Error",
    });
  }
});

app.post("/user-details", async (req, res) => {
  try {
    const result = await queryAsync("SELECT ud.id, ud.username as uname, ud.email, ud.mobile,ud.address, ud.email, ud.uid, ud.date FROM `user_details` as ud WHERE ud.`email` = ?",
      [req.body.email])
    if (result && result.length > 0) {
      result.forEach(item => {
        item.address = typeof item.address == 'object' ? [] : (item.address == '' ? [] : JSON.parse(item.address));
      });
      res.status(200).json({
        error: false,
        status: true,
        data: result
      });
    } else {
      res.status(302).json({
        error: true,
        status: false,
        message: "User details not found",
      });
    }
  } catch (error) {
    console.error("Error fetching user details:", error);
    res.status(500).json({
      error: true,
      status: false,
      message: "Internal Server Error",
    });
  }
});

app.post("/update-user-details", async (req, res) => {
  try {
    const cid = req.body.email;
    let array = [];
    const getaddress = await queryAsync("SELECT `address` FROM `user_details` WHERE `email` = ?", [req.body.email]);
    if (req.body.address) {
      if (!getaddress[0].address) {
        req.body.address = JSON.stringify([{
          "id": 1,
          "name": req.body.address.name,
          "street": req.body.address.street,
          "city": req.body.address.city,
          "state": req.body.address.state,
          "country": req.body.address.country,
          "pincode": req.body.address.pincode,
          "phone": req.body.address.phone
        }
        ]);
      } else {
        array = JSON.parse(getaddress[0].address);
        const maxId = getMaxId(array);
        array.push({
          "id": maxId + 1,
          "name": req.body.address.name,
          "street": req.body.address.street,
          "city": req.body.address.city,
          "state": req.body.address.state,
          "country": req.body.address.country,
          "pincode": req.body.address.pincode,
          "phone": req.body.address.phone
        });
        req.body.address = JSON.stringify(array);
      }
    }
    if (req.body.name) {
      req.body.username = req.body.name;
    }
    const allowedColumns = ["username", "address"];
    let stmts = [];
    let values = [];
    for (let c of allowedColumns) {
      if (c in req.body) {
        stmts.push(`${c} = ?`);
        values.push(req.body[c]);
      }
    }
    if (stmts.length === 0) {
      return res.sendStatus(204);
    }
    values.push(cid);
    const result = await queryAsync(`UPDATE user_details SET ${stmts.join(", ")} WHERE email = ?`, values);
    if (result && result.affectedRows > 0) {
      return res.status(200).json({
        error: false,
        status: true,
        // data: result,
      });
    } else {
      const email = await queryAsync("SELECT email FROM `user_details` WHERE `email` = ?", [req.body.email]);
      if (email && email.length > 0 && email[0].email === req.body.email) {
        return res.status(302).json({
          error: true,
          status: false,
          message: "Email id already exists"
        });
      } else {
        return res.status(500).json({
          error: true,
          status: false,
          message: "Failed to update user details"
        });
      }
    }
  } catch (error) {
    console.error('Error updating user details:', error);
    return res.status(500).json({
      error: true,
      status: false,
      message: "Internal Server Error"
    });
  }
});

app.post("/remove-address", async (req, res) => {
  try {
    const result = await queryAsync("SELECT ud.address FROM `user_details` as ud WHERE ud.`email` = ?",
      [req.body.email])
    if (result && result.length > 0) {
      result.forEach(item => {
        item.address = JSON.parse(item.address);
      });
      const a = result[0].address.filter(obj => obj.id !== req.body.id);
      const b = await queryAsync(`UPDATE user_details SET address = ? WHERE email = ?`, [JSON.stringify(a), req.body.email]);
      if (b && b.affectedRows > 0) {
        return res.status(200).json({
          error: false,
          status: true
        });
      } else {
        return res.status(500).json({
          error: true,
          status: false,
          message: "Failed to update user details"
        });
      }
    } else {
      res.status(302).json({
        error: true,
        status: false,
        message: "User details not found",
      });
    }
  } catch (error) {
    console.error("Error fetching user details:", error);
    res.status(500).json({
      error: true,
      status: false,
      message: "Internal Server Error",
    });
  }
});
app.post("/wallet-balance", verifyToken, (req, res) => {
  // req.body = JSON.parse(atob(req.body.data));
  con.query(
    "SELECT * FROM `wallet` WHERE user_name = ?",
    [req.body.mobile],
    (err, result) => {
      if (err) throw err;
      if (result) {
        res.status(200).json({
          error: false,
          status: "Success",
          data: result
        });
      }
    }
  );
});

app.post("/get-statement", verifyToken, async (req, res) => {
  try {
    const result = await queryAsync("SELECT s.email, s.type, s.amount, s.total_balance, s.date FROM `statement` as s WHERE `email` = ?",
      [req.body.email])

    if (result.length > 0) {
      res.status(200).json({
        error: false,
        status: true,
        data: result,
      });
    } else {
      res.status(404).json({
        error: true,
        status: false,
        message: "No data found",
      });
    }
  } catch (error) {
    console.error("Error retrieving statement:", error);
    res.status(500).json({ error: true, message: "Internal Server Error" });
  }
});

app.post("/get-statement-date", verifyToken, async (req, res) => {
  try {
    const result = await queryAsync("SELECT IFNULL(SUM(`amount`), 0) AS today FROM `statement` WHERE DATE(`date`) = CURRENT_DATE() AND `email` = ?; SELECT IFNULL(SUM(`amount`), 0) AS yesterday FROM `statement` WHERE DATE(`date`) = CURRENT_DATE() - INTERVAL 1 DAY AND `email` = ?; SELECT IFNULL(SUM(`amount`), 0) AS week FROM `statement` WHERE DATE(`date`) BETWEEN CURRENT_DATE() - INTERVAL 7 DAY AND CURRENT_DATE() AND `email` = ?; SELECT IFNULL(SUM(`amount`), 0) AS month FROM `statement` WHERE DATE(`date`) BETWEEN CURRENT_DATE() - INTERVAL 30 DAY AND CURRENT_DATE() AND `email` = ?;",
      [req.body.email, req.body.email, req.body.email, req.body.email])

    if (result.length > 0) {
      res.status(200).json({
        error: false,
        status: true,
        data: result,
      });
    } else {
      res.status(404).json({
        error: true,
        status: false,
        message: "No data found",
      });
    }
  } catch (error) {
    console.error("Error retrieving statement date:", error);
    res.status(500).json({ error: true, message: "Internal Server Error" });
  }
});

app.post("/get-otp", async (req, res) => {
  try {
    const val = Math.floor(1000 + Math.random() * 9000);
    const hash = bcrypt.hashSync(val.toString(), bcrypt.genSaltSync(12));

    const result = await queryAsync("SELECT * FROM `otp` WHERE `number` = ?", [req.body.email],)

    if (result.length > 0) {
      transporter.sendMail({
        from: 'otp@task.sparrowgames.in',
        to: req.body.email,
        subject: "OTP Verification",
        text: "To Create your Acoount",
        html: `Your OTP is <b>${val.toString()}</b>, valid for 10 min`,
      });
      con.query("UPDATE `otp` SET `otp` = ? WHERE `number` = ?", [hash, req.body.email], (err, result) => {
        if (err) throw err;
        if (result) {
          res.status(200).json({
            error: false,
            status: true,
          });
        }
      });
    } else {
      transporter.sendMail({
        from: 'otp@task.sparrowgames.in',
        to: req.body.email,
        subject: "OTP Verification",
        text: "To Create your Acoount",
        html: `Your OTP is <b>${val.toString()}</b>, valid for 10 min`,
      });

      await new Promise((resolve, reject) => {
        con.query("INSERT INTO `otp`(`otp`, `number`) VALUES (?,?)", [hash, req.body.email], (err, result) => {
          if (err) reject(err);
          else resolve(result);
        });
      });
    }

    res.status(200).json({
      error: false,
      status: true,
    });
  } catch (error) {
    console.error('Error in /get-otp:', error);
    res.status(500).json({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/verify-otp", async (req, res) => {
  try {
    const result = await queryAsync("SELECT * FROM `otp` WHERE number = ?", [req.body.email]);

    if (result.length > 0) {
      const match = bcrypt.compareSync(req.body.otp.toString(), result[0].otp);
      if (match) {
        await new Promise((resolve, reject) => {
          con.query("DELETE FROM `otp` WHERE number = ?", [req.body.email], (err, result) => {
            if (err) reject(err);
            else resolve(result);
          });
        });

        const token = jwt.sign({ email: req.body.email }, SECRET_KEY_VERIFY, { expiresIn: '10m' });

        return res.status(200).json({
          error: false,
          status: true,
          token,
          msg: "OTP Verified",
        });
      } else {
        return res.status(200).json({
          error: true,
          status: false,
          msg: "Wrong OTP",
        });
      }
    } else {
      return res.status(200).json({
        error: true,
        status: false,
        msg: "OTP Expired",
      });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: true,
      status: false,
      msg: "Internal Server Error",
    });
  }
});

app.post("/get-product", async (req, res) => {
  try {
    const result = await queryAsync("SELECT `id`,`name`,(select c.name from `category` as c WHERE c.id = `category_id`) as 'category',`category_id` as 'cat_id',(select sc.name from `sub_category` as sc WHERE sc.id = `sub_category_id`) as 'sub_category',`sub_category_id` as 'sub_cat_id',`colorDetails`,`date` FROM `product`");
    result.forEach(item => {
      item.colorDetails = JSON.parse(item.colorDetails);
      item.colorDetails.forEach(detail => {
        detail.name = item.name;
        detail.id = item.id;
        detail.image_url = JSON.parse(detail.image_url);
        detail.sizeDetails = JSON.parse(detail.sizeDetails);
      });
    });
    res.status(200).json({
      error: false,
      status: true,
      path: "assets/img",
      data: result
    })
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: true,
      message: "Internal server error"
    });
  }
});
app.post("/get-product-id", async (req, res) => {
  try {
    const result = await queryAsync("SELECT `id`,`name`,(select c.name from `category` as c WHERE c.id = `category_id`) as 'category',`category_id` as 'cat_id',(select sc.name from `sub_category` as sc WHERE sc.id = `sub_category_id`) as 'sub_category',`sub_category_id` as 'sub_cat_id',`colorDetails`,`date` FROM `product` where `id` = ?", req.body.id);
    const transformedData = result.map(product => {
      const colorDetails = JSON.parse(product.colorDetails).map(detail => ({
        ...detail,
        image_url: JSON.parse(detail.image_url),
        sizeDetails: JSON.parse(detail.sizeDetails)
      }));
      return {
        ...product,
        colorDetails
      };
    });
    res.status(200).json({
      error: false,
      status: true,
      path: "assets/img",
      data: transformedData
    })
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: true,
      message: "Internal server error"
    });
  }
});

app.post("/get-sub-category-by-id", async (req, res) => {
  try {
    const result = await queryAsync("SELECT `id`,`name`,image_url FROM `sub_category` WHERE `category_id` = ?", [req.body.cat_id]);
    res.status(200).json({
      error: false,
      status: true,
      data: result
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: true,
      message: "Internal server error"
    });
  }
});
app.post("/get-sub-category", async (req, res) => {
  try {
    const result = await queryAsync("SELECT `id`,`name`,`image_url`,(SELECT `name` FROM `category` WHERE `id`=sc.`category_id`) as cat_name,`category_id` as cat_id FROM `sub_category` as sc");
    res.status(200).json({
      error: false,
      status: true,
      data: result
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: true,
      message: "Internal server error"
    });
  }
});
app.post("/get-category", async (req, res) => {
  try {
    const result = await queryAsync("SELECT `id`,`name`,image_url FROM `category`");
    res.status(200).json({
      error: false,
      status: true,
      data: result
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: true,
      message: "Internal server error"
    });
  }
});
app.post("/get-sub-category-product", async (req, res) => {
  try {
    const result = await queryAsync("SELECT `id`,`name`,(select c.name from `category` as c WHERE c.id = `category_id`) as 'category',`category_id` as 'cat_id',(select sc.name from `sub_category` as sc WHERE sc.id = `sub_category_id`) as 'sub_category',`sub_category_id` as 'sub_cat_id',`colorDetails`,`date` FROM `product` WHERE `category_id` = ? AND `sub_category_id` = ?", [req.body.cat_id, req.body.sub_cat_id]);
    result.forEach(item => {
      item.colorDetails = JSON.parse(item.colorDetails);
      item.colorDetails.forEach(detail => {
        detail.name = item.name;
        detail.id = item.id;
        detail.image_url = JSON.parse(detail.image_url);
        detail.sizeDetails = JSON.parse(detail.sizeDetails);
      });
    });
    res.status(200).json({
      error: false,
      status: true,
      data: result
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: true,
      message: "Internal server error"
    });
  }
});
app.post('/get-current-offer', verifyToken, (req, res) => {
  con.query("SELECT  COUNT(`coupan`) as count FROM `deposit` WHERE `user_name` = ? and `coupan` = 'First' and (`status` = 'Success' OR `status` = 'Pending')", [req.body.mobile], (err, result) => {
    if (err) { throw err; }
    if (result[0].count == 0) {
      con.query("SELECT * FROM `payment_bonus` WHERE `status` = 'Y' ORDER BY id ASC LIMIT 1 OFFSET 0", (err, result) => {
        if (err) throw err;
        if (result) {
          res.status(200).json(btoa(JSON.stringify({ error: false, status: true, data: result })))
        }
      })
    } else {
      con.query("SELECT  COUNT(`coupan`) as count FROM `deposit` WHERE `user_name` = ? and `coupan` = 'SECOND' and (`status` = 'Success' OR `status` = 'Pending')", [req.body.mobile], (err, result) => {
        if (err) { throw err; }
        if (result[0].count == 0) {
          con.query("SELECT * FROM `payment_bonus` WHERE `status` = 'Y' ORDER BY id ASC LIMIT 1 OFFSET 1", (err, result) => {
            if (err) throw err;
            if (result) {
              res.status(200).json(btoa(JSON.stringify({ error: false, status: true, data: result })))
            }
          })
        } else {
          con.query("SELECT  COUNT(`coupan`) as count FROM `deposit` WHERE `user_name` = ? and `coupan` = 'THIRD' and (`status` = 'Success' OR `status` = 'Pending')", [req.body.mobile], (err, result) => {
            if (err) { throw err; }
            if (result[0].count == 0) {
              con.query("SELECT * FROM `payment_bonus` WHERE `status` = 'Y' ORDER BY id ASC LIMIT 1 OFFSET 2", (err, result) => {
                if (err) throw err;
                if (result) {
                  res.status(200).json(btoa(JSON.stringify({ error: false, status: true, data: result })))
                }
              })
            } else {
              con.query("SELECT  COUNT(`coupan`) as count FROM `deposit` WHERE `user_name` = ? and `coupan` = 'FOURTH' and (`status` = 'Success' OR `status` = 'Pending')", [req.body.mobile], (err, result) => {
                if (err) { throw err; }
                if (result[0].count == 0) {
                  con.query("SELECT * FROM `payment_bonus` WHERE `status` = 'Y' ORDER BY id ASC LIMIT 1 OFFSET 3", (err, result) => {
                    if (err) throw err;
                    if (result) {
                      res.status(200).json(btoa(JSON.stringify({ error: false, status: true, data: result })))
                    }
                  })
                } else {
                  con.query("SELECT  COUNT(`coupan`) as count FROM `deposit` WHERE `user_name` = ? and `coupan` = 'FIFTH' and (`status` = 'Success' OR `status` = 'Pending')", [req.body.mobile], (err, result) => {
                    if (err) { throw err; }
                    if (result[0].count == 0) {
                      con.query("SELECT * FROM `payment_bonus` WHERE `status` = 'Y' ORDER BY id ASC LIMIT 1 OFFSET 4", (err, result) => {
                        if (err) throw err;
                        if (result) {
                          res.status(200).json(btoa(JSON.stringify({ error: false, status: true, data: result })))
                        }
                      })
                    } else {
                      con.query("SELECT * FROM `payment_bonus` WHERE `status` = 'Y' ORDER BY id ASC LIMIT 100 OFFSET 5", (err, result) => {
                        if (err) throw err;
                        if (result) {
                          res.status(200).json(btoa(JSON.stringify({ error: false, status: true, data: result })))
                        }
                      })
                    }
                  })
                }
              })
            }
          })
        }
      })
    }
  })
});
app.post('/check-coupon-code', verifyToken, (req, res) => {
  req.body = JSON.parse(atob(req.body.data));
  con.query("SELECT * FROM `payment_bonus` WHERE `offer_name` = ? AND `status` = 'Y'", [req.body.code], (err, result) => {
    if (err) throw err;
    if (result.length > 0) {
      if (parseInt(req.body.balance) >= parseInt(result[0].amount_start) && parseInt(req.body.balance) <= parseInt(result[0].amount_end)) {
        res.status(200).json(btoa(JSON.stringify({ error: false, status: true, massage: "Apply SuccessFully", })));
      } else {
        res.status(200).json(btoa(JSON.stringify({ error: true, status: false, massage: "Invalid Coupon Code", })));
      }
    } else {
      res.status(200).json(btoa(JSON.stringify({ error: true, status: false, massage: "Invalid Coupon Code", })));
    }
  })
});
app.post("/remove-cart", async (req, res) => {
  try {
    const result = await queryAsync("DELETE FROM `add_to_cart` WHERE `id`=?", [req.body.id]);
    if (result) {
      res.status(200).json({ error: false, status: true });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: true, message: "Internal Server Error" });
  }
});

app.post('/add-wishlist', async (req, res) => {
  try {
    const checkemail = await queryAsync("SELECT `id` FROM `user_details` WHERE `email`=?", req.body.email);
    if (checkemail.length > 0) {
      const checkcolor = req.body.color.includes('#');
      if (checkcolor) {
        const result = await queryAsync(
          "INSERT INTO `add_to_wish`(`user_id`, `color`, `size`, `product_id`) VALUES ((SELECT `id` FROM `user_details` WHERE `email`=?),?,?,?)",
          [req.body.email, req.body.color, req.body.size, req.body.product_id]
        );
        if (result) {
          res.status(200).json({ error: false, status: true });
        }
      }
      else {
        res.status(400).json({ error: true, status: false, message: "Color Code required Only!" });
      }
    } else {
      res.status(400).json({ error: true, status: false, message: "Invalid Email!" });
    }
  } catch (err) {
    res.status(500).json({ error: true, status: false, message: err.message });
  }
});
app.post('/get-wishlist', async (req, res) => {
  try {
    let array = [];
    const result = await queryAsync(
      "SELECT atc.id as cart_id,atc.user_id,atc.color,atc.size,atc.product_id,p.name,p.category_id,p.sub_category_id,p.colorDetails,atc.date FROM `add_to_wish` as atc INNER join product as p on atc.product_id = p.id WHERE `user_id`=(SELECT id FROM `user_details` WHERE `email`=?)",
      [req.body.email]
    );
    if (result) {
      const transformedData = result.map(product => {
        const colorDetails = JSON.parse(product.colorDetails).map(detail => ({
          ...detail,
          image_url: JSON.parse(detail.image_url),
          sizeDetails: JSON.parse(detail.sizeDetails)
        }));
        return {
          ...product,
          colorDetails
        };
      });
      for (let index = 0; index < transformedData.length; index++) {
        const element = transformedData[index];
        for (let index = 0; index < element.colorDetails.length; index++) {
          const a = element.colorDetails[index];
          if (element.color == a.color) {
            for (let index = 0; index < a.sizeDetails.length; index++) {
              const b = a.sizeDetails[index];
              if (element.size == b.size) {
                array.push({
                  "cart_id": element.cart_id,
                  "user_id": element.user_id,
                  "color": a.color,
                  "size": element.size,
                  "product_id": element.product_id,
                  "date": element.date,
                  "name": element.name,
                  "category_id": element.category_id,
                  "sub_category_id": element.sub_category_id,
                  "colorDetails": [
                    {
                      "color": a.color,
                      "image_url": [a.image_url],
                      "gender": a.gender,
                      "promoted": a.promoted,
                      "top_selling": a.top_selling,
                      "shipping_note": a.shipping_note,
                      "extra_info": a.extra_info,
                      "description": a.description,
                      "sizeDetails": [b]
                    }
                  ]
                })
              }
            }
          }
        }
      }
      res.status(200).json({ error: false, status: true, data: array });
    }
  } catch (err) {
    res.status(500).json({ error: true, status: false, message: err.message });
  }
});
app.post("/remove-wishlist", async (req, res) => {
  try {
    const result = await queryAsync("DELETE FROM `add_to_wish` WHERE `id`=?", [req.body.id]);
    if (result) {
      res.status(200).json({ error: false, status: true });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: true, message: "Internal Server Error" });
  }
});
app.post("/get-level", async (req, res) => {
  const dataArray = [];
  const mobile = req.body.mobile;
  try {
    const levelQueries = [];
    for (let i = 1; i <= 9; i++) {
      const levelQuery = con.query(
        `SELECT ul.id, ud.uid, ud.username, 'level_${i}' as level, 
                (SELECT price FROM \`level\` WHERE \`name\` = '${i}') as amount, 
                ul.status${i} as status, ul.date 
         FROM \`user_level\` as ul 
         INNER JOIN user_details as ud ON ul.user_reffral = ud.reffer_code 
         WHERE ul.\`level_${i}\` = (SELECT udd.reffer_code FROM user_details as udd WHERE udd.mobile = ?)`,
        [mobile]
      );

      levelQueries.push(levelQuery);
    }
    const results = await Promise.all(levelQueries);
    results.forEach(result => {
      if (result) dataArray.push(...result);
    });
    dataArray.sort((a, b) => a.date - b.date);
    res.status(200).json({
      error: false,
      status: true,
      data: dataArray.reverse()
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: true,
      status: false,
      message: 'Internal Server Error'
    });
  }
});
app.post("/token-check", async (req, res) => {
  const bearerHeader = req.headers["authorization"];
  const MISSING_FIELDS = "Missing required fields";
  const INVALID_DATA_FORMAT = "Invalid data format";
  const TOKEN_EXPIRED = "Token Expired";

  if (!bearerHeader) {
    return res.status(403).send('Authorization header missing');
  }

  const bearer = bearerHeader.split(" ");
  const bearerToken = bearer[1];
  req.token = bearerToken;

  jwt.verify(req.token, SECRET_KEY_USER, (err, auth) => {
    if (err) {
      return res.status(403).send(TOKEN_EXPIRED);
    }

    const { email, data } = req.body;

    if (email) {
      return auth.username === email ? res.status(200).json({ error: false, status: true }) : res.status(200).json({ error: true, status: false, massage: TOKEN_EXPIRED })
    }

    if (data) {
      try {
        const decodedData = JSON.parse(Buffer.from(data, 'base64').toString('utf8'));
        return auth.username === decodedData.email ? res.status(200).json({ error: false, status: true }) : res.status(200).json({ error: true, status: false, massage: TOKEN_EXPIRED })
      } catch (error) {
        return res.status(400).send(INVALID_DATA_FORMAT);
      }
    }

    return res.status(400).send(MISSING_FIELDS);
  });
});

app.post("/add-order", async (req, res) => {
  try {
    for (let index = 0; index < req.body.items.length; index++) {
      const a = req.body.items[index];
      await queryAsync("INSERT INTO `order_page`(`user_id`, `product_id`, `size`, `color`, `qty`, `price`, `address`, `payment_type`, `delivery_date`) VALUES ((SELECT ud.`id` from `user_details` as ud WHERE ud.email = ?),?,?,?,?,?,?,?,(DATE_ADD(current_date(), INTERVAL 7 DAY)))", [req.body.email, a.product_id, a.size, a.color, a.qty, 290, JSON.stringify(req.body.address), req.body.payment_type])
      if (req.body.items.length - 1 == index) {
        res.status(200).send("true")
      }
    }
  } catch (error) {
    res.status(500).json({
      error: true,
      status: false,
      message: 'Internal Server Error'
    });
  }
}) //Prcessing 
app.post("/get-order", async (req, res) => {
  try {
    const array = [];
    const result = await queryAsync("SELECT op.id,p.name,p.colorDetails,op.size,op.color,op.qty,op.price,op.address, op.payment_type,op.delivery_date,op.status,op.date FROM `order_page` as op INNER join `product` as p on op.product_id = p.id WHERE op.`user_id` = (select udd.`id` from `user_details` as udd where udd.`email` = ? )", [req.body.email]);
    result.forEach(item => {
      item.colorDetails = JSON.parse(item.colorDetails);
      item.colorDetails.forEach(detail => {
        detail.name = item.name;
        detail.id = item.id;
        detail.image_url = JSON.parse(detail.image_url);
        detail.sizeDetails = JSON.parse(detail.sizeDetails);
      });
      item.address = JSON.parse(item.address);
    });
        if (result) {
          res.status(200).json({ error: false, status: true, data: result });
        }
  } catch (error) {
    res.status(500).json({
      error: true,
      status: false,
      message: 'Internal Server Error'
    });
  }
})

function verifyToken(req, res, next) {
  const bearerHeader = req.headers["authorization"];
  const MISSING_FIELDS = "Missing required fields";
  const INVALID_DATA_FORMAT = "Invalid data format";
  const TOKEN_EXPIRED = "Token Expired";
  const UNAUTHORIZED = "Unauthorized";

  if (!bearerHeader) {
    return res.status(403).send('Authorization header missing');
  }

  const bearer = bearerHeader.split(" ");
  const bearerToken = bearer[1];
  req.token = bearerToken;

  jwt.verify(req.token, SECRET_KEY_USER, (err, auth) => {
    if (err) {
      return res.status(403).send(TOKEN_EXPIRED);
    }

    const { mobile, data } = req.body;

    if (mobile) {
      return auth.username === mobile ? next() : res.status(403).send(UNAUTHORIZED);
    }

    if (data) {
      try {
        const decodedData = JSON.parse(Buffer.from(data, 'base64').toString('utf8'));
        return auth.username === decodedData.mobile ? next() : res.status(403).send(UNAUTHORIZED);
      } catch (error) {
        return res.status(400).send(INVALID_DATA_FORMAT);
      }
    }

    return res.status(400).send(MISSING_FIELDS);
  });
}
function code() {
  let x = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  let a = "";
  for (let index = 0; index < 8; index++) {
    a += x[Math.floor(Math.random() * x.length)];
  }

  return new Promise((resolve, reject) => {
    con.query("select * from user_details where `reffer_code` = ?", [a], (err, result) => {
      if (err) return reject(err);
      if (result.length > 0) {
        resolve(code()); // Recursively generate a new code
      } else {
        resolve(a);
      }
    });
  });
}
function reffer(ba, ab) {
  con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`) VALUES (?,?)', [ba, ab]);
}
function reffer2(ba, ab) {
  con.query("SELECT IFNULL(ud.`reffer_by`, 0) as ref FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [ab], (err, level1) => {
    if (err) throw err;
    if (level1[0].ref == '') {
      con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`) VALUES (?,?)', [ba, ab]);
    } else {
      con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`) VALUES (?,?,?)', [ba, ab, level1[0].ref]);
    }
  })
}
function reffer3(ba, ab) {
  con.query("SELECT IFNULL(ud.`reffer_by`, 0) as ref FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [ab], (err, level1) => {
    if (err) throw err;
    if (level1[0].ref == '') {
      con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`) VALUES (?,?)', [ba, ab]);
    } else {
      con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level1[0].ref], (err, level2) => {
        if (err) throw err;
        if (level2[0].reff == '') {
          con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`) VALUES (?,?,?)', [ba, ab, level1[0].ref]);
        } else {
          con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`) VALUES (?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff]);
        }
      })
    }
  })
}
function reffer4(ba, ab) {
  con.query("SELECT IFNULL(ud.`reffer_by`, 0) as ref FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [ab], (err, level1) => {
    if (err) throw err;
    if (level1[0].ref == '') {
      con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`) VALUES (?,?)', [ba, ab]);
    } else {
      con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level1[0].ref], (err, level2) => {
        if (err) throw err;
        if (level2[0].reff == '') {
          con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`) VALUES (?,?,?)', [ba, ab, level1[0].ref]);
        } else {
          con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level2[0].reff], (err, level3) => {
            if (err) throw err;
            if (level3[0].reff == '') {
              con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`) VALUES (?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff]);
            } else {
              con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`) VALUES (?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff]);
            }
          })
        }
      })
    }
  })
}
function reffer5(ba, ab) {
  con.query("SELECT IFNULL(ud.`reffer_by`, 0) as ref FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [ab], (err, level1) => {
    if (err) throw err;
    if (level1[0].ref == '') {
      con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`) VALUES (?,?)', [ba, ab]);
    } else {
      con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level1[0].ref], (err, level2) => {
        if (err) throw err;
        if (level2[0].reff == '') {
          con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`) VALUES (?,?,?)', [ba, ab, level1[0].ref]);
        } else {
          con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level2[0].reff], (err, level3) => {
            if (err) throw err;
            if (level3[0].reff == '') {
              con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`) VALUES (?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff]);
            } else {
              con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level3[0].reff], (err, level4) => {
                if (err) throw err;
                if (level4[0].reff == '') {
                  con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`) VALUES (?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff]);
                } else {
                  con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`, `level_5`) VALUES (?,?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff, level4[0].reff]);
                }
              })
            }
          })
        }
      })
    }
  })
}
function reffer6(ba, ab) {
  con.query("SELECT IFNULL(ud.`reffer_by`, 0) as ref FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [ab], (err, level1) => {
    if (err) throw err;
    if (level1[0].ref == '') {
      con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`) VALUES (?,?)', [ba, ab]);
    } else {
      con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level1[0].ref], (err, level2) => {
        if (err) throw err;
        if (level2[0].reff == '') {
          con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`) VALUES (?,?,?)', [ba, ab, level1[0].ref]);
        } else {
          con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level2[0].reff], (err, level3) => {
            if (err) throw err;
            if (level3[0].reff == '') {
              con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`) VALUES (?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff]);
            } else {
              con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level3[0].reff], (err, level4) => {
                if (err) throw err;
                if (level4[0].reff == '') {
                  con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`) VALUES (?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff]);
                } else {
                  con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level4[0].reff], (err, level5) => {
                    if (err) throw err;
                    if (level5[0].reff == '') {
                      con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`, `level_5`) VALUES (?,?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff, level4[0].reff]);
                    } else {
                      con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`, `level_5`, `lavel_6`) VALUES (?,?,?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff, level4[0].reff, level5[0].reff]);
                    }
                  })
                }
              })
            }
          })
        }
      })
    }
  })
}
function reffer7(ba, ab) {
  con.query("SELECT IFNULL(ud.`reffer_by`, 0) as ref FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [ab], (err, level1) => {
    if (err) throw err;
    if (level1[0].ref == '') {
      con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`) VALUES (?,?)', [ba, ab]);
    } else {
      con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level1[0].ref], (err, level2) => {
        if (err) throw err;
        if (level2[0].reff == '') {
          con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`) VALUES (?,?,?)', [ba, ab, level1[0].ref]);
        } else {
          con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level2[0].reff], (err, level3) => {
            if (err) throw err;
            if (level3[0].reff == '') {
              con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`) VALUES (?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff]);
            } else {
              con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level3[0].reff], (err, level4) => {
                if (err) throw err;
                if (level4[0].reff == '') {
                  con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`) VALUES (?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff]);
                } else {
                  con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level4[0].reff], (err, level5) => {
                    if (err) throw err;
                    if (level5[0].reff == '') {
                      con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`, `level_5`) VALUES (?,?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff, level4[0].reff]);
                    } else {
                      con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level5[0].reff], (err, level6) => {
                        if (err) throw err;
                        if (level6[0].reff == '') {
                          con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`, `level_5`, `lavel_6`) VALUES (?,?,?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff, level4[0].reff, level5[0].reff]);
                        } else {
                          con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`, `level_5`, `lavel_6`, `lavel_7`) VALUES (?,?,?,?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff, level4[0].reff, level5[0].reff, level6[0].reff]);
                        }
                      })
                    }
                  })
                }
              })
            }
          })
        }
      })
    }
  })
}
function reffer8(ba, ab) {
  con.query("SELECT IFNULL(ud.`reffer_by`, 0) as ref FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [ab], (err, level1) => {
    if (err) throw err;
    if (level1[0].ref == '') {
      con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`) VALUES (?,?)', [ba, ab]);
    } else {
      con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level1[0].ref], (err, level2) => {
        if (err) throw err;
        if (level2[0].reff == '') {
          con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`) VALUES (?,?,?)', [ba, ab, level1[0].ref]);
        } else {
          con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level2[0].reff], (err, level3) => {
            if (err) throw err;
            if (level3[0].reff == '') {
              con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`) VALUES (?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff]);
            } else {
              con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level3[0].reff], (err, level4) => {
                if (err) throw err;
                if (level4[0].reff == '') {
                  con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`) VALUES (?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff]);
                } else {
                  con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level4[0].reff], (err, level5) => {
                    if (err) throw err;
                    if (level5[0].reff == '') {
                      con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`, `level_5`) VALUES (?,?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff, level4[0].reff]);
                    } else {
                      con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level5[0].reff], (err, level6) => {
                        if (err) throw err;
                        if (level6[0].reff == '') {
                          con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`, `level_5`, `lavel_6`) VALUES (?,?,?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff, level4[0].reff, level5[0].reff]);
                        } else {
                          con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level6[0].reff], (err, level7) => {
                            if (err) throw err;
                            if (level7[0].reff == '') {
                              con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`, `level_5`, `lavel_6`, `lavel_7`) VALUES (?,?,?,?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff, level4[0].reff, level5[0].reff, level6[0].reff]);
                            } else {
                              con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`, `level_5`, `lavel_6`, `lavel_7`, `lavel_8`) VALUES (?,?,?,?,?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff, level4[0].reff, level5[0].reff, level6[0].reff, level7[0].reff]);
                            }
                          })
                        }
                      })
                    }
                  })
                }
              })
            }
          })
        }
      })
    }
  })
}
function reffer9(ba, ab) {
  con.query("SELECT IFNULL(ud.`reffer_by`, 0) as ref FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [ab], (err, level1) => {
    if (err) throw err;
    if (level1[0].ref == '') {
      con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`) VALUES (?,?)', [ba, ab]);
    } else {
      con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level1[0].ref], (err, level2) => {
        if (err) throw err;
        if (level2[0].reff == '') {
          con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`) VALUES (?,?,?)', [ba, ab, level1[0].ref]);
        } else {
          con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level2[0].reff], (err, level3) => {
            if (err) throw err;
            if (level3[0].reff == '') {
              con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`) VALUES (?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff]);
            } else {
              con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level3[0].reff], (err, level4) => {
                if (err) throw err;
                if (level4[0].reff == '') {
                  con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`) VALUES (?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff]);
                } else {
                  con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level4[0].reff], (err, level5) => {
                    if (err) throw err;
                    if (level5[0].reff == '') {
                      con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`, `level_5`) VALUES (?,?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff, level4[0].reff]);
                    } else {
                      con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level5[0].reff], (err, level6) => {
                        if (err) throw err;
                        if (level6[0].reff == '') {
                          con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`, `level_5`, `lavel_6`) VALUES (?,?,?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff, level4[0].reff, level5[0].reff]);
                        } else {
                          con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level6[0].reff], (err, level7) => {
                            if (err) throw err;
                            if (level7[0].reff == '') {
                              con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`, `level_5`, `lavel_6`, `lavel_7`) VALUES (?,?,?,?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff, level4[0].reff, level5[0].reff, level6[0].reff]);
                            } else {
                              con.query("SELECT IFNULL(ud.`reffer_by`, 0) as reff FROM `user_details` as ud WHERE ud.`reffer_code` = ?", [level7[0].reff], (err, level8) => {
                                if (err) throw err;
                                if (level8[0].reff == '') {
                                  con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`, `level_5`, `lavel_6`, `lavel_7`, `lavel_8`) VALUES (?,?,?,?,?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff, level4[0].reff, level5[0].reff, level6[0].reff, level7[0].reff]);
                                } else {
                                  con.query('INSERT INTO `user_level`(`user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`, `level_5`, `lavel_6`, `lavel_7`, `lavel_8`, `lavel_9`) VALUES (?,?,?,?,?,?,?,?,?,?)', [ba, ab, level1[0].ref, level2[0].reff, level3[0].reff, level4[0].reff, level5[0].reff, level6[0].reff, level7[0].reff, level8[0].reff]);
                                }
                              })
                            }
                          })
                        }
                      })
                    }
                  })
                }
              })
            }
          })
        }
      })
    }
  })
}
function reffer_bonus(ba) {
  let a = 0;
  con.query("SELECT IFNULL(ul.`level_1`,0) as level_1,IFNULL(ul.`level_2`,0) as level_2,IFNULL(ul.`level_3`,0) as level_3,IFNULL(ul.`level_4`,0) as level_4,IFNULL(ul.`level_5`,0) as level_5,IFNULL(ul.`level_6`,0) as level_6,IFNULL(ul.`level_7`,0) as level_7,IFNULL(ul.`level_8`,0) as level_8,IFNULL(ul.`level_9`,0) as level_9 FROM `user_level` as ul WHERE ul.user_reffral = (SELECT ud.`reffer_code` FROM `user_details` as ud WHERE ud.`mobile` = ?);", [ba], (err1, result1) => {
    if (err1) throw err1;
    if (result1) {
      let a = Object.values(result1[0]);
      for (let index = 0; index < a.length; index++) {
        const element = a[index];
        con.query("SELECT COUNT(*) as c FROM `buy_plan` WHERE `user_id` = (select mobile from user_details where reffer_code = ?) and `plan_id` != '1'", [element], (error1, resultt1) => {
          if (error1) { throw error1 }
          if (resultt1[0].c > 0) {
            con.query(`UPDATE user_level as ul SET ul.status${index + 1} = 'Success' WHERE ul.user_reffral = (SELECT reffer_code FROM user_details as ud WHERE ud.mobile = ?)`, [ba]);
            con.query("UPDATE `wallet` SET `winning_wallet` = `winning_wallet` + (SELECT `price` FROM `level` WHERE `name` = ? UNION ALL SELECT 0 FROM DUAL WHERE NOT EXISTS(SELECT`price` FROM`level` WHERE`name` = ?)) WHERE `user_name` = (SELECT `mobile` FROM `user_details` WHERE `reffer_code` = ?)", [index + 1, index + 1, element]);
          } else {

          }
        })
      }
      // if (result1[0].level_1 != 0) {
      //   con.query("SELECT COUNT(*) as c FROM `buy_plan` WHERE `user_id` = (select mobile from user_details where reffer_code = ?) and `plan_id` != '1'", [result1[0].level_1], (error1, resultt1) => {
      //     if (error1) { throw error1 }
      //     if (resultt1[0].c > 0) {
      //       con.query("UPDATE `user_level` as ul SET ul.`status` = 'Success' WHERE ul.`user_reffral` = (SELECT reffer_code FROM `user_details` as ud WHERE ud.`mobile` = ?)", [ba]);
      //       con.query("UPDATE `wallet` SET `winning_wallet` = `winning_wallet` + (SELECT `price` FROM `level` WHERE `name` = ? UNION ALL SELECT 0 FROM DUAL WHERE NOT EXISTS(SELECT`price` FROM`level` WHERE`name` = ?)) WHERE `user_name` = (SELECT `mobile` FROM `user_details` WHERE `reffer_code` = ?)", [1, 1, result1[0].level_1]);
      //     } else {
      //       if (result1[0].level_2 != 0) {
      //         con.query("UPDATE `user_level` as ul SET ul.`status2` = 'Success' WHERE ul.`user_reffral` = (SELECT reffer_code FROM `user_details` as ud WHERE ud.`mobile` = ?)", [ba]);
      //         con.query("UPDATE `wallet` SET `winning_wallet` = `winning_wallet` + (SELECT `price` FROM `level` WHERE `name` = ? UNION ALL SELECT 0 FROM DUAL WHERE NOT EXISTS(SELECT`price` FROM`level` WHERE`name` = ?)) WHERE `user_name` = (SELECT `mobile` FROM `user_details` WHERE `reffer_code` = ?)", [2, 2, result1[0].level_2]);
      //         if (result1[0].level_3 != 0) {
      //           con.query("UPDATE `user_level` as ul SET ul.`status3` = 'Success' WHERE ul.`user_reffral` = (SELECT reffer_code FROM `user_details` as ud WHERE ud.`mobile` = ?)", [ba]);
      //           con.query("UPDATE `wallet` SET `winning_wallet` = `winning_wallet` + (SELECT `price` FROM `level` WHERE `name` = ? UNION ALL SELECT 0 FROM DUAL WHERE NOT EXISTS(SELECT`price` FROM`level` WHERE`name` = ?)) WHERE `user_name` = (SELECT `mobile` FROM `user_details` WHERE `reffer_code` = ?)", [3, 3, result1[0].level_3]);
      //           if (result1[0].level_4 != 0) {
      //             con.query("UPDATE `user_level` as ul SET ul.`status4` = 'Success' WHERE ul.`user_reffral` = (SELECT reffer_code FROM `user_details` as ud WHERE ud.`mobile` = ?)", [ba]);
      //             con.query("UPDATE `wallet` SET `winning_wallet` = `winning_wallet` + (SELECT `price` FROM `level` WHERE `name` = ? UNION ALL SELECT 0 FROM DUAL WHERE NOT EXISTS(SELECT`price` FROM`level` WHERE`name` = ?)) WHERE `user_name` = (SELECT `mobile` FROM `user_details` WHERE `reffer_code` = ?)", [4, 4, result1[0].level_4]);
      //             if (result1[0].level_5 != 0) {
      //               con.query("UPDATE `user_level` as ul SET ul.`status5` = 'Success' WHERE ul.`user_reffral` = (SELECT reffer_code FROM `user_details` as ud WHERE ud.`mobile` = ?)", [ba]);
      //               con.query("UPDATE `wallet` SET `winning_wallet` = `winning_wallet` + (SELECT `price` FROM `level` WHERE `name` = ? UNION ALL SELECT 0 FROM DUAL WHERE NOT EXISTS(SELECT`price` FROM`level` WHERE`name` = ?)) WHERE `user_name` = (SELECT `mobile` FROM `user_details` WHERE `reffer_code` = ?)", [5, 5, result1[0].level_5]);
      //               if (result1[0].level_6 != 0) {
      //                 con.query("UPDATE `user_level` as ul SET ul.`status6` = 'Success' WHERE ul.`user_reffral` = (SELECT reffer_code FROM `user_details` as ud WHERE ud.`mobile` = ?)", [ba]);
      //                 con.query("UPDATE `wallet` SET `winning_wallet` = `winning_wallet` + (SELECT `price` FROM `level` WHERE `name` = ? UNION ALL SELECT 0 FROM DUAL WHERE NOT EXISTS(SELECT`price` FROM`level` WHERE`name` = ?)) WHERE `user_name` = (SELECT `mobile` FROM `user_details` WHERE `reffer_code` = ?)", [6, 6, result1[0].level_6]);
      //                 if (result1[0].level_7 != 0) {
      //                   con.query("UPDATE `user_level` as ul SET ul.`status7` = 'Success' WHERE ul.`user_reffral` = (SELECT reffer_code FROM `user_details` as ud WHERE ud.`mobile` = ?)", [ba]);
      //                   con.query("UPDATE `wallet` SET `winning_wallet` = `winning_wallet` + (SELECT `price` FROM `level` WHERE `name` = ? UNION ALL SELECT 0 FROM DUAL WHERE NOT EXISTS(SELECT`price` FROM`level` WHERE`name` = ?)) WHERE `user_name` = (SELECT `mobile` FROM `user_details` WHERE `reffer_code` = ?)", [7, 7, result1[0].level_7]);
      //                   if (result1[0].level_8 != 0) {
      //                     con.query("UPDATE `user_level` as ul SET ul.`status8` = 'Success' WHERE ul.`user_reffral` = (SELECT reffer_code FROM `user_details` as ud WHERE ud.`mobile` = ?)", [ba]);
      //                     con.query("UPDATE `wallet` SET `winning_wallet` = `winning_wallet` + (SELECT `price` FROM `level` WHERE `name` = ? UNION ALL SELECT 0 FROM DUAL WHERE NOT EXISTS(SELECT`price` FROM`level` WHERE`name` = ?)) WHERE `user_name` = (SELECT `mobile` FROM `user_details` WHERE `reffer_code` = ?)", [8, 8, result1[0].level_8]);
      //                     if (result1[0].level_9 != 0) {
      //                       con.query("UPDATE `user_level` as ul SET ul.`status9` = 'Success' WHERE ul.`user_reffral` = (SELECT reffer_code FROM `user_details` as ud WHERE ud.`mobile` = ?)", [ba]);
      //                       con.query("UPDATE `wallet` SET `winning_wallet` = `winning_wallet` + (SELECT `price` FROM `level` WHERE `name` = ? UNION ALL SELECT 0 FROM DUAL WHERE NOT EXISTS(SELECT`price` FROM`level` WHERE`name` = ?)) WHERE `user_name` = (SELECT `mobile` FROM `user_details` WHERE `reffer_code` = ?)", [9, 9, result1[0].level_9]);
      //                     }
      //                   }
      //                 }
      //               }
      //             }
      //           }
      //         }
      //       }
      //     }
      //   })
      // }
    }
  })
}
const queryAsync = (sql, params) => {
  return new Promise((resolve, reject) => {
    con.query(sql, params, (err, results) => {
      if (err) {
        reject(err);
      } else {
        resolve(results);
      }
    });
  });
};

module.exports = app;