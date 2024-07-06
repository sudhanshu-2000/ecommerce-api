const express = require("express");
const app = express.Router();
exports.app = app;
const con = require("../db/conn");
var jwt = require("jsonwebtoken");
const cors = require("cors");
app.use(cors());
require("dotenv").config();
SECRET_KEY_USER = ':3.*1>.<2e_1>&b:5.9x_d,86ac3b:-5%1$%?0$*c>4e7,6aa<e?3.8:<8%28<801?0c66d885!?%6@d:_2a_07-1!+c?+%@4$.?>c<d&?<a$b5:*^b9&-&70d-3&@<&&4^e?99$@:1<fdd@9?bc,-?5*d4e_1f6?%,.5c08c6b_1_^,%1.7:4<,341,d%9d-3e4%d6-9.-:f@+$bc5&!-@24e^7cac*+ee:@4>8-+@0!8*&0f<8<.$^&$b43f!d<-$@d3<+a5c_&19^4a2^_?c0d:_6c1+d*_a_:6:3c43.41^2:59ae%b_e&^-d4a$*4b8c+<0@!1a%59.<e3_:68-_e8+4%d!4-360$5%1@+&0!^?d6fcf,?_.8..-f62-+<,_!bf&>a+?f2*0c61!-^7__1448c:60*^?_!9&:1b7>d^@2fa78^2%44*--d.86a<b<8d681^bb5*396&dd_6.^.^$d2:!!<,8@5&^&+*32506658>!_fd8.04@&*5%-.6^4>e99_0ce*@f6$*-d?d4<5?*cd7-26a%&,!4%4904,a!4*12_+93c&+^$24ad_8974d-!.0a$:<:>9&7@&+.a!?0_%*<-69@a07-^_5ce.&cb>32a626,>@,6_6!:5+:2c_7<bc34%8-3^_4<,5%1-@7a,^>>0:+0:2&a^_^9_.b>::^&f+d+@?ded9d7,dc5?3:@1-??7@c0**47-a2c4b:%f&5-!>e_<95d<7.ff--_a-9b&ac:?,6332f!5_>>f>6c@1!:<<__:>0>.^>c@$935?+&--&->$f%23<fa4<44^,>c8-_@a@bd*:e7838*c!>b>,!9%b52!*<*?029.9-44%9@70!^.5bc%b&d4bb$@6&9@8!69+*4$,96<4816c&8+0e4a372e,<47+%5_^bbce-3^409-0f%44!:2e@5+-f3,8_d.de3d_7&a72:,*5-!-c255!&^.1@&:0e&$2!5c9+*e-+fd*+@6%7&0<>-0%c$d^4!-';
SECRET_KEY_VERIFY = ':3.*1>.<2e_1>&b:5.9x_d,86ac3b:-5%1$%?0$*c>4e7,6aa<e?3.6d885!?%6@d:_2a_07-1!+c?+%@4$.?>c<d&?<a$b5:*^b9&-&wetfghjdskf3&@<&&4^e?99$@:1<fdd@9?bc,-?5*d4e_1f6?%,.5c08c6b_1_^,%1.7:4<,341,d%9d-3e4%d6-9.-:f@+$bc5&!-@24e^7cac*+ee:@4>8-+@0!8*&0f<8<.$^&$b43f!d<-$@d3<+a5c_&19^4a2^_?c0d:_6c1+d*_a_:6:3c43.41^2:59ae%b_e&^-d4a$*4b8c+<0@!1a%59.<e3_:68-_e8+4%d!4-360$5%1@+&0!^?d6fcf,?_.8..-f62-+<,_!bf&>a+?f2*0c61!-^7__1448c:60*^?_!9&:1b7>d^@2fa78^2%44*--d.86a<b<8d681^bb5*396&dd_6.^.^$d2:!!<,8@5&^&+*32506658>!_fd8.04@&*5%-.6^4>e99_0ce*@f6$*-d?d4<5?*cd7-26a%&,!4%4904,a!4*12_+93c&+^$24ad_8974d-!.0a$:<:>9&7@&+.a!?0_%*<-69@a07-^_5ce.&cb>32a626,>@,6_6!:5+:2c_7<bc34%8-3^_4<,5%1-@7a,^>>0:+0:2&a^_^9_.b>::^&f+d+@?ded9d7,dc5?3:@1-??7@c0**47-a2c4b:%f&5-!>e_<95d<7.ff--_a-9b&ac:?,6332f!5_>>f>6c@1!:<<__:>0>.^>c@$935?+&--&->$f%23<fa4<44^,>c8-_@a@bd*:e7838*c!>b>,!9%b52!*<*?029.9-44%9@70!^.5bc%b&d4bb$@6&9@8!69+*4$,96<4816c&8+0e4a372e,<47+%5_^bbce-3^409-0f%44!:2e@5+-f3,8_d.de3d_7&a72:,*5-!-c255!&^.1@&:0e&$2!5c9+*e-+fd*+@6%7&0<>-0%c$d^4!-';
const bcrypt = require("bcrypt");
var bodyParser = require("body-parser");
var multer = require("multer");
app.use(bodyParser.json({ limit: "50mb" }));
app.use("/assets", express.static('assets'));
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
const nodemailer = require("nodemailer");
const transporter = nodemailer.createTransport({
  name: "mail.earnkrobharat.com",
  host: "mail.earnkrobharat.com",
  port: 465,
  secure: true,
  auth: {
    user: "otp@earnkrobharat.com",
    pass: "BXk)79NHb6si",
  },
});
app.get('/get', (req, res) => {
  con.query("SELECT * FROM `user_details` WHERE id = ?;", [96], (err, result) => {
    if (err) { throw err; }
    if (result) {
      res.send(result)
    }
  })
});

app.post("/register", async (req, res) => {
  const { email, mobile, password, name, token } = req.body;
  if (typeof name != 'string') {
    return res.status(400).json({
      error: true,
      status: false,
      message: "Name must be a string value",
    });
  }
  if (!email) {
    return res.status(400).json({
      error: true,
      status: false,
      message: "Email is required.",
    });
  }

  if (!mobile) {
    return res.status(400).json({
      error: true,
      status: false,
      message: "Mobile number is required.",
    });
  }

  if (!password) {
    return res.status(400).json({
      error: true,
      status: false,
      message: "Password is required.",
    });
  }

  if (!name) {
    return res.status(400).json({
      error: true,
      status: false,
      message: "Name is required.",
    });
  }

  if (!token) {
    return res.status(400).json({
      error: true,
      status: false,
      message: "Token is required.",
    });
  }
  try {
    jwt.verify(token, SECRET_KEY_VERIFY, async (err, auth) => {
      if (err) {
        res.status(200).json({
          error: true,
          status: false,
          message: "Invalid Token.",
        });
      } else {
        if (auth.email == req.body.email) {
          const emailResult = await queryAsync("SELECT * FROM `user_details` WHERE `email` = ?;", [email]);
          if (emailResult.length > 0) {
            return res.status(302).json({
              error: true,
              status: false,
              message: "Email Id is Already Exist",
            });
          }
          const mobileResult = await queryAsync("SELECT * FROM `user_details` WHERE `mobile` = ?;", [mobile]);
          if (mobileResult.length > 0) {
            return res.status(302).json({
              error: true,
              status: false,
              message: "Mobile Number is Already Exist",
            });
          }
          const idesResult = await queryAsync("SELECT (IFNULL(MAX(uid),100000)) as id FROM user_details");
          const newUid = parseInt(idesResult[0].id) + 1;
          const hash = bcrypt.hashSync(password, bcrypt.genSaltSync(12));
          const insertUserResult = await queryAsync(
            "INSERT INTO `user_details`(`mobile`, `username`, `password`,`email`, `uid`) VALUES (?,?,?,?,?)",
            [mobile, name, hash, email, newUid]
          );
          if (insertUserResult) {
            await queryAsync("INSERT INTO `wallet`(`user_name`, `wallet_balance`) VALUES (?,?)", [mobile, 0]);
            return res.status(200).json({
              error: false,
              status: true,
              message: "Registered Successfully",
            });
          }
        } else {
          res.status(200).json({
            error: true,
            status: false,
            message: "Invalid Token.",
          });
        }
      }
    });
  } catch (err) {
    return res.status(500).json({
      error: true,
      status: false,
      message: "An error occurred during registration",
    });
  }
});
app.post("/login", async (req, res) => {
  try {
    if (typeof req.body.password === "number") {
      return res.status(400).json({
        error: true,
        status: false,
        message: "Password must be a string value",
      });
    }
    const users = await queryAsync("SELECT * FROM user_details WHERE email = ?", [req.body.email]);
    if (users.length > 0) {
      const user = users[0];
      const status = bcrypt.compareSync(req.body.password, user.password);
      if (status) {
        const token = jwt.sign({ username: user.email }, SECRET_KEY_USER, { expiresIn: '1d' });
        await queryAsync("UPDATE user_details SET is_active = 'Y' WHERE email = ?", [req.body.email]);
        res.status(200).json({
          error: false,
          status: true,
          ID: user.uid,
          username: user.username,
          email: user.email,
          message: "Login successfully",
          token,
        });
      } else {
        res.status(404).json({
          error: true,
          status: false,
          message: "Email or password is wrong",
        });
      }
    } else {
      res.status(404).json({
        error: true,
        message: "Email ID does not exist",
      });
    }
  } catch (error) {
    res.status(500).json({
      error: true,
      message: "Internal server error",
    });
  }
});
app.post("/logout", async (req, res) => {
  try {
    const result = await queryAsync(
      "UPDATE `user_details` SET `is_active` = 'N' WHERE `email` = ?",
      [req.body.email]
    );
    if (result && result.affectedRows > 0) {
      res.status(200).json({ error: false, status: true });
    } else {
      res.status(200).json({ error: false, status: false });
    }
  } catch (error) {
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
    const mobileResult = await queryAsync("SELECT * FROM `user_details` WHERE `mobile` = ?;", [req.body.mobile]);
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
    res.status(500).json({
      error: true,
      status: false,
      message: "Internal Server Error",
    });
  }
});
app.post("/change-password", verifyToken, async (req, res) => {
  try {
    const result = await queryAsync("select * from user_details where `email` = ?", [req.body.email]);
    if (result) {
      const status = bcrypt.compareSync(
        req.body.password,
        result[0].password
      );
      if (status == true) {
        const hash = bcrypt.hashSync(
          req.body.new_password,
          bcrypt.genSaltSync(12)
        );
        const updateResult = await queryAsync("UPDATE `user_details` SET `password` = ? WHERE `email` = ?", [hash, req.body.email]);
        if (updateResult) {
          res.status(200).json({
            error: false,
            status: true,
            message: "Reset Password Successfully",
          });
        }
      } else {
        res.status(200).json({
          error: true,
          message: "Password is Wrong",
        });
      }
    }
  } catch (err) {
    res.status(500).json({
      error: true,
      message: "Internal Server Error"
    });
  }
});
app.post("/forget-password", async (req, res) => {
  if (!req.body.email) {
    return res.status(400).json({
      error: true,
      status: false,
      message: "Email is required.",
    });
  }
  if (!req.body.token) {
    return res.status(400).json({
      error: true,
      status: false,
      message: "Token is required.",
    });
  }
  try {
    jwt.verify(req.body.token, SECRET_KEY_VERIFY, async (err, auth) => {
      if (err) {
        res.status(200).json({
          error: true,
          status: false,
          message: "Invalid Details.",
        });
      } else {
        if (auth.email == req.body.email) {
          const result = await queryAsync("select * from user_details where `email` = ?", [req.body.email])
          if (result.length > 0) {
            const hash = bcrypt.hashSync(
              req.body.password,
              bcrypt.genSaltSync(12)
            );
            const updateResult = await queryAsync("UPDATE `user_details` SET `password` = ? WHERE `email` = ?", [hash, req.body.email]);
            if (updateResult) {
              res.status(200).json({
                error: false,
                status: true,
                message: "Forget Password Successfully",
              });
            }
          } else {
            res.status(200).json({
              error: true,
              message: "Email Id is Not Exist.",
            });
          }
        } else {
          res.status(200).json({
            error: true,
            status: false,
            message: "Invalid Details.",
          });
        }
      }
    });
  } catch (err) {
    res.status(500).json({
      error: true,
      message: "Internal Server Error"
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
      if (JSON.parse(getaddress[0].address).length == 0) {
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
        const maxId = array.reduce((max, obj) => (obj.id > max ? obj.id : max), array[0].id);
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
    res.status(500).json({
      error: true,
      status: false,
      message: "Internal Server Error",
    });
  }
});
app.post("/wallet-balance", verifyToken, async (req, res) => {
  try {
    const result = await queryAsync("SELECT * FROM `wallet` WHERE user_name = ?", [req.body.mobile]);
    res.status(200).json({
      error: false,
      status: "Success",
      data: result
    });
  } catch (err) {
    res.status(500).json({
      error: true,
      status: "Error",
      message: err.message
    });
  }
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
    res.status(500).json({ error: true, message: "Internal Server Error" });
  }
});

app.post("/get-otp", async (req, res) => {
  try {
    const val = Math.floor(1000 + Math.random() * 9000);
    const hash = bcrypt.hashSync(val.toString(), bcrypt.genSaltSync(12));
    const result = await queryAsync("SELECT * FROM `otp` WHERE `number` = ?", [req.body.email]);
    const sendOTPEmail = async () => {
      await transporter.sendMail({
        from: 'otp@earnkrobharat.com',
        to: req.body.email,
        subject: "OTP Verification",
        text: "To Create your Account",
        html: `Your OTP is <b>${val.toString()}</b>, valid for 10 min`,
      });
    };
    if (result.length > 0) {
      await sendOTPEmail();
      const op = await queryAsync("UPDATE `otp` SET `otp` = ? WHERE `number` = ?", [hash, req.body.email]);
      if (op) {
        res.status(200).json({
          error: false,
          status: true,
        });
      }
    } else {
      await sendOTPEmail();
      const ana = await queryAsync("INSERT INTO `otp`(`otp`, `number`) VALUES (?,?)", [hash, req.body.email]);
      if (ana) {
        res.status(200).json({
          error: false,
          status: true,
        });
      }
    }
  } catch (error) {
    res.status(500).json({ error: true, status: false, message: 'Internal Server Error' });
  }
});

app.post("/verify-otp", async (req, res) => {
  try {
    const result = await queryAsync("SELECT * FROM `otp` WHERE number = ?", [req.body.email]);
    if (result.length > 0) {
      const match = bcrypt.compareSync(req.body.otp.toString(), result[0].otp);
      if (match) {
        await queryAsync("DELETE FROM `otp` WHERE number = ?", [req.body.email]);
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
    return res.status(500).json({
      error: true,
      status: false,
      msg: "Internal Server Error",
    });
  }
});

app.post("/get-product", async (req, res) => {
  try {
    let arr = [];
    const completearr = [];
    const result = await queryAsync("SELECT `id`,`name`,`tags`,(select c.name from `category` as c WHERE c.id = `category_id`) as 'category',`category_id` as 'cat_id',(select sc.name from `sub_category` as sc WHERE sc.id = `sub_category_id`) as 'sub_category',`sub_category_id` as 'sub_cat_id',`colorDetails`,`date` FROM `product`");
    result.forEach(item => {
      item.colorDetails = JSON.parse(item.colorDetails);
      item.tags = JSON.parse(item.tags);
      item.colorDetails.forEach(detail => {
        detail.image_url = JSON.parse(detail.image_url);
        detail.sizeDetails = JSON.parse(detail.sizeDetails);
      });
    });
    for (let i = 0; i < result.length; i++) {
      const w = result[i];
      for (let index = 0; index < w.colorDetails.length; index++) {
        const a = w.colorDetails[index];
        arr.push({
          id: w.id,
          name: w.name,
          color: a.color,
          image_url: a.image_url,
          gender: a.gender,
          promoted: a.promoted,
          top_selling: a.top_selling,
          shipping_note: a.shipping_note,
          sizeDetails: a.sizeDetails,
          extra_info: a.extra_info,
          description: a.description
        })
      }
      const rating = await queryAsync("SELECT pr.`rating`,(SELECT ud.`username` FROM `user_details` as ud WHERE ud.`id`=pr.user_id) as user,pr.`review` FROM `product_ratings` as pr WHERE pr.`product_id` = ?", [w.id]);
      completearr.push({
        id: w.id,
        name: w.name,
        category: w.category,
        cat_id: w.cat_id,
        rating: rating,
        sub_category: w.sub_category,
        sub_cat_id: w.sub_cat_id,
        colorDetails: arr,
        tags: w.tags,
        date: w.date
      })
      arr = [];
    }
    res.status(200).json({
      error: false,
      status: true,
      path: "assets/img",
      data: completearr
    })
  } catch (err) {
    res.status(500).json({
      error: true,
      message: "Internal server error"
    });
  }
});
// app.post("/get-product-id", async (req, res) => {
//   try {
//     let arr = [];
//     let sizedd = [];
//     const completearr = [];
//     const result = await queryAsync("SELECT `id`,`name`,(select c.name from `category` as c WHERE c.id = `category_id`) as 'category',`category_id` as 'cat_id',(select sc.name from `sub_category` as sc WHERE sc.id = `sub_category_id`) as 'sub_category',`sub_category_id` as 'sub_cat_id',`colorDetails`,`date` FROM `product` where `id` = ?", req.body.id);
//     const transformedData = result.map(product => {
//       const colorDetails = JSON.parse(product.colorDetails).map(detail => ({
//         ...detail,
//         image_url: JSON.parse(detail.image_url),
//         sizeDetails: JSON.parse(detail.sizeDetails)
//       }));
//       return {
//         ...product,
//         colorDetails
//       };
//     });
//     for (let i = 0; i < transformedData.length; i++) {
//       const w = transformedData[i];
//       for (let index = 0; index < w.colorDetails.length; index++) {
//         const a = w.colorDetails[index];
//         for (let i2 = 0; i2 < a.sizeDetails.length; i2++) {
//           const elems = a.sizeDetails[i2];
//           if (elems.size == 'M' || elems.size == '500 gm' || elems.size == '6/128' || elems.size == '10' || elems.size == '8/128' || elems.size == 'XL' || elems.size == 'S') {
//             sizedd.push({
//               size: elems.size,
//               regular_price: elems.regular_price,
//               quantity: elems.quantity,
//               discount_price: elems.discount_price,
//               percent_off: elems.percent_off,
//               count: true
//             })
//           } else {
//             sizedd.push({
//               size: elems.size,
//               regular_price: elems.regular_price,
//               quantity: elems.quantity,
//               discount_price: elems.discount_price,
//               percent_off: elems.percent_off,
//               count: false
//             })
//           }
//         }
//         arr.push({
//           id: w.id,
//           name: w.name,
//           color: a.color,
//           image_url: a.image_url,
//           gender: a.gender,
//           promoted: a.promoted,
//           top_selling: a.top_selling,
//           shipping_note: a.shipping_note,
//           sizeDetails: sizedd,
//           extra_info: a.extra_info,
//           description: a.description
//         })
//         sizedd = [];
//       }
//       const rating = await queryAsync("SELECT `rating`,`review` FROM `product_ratings` WHERE `product_id` = ?", [w.id]);
//       completearr.push({
//         id: w.id,
//         name: w.name,
//         category: w.category,
//         cat_id: w.cat_id,
//         rating: rating,
//         sub_category: w.sub_category,
//         sub_cat_id: w.sub_cat_id,
//         colorDetails: arr,
//         date: w.date
//       })
//       arr = [];
//     }
//     res.status(200).json({
//       error: false,
//       status: true,
//       path: "assets/img",
//       data: completearr
//     })
//   } catch (err) {
//     res.status(500).json({
//       error: true,
//       message: "Internal server error"
//     });
//   }
// });
app.post("/get-product-id", async (req, res) => {
  try {
    let arr = [];
    const completearr = [];
    const result = await queryAsync("SELECT `id`,`tags`,`name`,(select c.name from `category` as c WHERE c.id = `category_id`) as 'category',`category_id` as 'cat_id',(select sc.name from `sub_category` as sc WHERE sc.id = `sub_category_id`) as 'sub_category',`sub_category_id` as 'sub_cat_id',`colorDetails`,`date` FROM `product` where `id` = ?", req.body.id);
    const transformedData = result.map(product => {
      const colorDetails = JSON.parse(product.colorDetails).map(detail => ({
        ...detail,
        image_url: JSON.parse(detail.image_url),
        sizeDetails: JSON.parse(detail.sizeDetails)
      }));
      const tags = JSON.parse(product.tags);
      return {
        ...product,
        colorDetails,
        tags
      };
    });
    for (let i = 0; i < transformedData.length; i++) {
      const w = transformedData[i];
      for (let index = 0; index < w.colorDetails.length; index++) {
        const a = w.colorDetails[index];
        arr.push({
          id: w.id,
          name: w.name,
          color: a.color,
          image_url: a.image_url,
          gender: a.gender,
          promoted: a.promoted,
          top_selling: a.top_selling,
          shipping_note: a.shipping_note,
          sizeDetails: a.sizeDetails,
          extra_info: a.extra_info,
          description: a.description
        })
      }
      const rating = await queryAsync("SELECT pr.`rating`,(SELECT ud.`username` FROM `user_details` as ud WHERE ud.`id`=pr.user_id) as user,pr.`review` FROM `product_ratings` as pr WHERE pr.`product_id` = ?", [w.id]);
      completearr.push({
        id: w.id,
        name: w.name,
        category: w.category,
        cat_id: w.cat_id,
        rating: rating,
        sub_category: w.sub_category,
        sub_cat_id: w.sub_cat_id,
        colorDetails: arr,
        tags: w.tags,
        date: w.date
      })
      arr = [];
    }
    res.status(200).json({
      error: false,
      status: true,
      path: "assets/img",
      data: completearr
    })
  } catch (err) {
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
    res.status(500).json({
      error: true,
      message: "Internal server error"
    });
  }
});

app.post('/get-current-offer', verifyToken, async (req, res) => {
  try {
    const getOffer = async (coupon, offset) => {
      const couponCount = await queryAsync(
        "SELECT COUNT(`coupan`) AS count FROM `deposit` WHERE `user_name` = ? AND `coupan` = ? AND (`status` = 'Success' OR `status` = 'Pending')",
        [req.body.mobile, coupon]
      );
      if (couponCount[0].count === 0) {
        const result = await queryAsync(
          "SELECT * FROM `payment_bonus` WHERE `status` = 'Y' ORDER BY id ASC LIMIT 1 OFFSET ?",
          [offset]
        );
        return result;
      }
      return null;
    };
    let result = null;
    result = await getOffer('First', 0);
    if (result) {
      return res.status(200).json({ error: false, status: true, data: result });
    }
    result = await getOffer('SECOND', 1);
    if (result) {
      return res.status(200).json({ error: false, status: true, data: result });
    }
    result = await getOffer('THIRD', 2);
    if (result) {
      return res.status(200).json({ error: false, status: true, data: result });
    }
    result = await getOffer('FOURTH', 3);
    if (result) {
      return res.status(200).json({ error: false, status: true, data: result });
    }
    result = await getOffer('FIFTH', 4);
    if (result) {
      return res.status(200).json({ error: false, status: true, data: result });
    }
    const otherResults = await queryAsync(
      "SELECT * FROM `payment_bonus` WHERE `status` = 'Y' ORDER BY id ASC LIMIT 100 OFFSET 5"
    );
    res.status(200).json({ error: false, status: true, data: otherResults });
  } catch (err) {
    res.status(500).json({ error: true, status: false, message: "Internal server error" });
  }
});
app.post('/check-coupon-code', verifyToken, async (req, res) => {
  try {
    const results = await queryAsync("SELECT * FROM `payment_bonus` WHERE `offer_name` = ? AND `status` = 'Y'", [req.body.code]);
    if (results.length > 0) {
      if (parseInt(req.body.balance) >= parseInt(results[0].amount_start) && parseInt(req.body.balance) <= parseInt(results[0].amount_end)) {
        res.status(200).json({ error: false, status: true, message: "Apply Successfully" });
      } else {
        res.status(200).json({ error: true, status: false, message: "Invalid Coupon Code" });
      }
    } else {
      res.status(200).json({ error: true, status: false, message: "Invalid Coupon Code" });
    }
  } catch (error) {
    res.status(500).json({ error: true, status: false, message: "Internal Server Error" });
  }
});
app.post("/add-cart", async (req, res) => {
  try {
    let arrayadd = [];
    let sizeadd = [];
    let add_order = [];
    let add_product = [];
    let size_product = [];
    let add_id_price = [];
    const a = req.body;
    const assas = await queryAsync("SELECT * FROM `add_to_cart` WHERE `color` = ? and `size` = ? and `product_id` = ? and user_id=(select ud.id from user_details as ud where ud.email = ?)", [a.color, a.size, a.product_id, a.email]);
    if (assas.length > 0) {
      res.status(302).json({
        error: true,
        status: false,
        message: 'This Product is Already Added!'
      });
    } else {
      const product = await queryAsync("SELECT `id`,`tags`,`name`,(select c.name from `category` as c WHERE c.id = `category_id`) as 'category',`category_id`,(select sc.name from `sub_category` as sc WHERE sc.id = `sub_category_id`) as 'sub_category',`sub_category_id`,`colorDetails`,`date` FROM `product` WHERE `id` = ?", [a.product_id]);
      if (product.length == 0) {
        return res.status(404).json({ error: true, status: false, message: "Product not Found!" });
      }
      product.forEach(item => {
        item.colorDetails = JSON.parse(item.colorDetails);
        item.tags = JSON.parse(item.tags);
        item.colorDetails.forEach(detail => {
          detail.image_url = JSON.parse(detail.image_url);
          detail.sizeDetails = JSON.parse(detail.sizeDetails);
        });
      });
      const exists = add_product.find(obj => obj.id == a.product_id);
      if (exists) {
        const error = updateQuantity(exists, a.color, a.size);
        if (error) return res.status(error.status).json({ error: true, status: false, message: error.message });
      } else {
        for (let i = 0; i < product[0].colorDetails.length; i++) {
          const j = product[0].colorDetails[i];
          if (a.color == j.color) {
            for (let k = 0; k < j.sizeDetails.length; k++) {
              const l = j.sizeDetails[k];
              if (a.size == l.size) {
                add_id_price.push({ price: l.regular_price, id: product[0].id });
                sizeadd.push({
                  size: a.size,
                  regular_price: parseInt(l.regular_price),
                  discount_price: parseInt(l.discount_price),
                  percent_off: parseInt(l.percent_off),
                  quantity: l.quantity,
                  count: true
                });
                size_product.push({
                  size: a.size,
                  regular_price: parseInt(l.regular_price),
                  discount_price: parseInt(l.discount_price),
                  percent_off: parseInt(l.percent_off),
                  quantity: l.quantity,
                  count: true
                });
              } else {
                size_product.push({
                  size: l.size,
                  regular_price: parseInt(l.regular_price),
                  discount_price: parseInt(l.discount_price),
                  percent_off: parseInt(l.percent_off),
                  quantity: l.quantity,
                  count: l.count
                });
              }
              if ((j.sizeDetails.length - 1) == k) {
                add_order.push({
                  color: j.color,
                  image_url: j.image_url,
                  gender: j.gender,
                  promoted: j.promoted,
                  top_selling: j.top_selling,
                  shipping_note: j.shipping_note,
                  sizeDetails: sizeadd,
                  extra_info: j.extra_info,
                  description: j.description
                });
                sizeadd = [];
                arrayadd.push({
                  color: j.color,
                  image_url: j.image_url,
                  gender: j.gender,
                  promoted: j.promoted,
                  top_selling: j.top_selling,
                  shipping_note: j.shipping_note,
                  sizeDetails: size_product,
                  extra_info: j.extra_info,
                  description: j.description
                });
                size_product = [];
              }
            }
          } else {
            arrayadd.push(j);
          }
          if ((product[0].colorDetails.length - 1) == i) {
            add_product.push({
              id: product[0].id,
              name: product[0].name,
              category: product[0].category,
              cat_id: product[0].category_id,
              sub_category: product[0].sub_category,
              sub_cat_id: product[0].sub_category_id,
              colorDetails: arrayadd,
              tags: product[0].tags,
              date: product[0].date,
            });
            arrayadd = [];
          }
        }
      }
      add_product.forEach(item => {
        item.colorDetails.forEach(detail => {
          detail.image_url = JSON.stringify(detail.image_url);
          detail.sizeDetails = JSON.stringify(detail.sizeDetails);
        });
        item.colorDetails = JSON.stringify(item.colorDetails);
        item.tags = JSON.stringify(item.tags);
      });
      add_order.forEach(item => {
        item.image_url = JSON.stringify(item.image_url);
        item.sizeDetails = JSON.stringify(item.sizeDetails);
      });
      for (let pk = 0; pk < add_product.length; pk++) {
        const pk1 = add_product[pk];
        await queryAsync("UPDATE `product` SET `colorDetails`=? WHERE `id`=?", [pk1.colorDetails, pk1.id]);
        if ((add_product.length - 1) == pk) {
          const result = await queryAsync("INSERT INTO `add_to_cart`(`user_id`, `color`, `size`, `product_id`) VALUES ((SELECT `id` FROM `user_details` WHERE `email`=?),?,?,?)",
            [req.body.email, req.body.color, req.body.size, req.body.product_id]);
          if (result) {
            res.status(200).json({ error: false, status: true, message: "Add Cart Successfully" });
          }
        }
      }
    }
  } catch (error) {
    if (!res.headersSent) {
      res.status(500).json({
        error: true,
        status: false,
        message: 'Internal Server Error'
      });
    }
  }
  function updateQuantity(product, color, size) {
    const colorDetail = product.colorDetails.find(cd => cd.color == color);
    if (!colorDetail) {
      return { status: 400, message: `Color ${color} not found` };
    }

    const sizeDetail = colorDetail.sizeDetails.find(sd => sd.size == size);
    if (!sizeDetail) {
      return { status: 400, message: `Size ${size} not found` };
    }

    return null;
  }
});
app.post('/get-cart', async (req, res) => {
  try {
    let array = [];
    const result = await queryAsync(
      "SELECT atc.id as cart_id,atc.user_id,atc.color,atc.count,atc.size,atc.product_id,p.name,p.category_id,p.sub_category_id,p.colorDetails,atc.date FROM `add_to_cart` as atc INNER join product as p on atc.product_id = p.id WHERE `user_id`=(SELECT id FROM `user_details` WHERE `email`=?)",
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
                  "count": element.count,
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
app.post("/update-cart-item", async (req, res) => {
  try {
    if (req.body.count > 0) {
      res.status(400).json({ error: true, status: false, message: "Count is not less then 0" });
    }
    const check = await queryAsync('SELECT * FROM `add_to_cart` WHERE `id` = ?', [req.body.id]);
    if (check.length > 0) {
      const result = await queryAsync("UPDATE `add_to_cart` SET `count`=? WHERE `id` = ?", [req.body.count, req.body.id]);
      if (result) {
        res.status(200).json({ error: false, status: true });
      }
    } else {
      res.status(400).json({ error: true, status: false, message: "Cart Id not Found" });
    }
  } catch (err) {
    res.status(500).json({ error: true, message: "Internal Server Error" });
  }
});
app.post("/remove-cart", async (req, res) => {
  try {
    let arrayadd = [];
    let sizeadd = [];
    let add_order = [];
    let add_product = [];
    let size_product = [];
    let add_id_price = [];
    const check = await queryAsync('SELECT * FROM add_to_cart WHERE id = ? and user_id = (SELECT ud.id FROM `user_details` as ud WHERE ud.`email` = ?)', [req.body.id, req.body.email]);
    if (check.length > 0) {
      const a = { product_id: check[0].product_id, size: check[0].size, color: check[0].color };
      const product = await queryAsync("SELECT `id`,`name`,`tags`,(select c.name from `category` as c WHERE c.id = `category_id`) as 'category',`category_id`,(select sc.name from `sub_category` as sc WHERE sc.id = `sub_category_id`) as 'sub_category',`sub_category_id`,`colorDetails`,`date` FROM `product` WHERE `id` = ?", [a.product_id]);
      if (product.length == 0) {
        return res.status(404).json({ error: true, status: false, message: "Product not Found!" });
      }
      product.forEach(item => {
        item.colorDetails = JSON.parse(item.colorDetails);
        item.tags = JSON.parse(item.tags);
        item.colorDetails.forEach(detail => {
          detail.image_url = JSON.parse(detail.image_url);
          detail.sizeDetails = JSON.parse(detail.sizeDetails);
        });
      });
      const exists = add_product.find(obj => obj.id == a.product_id);
      if (exists) {
        const error = updateQuantity(exists, a.color, a.size);
        if (error) return res.status(error.status).json({ error: true, status: false, message: error.message });
      } else {
        for (let i = 0; i < product[0].colorDetails.length; i++) {
          const j = product[0].colorDetails[i];
          if (a.color == j.color) {
            for (let k = 0; k < j.sizeDetails.length; k++) {
              const l = j.sizeDetails[k];
              if (a.size == l.size) {
                add_id_price.push({ price: l.regular_price, id: product[0].id });
                sizeadd.push({
                  size: a.size,
                  regular_price: parseInt(l.regular_price),
                  discount_price: parseInt(l.discount_price),
                  percent_off: parseInt(l.percent_off),
                  count: false
                });
                size_product.push({
                  size: a.size,
                  regular_price: parseInt(l.regular_price),
                  discount_price: parseInt(l.discount_price),
                  percent_off: parseInt(l.percent_off),
                  count: false
                });
              } else {
                size_product.push({
                  size: l.size,
                  regular_price: parseInt(l.regular_price),
                  discount_price: parseInt(l.discount_price),
                  percent_off: parseInt(l.percent_off),
                  count: l.count
                });
              }
              if ((j.sizeDetails.length - 1) == k) {
                add_order.push({
                  color: j.color,
                  image_url: j.image_url,
                  gender: j.gender,
                  promoted: j.promoted,
                  top_selling: j.top_selling,
                  shipping_note: j.shipping_note,
                  sizeDetails: sizeadd,
                  extra_info: j.extra_info,
                  description: j.description
                });
                sizeadd = [];
                arrayadd.push({
                  color: j.color,
                  image_url: j.image_url,
                  gender: j.gender,
                  promoted: j.promoted,
                  top_selling: j.top_selling,
                  shipping_note: j.shipping_note,
                  sizeDetails: size_product,
                  extra_info: j.extra_info,
                  description: j.description
                });
                size_product = [];
              }
            }
          } else {
            arrayadd.push(j);
          }
          if ((product[0].colorDetails.length - 1) == i) {
            add_product.push({
              id: product[0].id,
              name: product[0].name,
              category: product[0].category,
              cat_id: product[0].category_id,
              sub_category: product[0].sub_category,
              sub_cat_id: product[0].sub_category_id,
              colorDetails: arrayadd,
              tags: product[0].tags,
              date: product[0].date,
            });
            arrayadd = [];
          }
        }
      }
      add_product.forEach(item => {
        item.colorDetails.forEach(detail => {
          detail.image_url = JSON.stringify(detail.image_url);
          detail.sizeDetails = JSON.stringify(detail.sizeDetails);
        });
        item.colorDetails = JSON.stringify(item.colorDetails);
        item.tags = JSON.stringify(item.tags);
      });
      add_order.forEach(item => {
        item.image_url = JSON.stringify(item.image_url);
        item.sizeDetails = JSON.stringify(item.sizeDetails);
      });
      for (let pk = 0; pk < add_product.length; pk++) {
        const pk1 = add_product[pk];
        await queryAsync("UPDATE `product` SET `colorDetails`=? WHERE `id`=?", [pk1.colorDetails, pk1.id]);
        if ((add_product.length - 1) == pk) {
          const resulte = await queryAsync("DELETE FROM `add_to_cart` WHERE `id`=?", [req.body.id]);
          if (resulte) {
            res.status(200).json({ error: false, status: true });
          }
        }
      }
    } else {
      res.status(400).json({ error: true, status: false, message: "Cart Id not Found" });
    }
  } catch (error) {
    if (!res.headersSent) {
      res.status(500).json({
        error: true,
        status: false,
        message: 'Internal Server Error'
      });
    }
  }
  function updateQuantity(product, color, size) {
    const colorDetail = product.colorDetails.find(cd => cd.color == color);
    if (!colorDetail) {
      return { status: 400, message: `Color ${color} not found` };
    }

    const sizeDetail = colorDetail.sizeDetails.find(sd => sd.size == size);
    if (!sizeDetail) {
      return { status: 400, message: `Size ${size} not found` };
    }

    return null;
  }
});
app.post('/get-cart-by-id', async (req, res) => {
  try {
    let comarray = [];
    let array = [];
    for (let abc = 0; abc < req.body.ids.length; abc++) {
      const ele = req.body.ids[abc];
      const result = await queryAsync("SELECT atc.id as cart_id,atc.user_id,atc.color,atc.count,atc.size,atc.product_id,p.name,p.category_id,p.sub_category_id,p.colorDetails,atc.date FROM `add_to_cart` as atc INNER join product as p on atc.product_id = p.id WHERE atc.`user_id`=(SELECT id FROM `user_details` WHERE `email`=?) and atc.id = ?", [req.body.email, ele]);
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
                    "count": element.count,
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
        comarray.push(array[0]);
        array = [];
      }
      if ((req.body.ids.length - 1) == abc) {
        res.status(200).json({ error: false, status: true, data: comarray });
      }
    }
  } catch (err) {
    res.status(500).json({ error: true, status: false, message: err.message });
  }
});

app.post('/add-wishlist', async (req, res) => {
  try {
    const assas = await queryAsync("SELECT * FROM `add_to_wish` WHERE `color` = ? and `size` = ? and `product_id` = ? and user_id=(select ud.id from user_details as ud where ud.email = ?)", [req.body.color, req.body.size, req.body.product_id, req.body.email]);
    if (assas.length > 0) {
      res.status(302).json({
        error: true,
        status: false,
        message: 'This Wishlist item is Already Added!'
      });
    } else {
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
    const check = await queryAsync('SELECT * FROM add_to_wish WHERE id = ? and user_id = (SELECT id FROM `user_details` WHERE `email` = ?)', [req.body.id, req.body.email]);
    if (check.length > 0) {
      const result = await queryAsync("DELETE FROM `add_to_wish` WHERE `id`=?", [req.body.id]);
      if (result) {
        res.status(200).json({ error: false, status: true });
      }
    } else {
      res.status(400).json({ error: true, status: false, message: "Wishlist Id not Found" });
    }
  } catch (err) {
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
    let arrayadd = [];
    let sizeadd = [];
    let add_order = [];
    let add_product = [];
    let size_product = [];
    let add_id_price = [];

    for (let index = 0; index < req.body.items.length; index++) {
      const a = req.body.items[index];
      const product = await queryAsync("SELECT `id`,`name`,`tags`,(select c.name from `category` as c WHERE c.id = `category_id`) as 'category',`category_id`,(select sc.name from `sub_category` as sc WHERE sc.id = `sub_category_id`) as 'sub_category',`sub_category_id`,`colorDetails`,`date` FROM `product` WHERE `id` = ?", [a.product_id]);
      if (product.length == 0) {
        return res.status(404).json({ error: true, status: false, message: "Product not Found!" });
      }
      product.forEach(item => {
        item.colorDetails = JSON.parse(item.colorDetails);
        item.tags = JSON.parse(item.tags);
        item.colorDetails.forEach(detail => {
          detail.image_url = JSON.parse(detail.image_url);
          detail.sizeDetails = JSON.parse(detail.sizeDetails);
        });
      });
      const exists = add_product.find(obj => obj.id == a.product_id);
      if (exists) {
        const error = updateQuantity(exists, a.color, a.size, a.qty);
        if (error) return res.status(error.status).json({ error: true, status: false, message: error.message });
      } else {
        for (let i = 0; i < product[0].colorDetails.length; i++) {
          const j = product[0].colorDetails[i];
          if (a.color == j.color) {
            for (let k = 0; k < j.sizeDetails.length; k++) {
              const l = j.sizeDetails[k];
              if (a.size == l.size) {
                if (l.quantity >= a.qty) {
                  add_id_price.push({ price: l.regular_price, id: product[0].id });
                  sizeadd.push({
                    size: a.size,
                    regular_price: parseInt(l.regular_price),
                    discount_price: parseInt(l.discount_price),
                    percent_off: parseInt(l.percent_off),
                    quantity: parseInt(l.quantity - a.qty)
                  });
                  size_product.push({
                    size: a.size,
                    regular_price: parseInt(l.regular_price),
                    discount_price: parseInt(l.discount_price),
                    percent_off: parseInt(l.percent_off),
                    quantity: parseInt(l.quantity - a.qty)
                  });
                } else {
                  return res.status(400).json({ error: true, status: false, message: `Size ${a.size} is out of Stock` });
                }
              } else {
                size_product.push(l);
              }
              if ((j.sizeDetails.length - 1) == k) {
                add_order.push({
                  color: j.color,
                  image_url: j.image_url,
                  gender: j.gender,
                  promoted: j.promoted,
                  top_selling: j.top_selling,
                  shipping_note: j.shipping_note,
                  sizeDetails: sizeadd,
                  extra_info: j.extra_info,
                  description: j.description
                });
                sizeadd = [];
                arrayadd.push({
                  color: j.color,
                  image_url: j.image_url,
                  gender: j.gender,
                  promoted: j.promoted,
                  top_selling: j.top_selling,
                  shipping_note: j.shipping_note,
                  sizeDetails: size_product,
                  extra_info: j.extra_info,
                  description: j.description
                });
                size_product = [];
              }
            }
          } else {
            arrayadd.push(j);
          }
          if ((product[0].colorDetails.length - 1) == i) {
            add_product.push({
              id: product[0].id,
              name: product[0].name,
              category: product[0].category,
              cat_id: product[0].category_id,
              sub_category: product[0].sub_category,
              sub_cat_id: product[0].sub_category_id,
              colorDetails: arrayadd,
              tags: product[0].tags,
              date: product[0].date,
            });
            arrayadd = [];
          }
        }
      }
      if ((req.body.items.length - 1) == index) {
        add_product.forEach(item => {
          item.colorDetails.forEach(detail => {
            detail.image_url = JSON.stringify(detail.image_url);
            detail.sizeDetails = JSON.stringify(detail.sizeDetails);
          });
          item.colorDetails = JSON.stringify(item.colorDetails);
          item.tags = JSON.stringify(item.tags);
        });
        add_order.forEach(item => {
          item.image_url = JSON.stringify(item.image_url);
          item.sizeDetails = JSON.stringify(item.sizeDetails);
        });
        for (let pk = 0; pk < add_product.length; pk++) {
          const pk1 = add_product[pk];
          await queryAsync("UPDATE `product` SET `colorDetails`=? WHERE `id`=?", [pk1.colorDetails, pk1.id]);
          if ((add_product.length - 1) == pk) {
            for (let kp = 0; kp < req.body.items.length; kp++) {
              const kp1 = req.body.items[kp];
              await queryAsync("INSERT INTO `order_page`(`user_id`, `product_id`, `size`, `color`, `qty`, `price`, `address`, `payment_type`,`delivery_date`) VALUES ((SELECT ud.`id` from `user_details` as ud where ud.email = ?),?,?,?,?,?,?,?,(NOW() + INTERVAL 7 DAY))", [req.body.email, pk1.id, kp1.size, kp1.color, kp1.qty, add_id_price[kp].price, JSON.stringify(req.body.address), req.body.payment_type]);
              if ((req.body.items.length - 1) == kp) {
                res.status(200).json({ error: false, status: true, massege: "Add Order SuccessFully" })
              }
            }
          }
        }
      }
    }
  } catch (error) {
    if (!res.headersSent) {
      res.status(500).json({
        error: true,
        status: false,
        message: 'Internal Server Error'
      });
    }
  }

  function updateQuantity(product, color, size, newQuantity) {
    const colorDetail = product.colorDetails.find(cd => cd.color == color);
    if (!colorDetail) {
      return { status: 400, message: `Color ${color} not found` };
    }

    const sizeDetail = colorDetail.sizeDetails.find(sd => sd.size == size);
    if (!sizeDetail) {
      return { status: 400, message: `Size ${size} not found` };
    }

    if (newQuantity > sizeDetail.quantity) {
      return { status: 400, message: `Your quantity is (${newQuantity}) and Available quantity is (${sizeDetail.quantity})` };
    }

    sizeDetail.quantity -= newQuantity;
    return null; // No error
  }
});
// app.post("/add-order2", async (req, res) => {
//   try {
//     let arrayadd = [];
//     let sizeadd = [];
//     let add_order = [];
//     let add_product = [];
//     let size_product = [];
//     let add_id_price = [];
//     for (let index = 0; index < req.body.items.length; index++) {
//       const a = req.body.items[index];
//       const product = await queryAsync("SELECT `id`,`name`,(select c.name from `category` as c WHERE c.id = `category_id`) as 'category',`category_id`,(select sc.name from `sub_category` as sc WHERE sc.id = `sub_category_id`) as 'sub_category',`sub_category_id`,`colorDetails`,`date` FROM `product` WHERE `id` = ?", [a.product_id]);
//       if (product.length == 0) {
//         res.status(404).json({ error: true, status: false, message: "Product not Found!" })
//       } else {
//         product.forEach(item => {
//           item.colorDetails = JSON.parse(item.colorDetails);
//           item.colorDetails.forEach(detail => {
//             detail.name = item.name;
//             detail.id = item.id;
//             detail.image_url = JSON.parse(detail.image_url);
//             detail.sizeDetails = JSON.parse(detail.sizeDetails);
//           });
//         });
//         const exists = add_product.find(obj => obj.id == a.product_id);
//         if (exists != undefined) {
//           updateQuantity(exists, a.color, a.size, a.qty);
//           function updateQuantity(product, color, size, newQuantity) {
//             const colorDetail = product.colorDetails.find(cd => cd.color == color);
//             if (!colorDetail) {
//               return res.status(400).json({ error: true, status: false, message: `Color ${color} not found` });
//             }

//             const sizeDetail = colorDetail.sizeDetails.find(sd => sd.size == size);
//             if (!sizeDetail) {
//               return res.status(400).json({ error: true, status: false, message: `Size ${size} not found` });
//             }

//             if (newQuantity > sizeDetail.quantity) {
//               return res.status(400).json({ error: true, status: false, message: `Your quantity is (${newQuantity}) and Available quantity is (${sizeDetail.quantity})` });
//             }

//             sizeDetail.quantity -= newQuantity;
//           }
//           for (let i = 0; i < product[0].colorDetails.length; i++) {
//             const j = product[0].colorDetails[i];
//             if (a.color == j.color) {
//               for (let k = 0; k < j.sizeDetails.length; k++) {
//                 const l = j.sizeDetails[k];
//                 if (a.size == l.size) {
//                   if (l.quantity >= a.qty) {
//                     add_id_price.push({ price: l.regular_price, id: product[0].id });
//                     sizeadd.push({
//                       size: a.size,
//                       regular_price: parseInt(l.regular_price),
//                       discount_price: parseInt(l.discount_price),
//                       percent_off: parseInt(l.percent_off),
//                       quantity: parseInt(l.quantity - a.qty)
//                     })
//                   } else {
//                     res.status(400).json({ error: true, status: false, message: `Size ${a.size} is an out of Stock` });
//                     return;
//                   }
//                 } else {
//                   size_product.push(l);
//                 }
//                 if ((j.sizeDetails.length - 1) == k) {
//                   add_order.push({
//                     id: j.id,
//                     name: j.name,
//                     color: j.color,
//                     image_url: j.image_url,
//                     gender: j.gender,
//                     promoted: j.promoted,
//                     top_selling: j.top_selling,
//                     shipping_note: j.shipping_note,
//                     sizeDetails: sizeadd,
//                     extra_info: j.extra_info,
//                     description: j.description
//                   })
//                   sizeadd = [];
//                 }
//               }
//             } else {
//               arrayadd.push(j);
//             }
//           }
//         } else {
//           for (let i = 0; i < product[0].colorDetails.length; i++) {
//             const j = product[0].colorDetails[i];
//             if (a.color == j.color) {
//               for (let k = 0; k < j.sizeDetails.length; k++) {
//                 const l = j.sizeDetails[k];
//                 if (a.size == l.size) {
//                   if (l.quantity >= a.qty) {
//                     add_id_price.push({ price: l.regular_price, id: product[0].id });
//                     sizeadd.push({
//                       size: a.size,
//                       regular_price: parseInt(l.regular_price),
//                       discount_price: parseInt(l.discount_price),
//                       percent_off: parseInt(l.percent_off),
//                       quantity: parseInt(l.quantity - a.qty)
//                     })
//                     size_product.push({
//                       size: a.size,
//                       regular_price: parseInt(l.regular_price),
//                       discount_price: parseInt(l.discount_price),
//                       percent_off: parseInt(l.percent_off),
//                       quantity: parseInt(l.quantity - a.qty)
//                     })
//                   } else {
//                     res.status(400).json({ error: true, status: false, message: `Size ${a.size} is an out of Stock` });
//                     return;
//                   }
//                 } else {
//                   size_product.push(l);
//                 }
//                 if ((j.sizeDetails.length - 1) == k) {
//                   add_order.push({
//                     id: j.id,
//                     name: j.name,
//                     color: j.color,
//                     image_url: j.image_url,
//                     gender: j.gender,
//                     promoted: j.promoted,
//                     top_selling: j.top_selling,
//                     shipping_note: j.shipping_note,
//                     sizeDetails: sizeadd,
//                     extra_info: j.extra_info,
//                     description: j.description
//                   })
//                   sizeadd = []
//                   arrayadd.push({
//                     id: j.id,
//                     name: j.name,
//                     color: j.color,
//                     image_url: j.image_url,
//                     gender: j.gender,
//                     promoted: j.promoted,
//                     top_selling: j.top_selling,
//                     shipping_note: j.shipping_note,
//                     sizeDetails: size_product,
//                     extra_info: j.extra_info,
//                     description: j.description
//                   });
//                   size_product = [];
//                 }
//               }
//             } else {
//               arrayadd.push(j);
//             }
//             if ((product[0].colorDetails.length - 1) == i) {
//               add_product.push({
//                 id: product[0].id,
//                 name: product[0].name,
//                 category: product[0].category,
//                 cat_id: product[0].category_id,
//                 sub_category: product[0].sub_category,
//                 sub_cat_id: product[0].sub_category_id,
//                 colorDetails: arrayadd,
//                 date: product[0].date,
//               });
//               arrayadd = [];
//             }
//           }
//         }
//       }
//       if ((req.body.items.length - 1) == index) {
//         add_product.forEach(item => {
//           item.colorDetails.forEach(detail => {
//             detail.image_url = JSON.stringify(detail.image_url);
//             detail.sizeDetails = JSON.stringify(detail.sizeDetails);
//           });
//           item.colorDetails = JSON.stringify(item.colorDetails)
//         });
//         add_order.forEach(item => {
//           item.image_url = JSON.stringify(item.image_url);
//           item.sizeDetails = JSON.stringify(item.sizeDetails);
//         });
//         for (let pk = 0; pk < add_product.length; pk++) {
//           const pk1 = add_product[pk];
//           await queryAsync("UPDATE `product` SET `colorDetails`=? WHERE `id`=?", [pk1.colorDetails, pk1.id]);
//           if ((add_product.length - 1) == pk) {
//             for (let kp = 0; kp < req.body.items.length; kp++) {
//               const kp1 = req.body.items[kp];
//               await queryAsync("INSERT INTO `order_page`(`user_id`, `product_id`, `size`, `color`, `qty`, `price`, `address`, `payment_type`,`delivery_date`) VALUES ((SELECT ud.`id` from `user_details` as ud where ud.email = ?),?,?,?,?,?,?,?,(NOW() + INTERVAL 7 DAY))", [req.body.email, add_id_price[kp].id, kp1.size, kp1.color, kp1.qty, add_id_price[kp].price, JSON.stringify(req.body.address), req.body.payment_type]);
//               if ((req.body.items.length - 1) == kp) {
//                 res.status(200).json({ error: false, status: true, message: "Add Ordered SuccessFully" });
//               }
//             }
//           }
//         }
//       }
//     }
//   } catch (error) {
//     res.status(500).json({
//       error: true,
//       status: false,
//       message: 'Internal Server Error'
//     });
//   }
// })
app.post("/get-order", async (req, res) => {
  try {
    let array = [];
    let size = [];
    let completearr = [];
    const result = await queryAsync("SELECT op.id,p.name,p.colorDetails,p.tags,op.size,op.color,op.qty,op.price,op.address, op.payment_type,op.delivery_date,op.status,op.date FROM `order_page` as op INNER join `product` as p on op.product_id = p.id WHERE op.`user_id` = (select udd.`id` from `user_details` as udd where udd.`email` = ? )", [req.body.email]);
    result.forEach(item => {
      item.colorDetails = JSON.parse(item.colorDetails);
      item.tags = JSON.parse(item.tags);
      item.colorDetails.forEach(detail => {
        detail.name = item.name;
        detail.id = item.id;
        detail.image_url = JSON.parse(detail.image_url);
        detail.sizeDetails = JSON.parse(detail.sizeDetails);
      });
      item.address = JSON.parse(item.address);
    });
    for (let j = 0; j < result.length; j++) {
      const j1 = result[j];
      for (let index = 0; index < j1.colorDetails.length; index++) {
        const el = j1.colorDetails[index];
        if (el.color == j1.color) {
          for (let i = 0; i < el.sizeDetails.length; i++) {
            const element = el.sizeDetails[i];
            if (element.size == j1.size) {
              size.push({
                "size": element.size,
                "regular_price": element.regular_price,
                "discount_price": element.discount_price,
                "percent_off": element.percent_off,
                "quantity": element.quantity,
                "count": element.count
              })
              array.push({
                "color": el.color,
                "image_url": el.image_url,
                "gender": el.gender,
                "promoted": el.promoted,
                "top_selling": el.top_selling,
                "shipping_note": el.shipping_note,
                "sizeDetails": size,
                "extra_info": el.extra_info,
                "description": el.description,
                "name": el.name,
                "id": el.id
              })
              size = [];
            }
          }
        }
        if ((j1.colorDetails.length - 1) == index) {
          completearr.push({
            id: j1.id,
            name: j1.name,
            colorDetails: array,
            tags: j1.tags,
            size: j1.size,
            color: j1.color,
            qty: j1.qty,
            price: j1.price,
            address: j1.address,
            payment_type: j1.payment_type,
            delivery_date: j1.delivery_date,
            status: j1.status,
            date: j1.date
          })
          array = [];
        }
      }
    }
    if (result) {
      res.status(200).json({ error: false, status: true, data: completearr });
    }
  } catch (error) {
    res.status(500).json({
      error: true,
      status: false,
      // message: error
      message: 'Internal Server Error'
    });
  }
})
app.get("/get-all", async (req, res) => {
  const product = await queryAsync("SELECT `id`,`name`,(select c.name from `category` as c WHERE c.id = `category_id`) as 'category',`category_id` as 'cat_id',(select sc.name from `sub_category` as sc WHERE sc.id = `sub_category_id`) as 'sub_category',`sub_category_id` as 'sub_cat_id',`colorDetails`,`date` FROM `product` WHERE `id` = ?", [12]);
  if (product.length == 0) {
    res.status(404).json({ error: true, status: false, message: "Product not Found!" })
  } else {
    product.forEach(item => {
      item.colorDetails = JSON.parse(item.colorDetails);
      item.colorDetails.forEach(detail => {
        detail.image_url = JSON.parse(detail.image_url);
        detail.sizeDetails = JSON.parse(detail.sizeDetails);
      });
    });
    res.send(product)
  }
})
app.post("/add-rating", async (req, res) => {
  if (
    !req.body.product_id ||
    !req.body.email ||
    !req.body.rating ||
    !req.body.review
  ) {
    return res.status(400).json({
      error: true,
      status: false,
      message: 'Missing required fields'
    });
  }
  try {
    const check = await queryAsync("select * from product where id = ?", [req.body.product_id]);
    if (check.length == 0) {
      res.status(400).json({
        error: true,
        status: false,
        message: 'Product Not Found!'
      })
    } else {
      const result = await queryAsync(
        "INSERT INTO product_ratings (product_id, user_id, rating, review) VALUES (?, (select ud.id from user_details as ud where ud.email = ?), ?, ?);",
        [req.body.product_id, req.body.email, req.body.rating, req.body.review]
      );
      if (result.affectedRows > 0) {
        return res.status(200).json({
          error: false,
          status: true,
          message: 'Rating added successfully'
        });
      } else {
        return res.status(500).json({
          error: true,
          status: false,
          message: 'Failed to add rating'
        });
      }
    }
  } catch (error) {
    return res.status(500).json({
      error: true,
      status: false,
      message: 'Internal Server Error'
    });
  }
});

app.post("/get-promoted", async (req, res) => {
  try {
    const result = await queryAsync(
      "SELECT ps.id,ps.sub_cat,sc.name,ps.name as promoted_name,ps.status,ps.date FROM `promoted_sub-cat` as ps INNER join sub_category as sc on ps.sub_cat = sc.id where ps.name = 'Sub-Category' and ps.`status`='Y'"
    );
    res.status(200).json({
      error: false,
      status: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      error: true,
      status: false,
      message: error.message
    });
  }
});
app.post("/get-banner", async (req, res) => {
  try {
    const result = await queryAsync(
      "SELECT `id`,`banner_name` as name,image_url,`status`,`date` FROM `banner` where `banner_name`= ? and `status`='Y'", [req.body.banner]
    );
    res.status(200).json({
      error: false,
      status: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      error: true,
      status: false,
      message: error.message
    });
  }
});


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
    const { email, data } = req.body;
    if (email) {
      return auth.username === email ? next() : res.status(403).send(UNAUTHORIZED);
    }
    if (data) {
      try {
        const decodedData = JSON.parse(Buffer.from(data, 'base64').toString('utf8'));
        return auth.username === decodedData.email ? next() : res.status(403).send(UNAUTHORIZED);
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
function refferLevel(level, ba, ab) {
  if (level < 1) throw new Error("Level must be at least 1");
  const columns = Array.from({ length: level }, (_, i) => `level_${i + 1}`);
  const values = columns.map(() => '?');
  const sqlInsert = `INSERT INTO user_level (user_reffral, ${columns.join(', ')}) VALUES (?, ${values.join(', ')})`;

  function getRefCode(refferCode, currentLevel, refs, callback) {
    if (currentLevel > level) {
      callback(refs);
    } else {
      con.query("SELECT IFNULL(reffer_by, 0) as ref FROM user_details WHERE reffer_code = ?", [refferCode], (err, result) => {
        if (err) throw err;
        const ref = result[0]?.ref || '';
        refs.push(ref);
        if (ref === '') {
          callback(refs);
        } else {
          getRefCode(ref, currentLevel + 1, refs, callback);
        }
      });
    }
  }

  getRefCode(ab, 1, [], (refs) => {
    const insertValues = [ba, ab, ...refs.slice(0, level - 1)];
    con.query(sqlInsert, insertValues);
  });
}
function reffer1(ba, ab) { refferLevel(1, ba, ab); };
function reffer2(ba, ab) { refferLevel(2, ba, ab); };
function reffer3(ba, ab) { refferLevel(3, ba, ab); };
function reffer4(ba, ab) { refferLevel(4, ba, ab); };
function reffer5(ba, ab) { refferLevel(5, ba, ab); };
function reffer6(ba, ab) { refferLevel(6, ba, ab); };
function reffer7(ba, ab) { refferLevel(7, ba, ab); };
function reffer8(ba, ab) { refferLevel(8, ba, ab); };
function reffer9(ba, ab) { refferLevel(9, ba, ab); };
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