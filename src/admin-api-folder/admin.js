const express = require("express");
const app = express.Router();
const con = require("../db/conn");
const multer = require("multer");
var jwt = require("jsonwebtoken");
const cors = require("cors");
const fs = require("fs");
const path = require('path');
require("dotenv").config();
const bcrypt = require("bcrypt");
var bodyParser = require("body-parser");
app.use(cors());
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({
  limit: "50mb",
  extended: true,
  parameterLimit: 50000,
}));
SECRET_KEY_SUPERADMIN = "5e0+&:e3%bcc4<f7:1f%.08x4-9:a8$*$&?&a9_a46c!2.:<^b&^f?4*&7a*>b!.f:_7>8:c-77@>&4*@3_e4,-f:$93?0$-,+*.&4c%1*d$<_481_,-_>4:0@&5e@*615bc54*!2.8cc679>319%.+:!b562>a4,@7$eaad?1!e!3:-c25f+d^a%$%0e7^^ef1c,5&.5d3%@b&&<?!&.4@27:>_-+$@3+911&7&0$9^,.4c,3:8d:c6a39!.?!7a$@%16*d&7187?<*0.,6%2!da9-f<81ca+>5@>_.5<+d,*_!@+<e.-8++ed&,b95-!.?2_&3$97587,:.&5$:*83045!&^23?b:89c-?6>0^f,<4fb&<2*b39?>!c4_d2!8,,d>2e!4?.&3<3e34@<4087>f3:>&08.b@%,!-!2ced9a9e.?a-$&+48<ee.e+<0d!c71?5*5.e8$605>@c!9bd<?b:5:_<_+c:*4*f83,5c4<:&0*b&e8d7fdc,bebd92f-cf?:59_+5c&1$%-<9bc_3+28+@+3&4!?8!2@<?*-d>7170-+?43b3.a9%4,+8>_?@5:+^8^2c@+1bd99aa346*c185c.9*,e36fa&0,%b>:d2!+?6624%,-6_7_8:23?4*4c&-add+26@52229+5^*b>c._0-d0*bc*_@be6a+_f8$aa854!3$a,a^.@10<f.>+@:1::.fa,68010a<f-@e60_8f9:55d>62f@+!:18!@a-,c@+9>>8?<5bd<1--8e163_156%&d_%32*,40-*02$+165_-*&.5!82_5d^a,_!96e_3*+31<&>--?c4a%a7+?>6*,<:-?e:+2$8<?%e+&*d78%_@e>2>1.!48ca$^8+%3b>6$+@-&*&,0&$c054_d7&4-!d7d._:>&81-41:<1d,f0aa2:4a?8_>?,f1_,&77+!7&!9d^@_e?02$d69^-a__3bc2,@1<%.4e0$7&f>3?&1c03e9+a-+b9*7?d$eb$>3>%c!b<.";
SECRET_KEY_ADMIN = "%35ea7>+bc3c+b4-b42+9@!-e%5.:e3>xf$:50%>95>!4c3^$*68!6+3>@2@_b9$^1*6!0<%a6?-.5_0c,1:29d<,--!0?->ce!5ba3d!3&b_9&_3$*e_8a:%,>?&2.d_0-f2e$_:96%9429-:3c!?d4!48.4f7@-0^6-53_?f555>>a$>8e,:-c++%:d_&83&%*a9%e_130:_!98:-@-$0?2!1c9$d<9*@58e^%+e77caf?b8!1+%?%a.^9@&-&c!@c!3&_117+&%&_7<9%&.@,e_56:a1!9519%.&e.e%_@02_2^!.5882%.&a%07+f6_322?_d<4+3>@:6-_!c+e0*%cc$0-4!0a!a.,^6@1*^9a8+1fa%6%%32$@668-5a$%*.^f712*$4*^180,,3a,?ac3e69@3a*f^+^,b509*&.a6%07be:5_+$.%b1:9323^+1+^+1a:-%0ecfa7!?2?1:6:!1+44%980.!+fdce,,!^53^9+:-9fd22+0d@:^e&&d1^33387-2c2,@@<2_e@f1@65^0c_e83%?.2.b8?<7&?&-+-e$*a7.42$.?e?<fd?>*b2b%c4,8>ab5>9<e-8d!:b567!dd+3&$>&9:fe$d773%!ee<9<*@97@-&3c3%93?c5&+6^f0e,!<-<,958+d+5$,f3634.+9>%*2?b6?9+c:4%_<7!^@%5.21f26edd,5_<%c_,>17&e4>@4b&,:&_!a1a?b::!:1*>_?3-?ec+1:e!-_e6@>ec6299_6<!-$841b08^7-<a&4f?880e:%4@a$*1?f61-&3$d,e^.,%5*c7*>&a-1_@1b0@?08^,?<:+97>*4%e9d8-5>361$-c3b$-*+b,%6d7f90!6a-c?*d&a&:&+&12!2<<7ba>6&^.>:c$_,a8&e4$<e93.*a,88+b-b.>_:*+<-2?*d*_^^2d7+:@?7f!b6*.*2:a:-18b7d+d@4a5800,&_<c46:9&2d?30f:281^d,^b.@-7^a3&^c+@^%f6";
app.use("../../assets", express.static("assets"));
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    if (file.fieldname == "add_banner") {
      cb(null, "image/banners-details");
    } else if (file.fieldname == "add_cat") {
      cb(null, "image/catagory");
    } else if (file.fieldname == "add_sub_cat") {
      cb(null, "image/sub-catagory");
    } else if (file.fieldname == "add_slug") {
      cb(null, "image/slug");
    } else if (file.fieldname == "Add_plan_img") {
      cb(null, "image/plan");
    } else if (file.fieldname == "qr_code") {
      cb(null, "image/QR-Code");
    } else if (file.fieldname == "s_image") {
      cb(null, "image/shopping_image");
    } else if (file.fieldname == "game_type") {
      cb(null, "image/game-type");
    }
    else {
      cb(null, "assets/img");
    }
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + "-" + uniqueSuffix + ".png");
  },
});
const vstorage = multer.diskStorage({
  destination: function (req, file, cb) {
    if (file.fieldname == "video") {
      cb(null, "assets/video");
    }
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + "-" + uniqueSuffix + ".mp4");
  },
});
const upload = multer({ storage: storage });
const vupload = multer({ storage: vstorage });
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await queryAsync(
      "SELECT (SELECT name FROM role WHERE id = role_id) AS role FROM role_assign WHERE user_id = (SELECT id FROM `login` WHERE `username` = ?);",
      [username]
    );
    if (result.length === 0) {
      return res.status(404).json({
        error: true,
        status: false,
        message: "This user is not assigned a role"
      });
    }
    const role = result[0].role;
    const loginResult = await queryAsync(
      "SELECT * FROM login WHERE username = ?",
      [username]
    );
    if (loginResult.length === 0) {
      return res.send("Username does not exist");
    }
    const user = loginResult[0];
    const isMatch = bcrypt.compareSync(password, user.password);
    if (!isMatch) {
      return res.send("Username and Password are Wrong!");
    }
    const secretKey = role === 'Super Admin' ? SECRET_KEY_SUPERADMIN : SECRET_KEY_ADMIN;
    const token = await new Promise((resolve, reject) => {
      jwt.sign(
        { username: user.username },
        secretKey,
        { expiresIn: '3h' },
        (err, token) => {
          if (err) {
            reject(err);
          } else {
            resolve(token);
          }
        }
      );
    });
    await queryAsync("UPDATE `login` SET `is_active` = 'Y' WHERE `username` = ?", [username]);
    res.status(200).json({
      status: true,
      username: user.username,
      token,
    });
  } catch (error) {
    res.status(500).json({ error: true, message: 'Internal Server Error' });
  }
});
app.post("/logout", async (req, res) => {
  const result = await queryAsync("UPDATE `login` SET `is_active` = 'N' WHERE `username` = ?", [req.body.username]);
  if (result) {
    res.status(200).send({ error: false, status: true });
  }
});
app.post('/change', verifytoken, async (req, res) => {
  const { username, password, new_password } = req.body;
  try {
    const result = await queryAsync(
      'SELECT * FROM `login` WHERE `username` = ?',
      [username]
    );

    if (result.length > 0) {
      // Compare the provided password with the stored hash
      const status = bcrypt.compareSync(password, result[0].password);
      if (status) {
        // Hash the new password
        const hash = bcrypt.hashSync(new_password, bcrypt.genSaltSync(12));

        // Update the password in the database
        const updateResult = await queryAsync(
          'UPDATE `login` SET `password` = ? WHERE `username` = ?',
          [hash, username]
        );

        // Check if the update was successful
        if (updateResult.affectedRows > 0) {
          res.status(200).json({
            error: false,
            status: true,
            message: 'Reset Password Successfully',
          });
        } else {
          res.status(500).json({
            error: true,
            message: 'Failed to update password',
          });
        }
      } else {
        res.status(200).json({
          error: true,
          message: 'Password is Wrong',
        });
      }
    } else {
      res.status(404).json({
        error: true,
        message: 'User not found',
      });
    }
  } catch (error) {
    res.status(500).json({
      error: true,
      message: 'Internal Server Error',
    });
  }
});

app.post("/add-admin", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'add_d');
    if (value[0].check === "true") {
      const salt = bcrypt.genSaltSync(10);
      const hash = bcrypt.hashSync(req.body.password, salt);

      const module = await queryAsync(
        "SELECT m.module_name FROM assign_module as am INNER JOIN module as m ON am.module = m.id WHERE am.role = (SELECT role_id FROM role_assign WHERE user_id = (SELECT id FROM login WHERE username = ?))",
        [req.body.username]
      );

      const f = module.find(element => element.module_name === 'Sub-Admin');
      if (!f) {
        res.status(403).send({ error: true, status: false, message: 'You are not Capable to Create Admin' });
        return;
      }

      const result = await queryAsync("SELECT * FROM login WHERE username = ?", [req.body.nusername]);
      if (result.length === 0) {
        await queryAsync(
          "INSERT INTO login(name, username, password) VALUES (?, ?, ?)",
          [req.body.name, req.body.nusername, hash]
        );

        await queryAsync(
          "INSERT INTO role_assign(role_id, user_id) VALUES (?, (SELECT id FROM login WHERE username = ?))",
          [req.body.role, req.body.nusername]
        );

        res.status(200).send({ error: false, status: true, message: 'New Admin Created Successfully' });
      } else {
        res.status(302).send("Username already exists");
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/update-admin", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'update_d');
    if (value[0].check === "true") {
      const module = await queryAsync(
        "SELECT m.module_name FROM assign_module as am INNER JOIN module as m ON am.module = m.id WHERE am.role = (SELECT role_id FROM role_assign WHERE user_id = (SELECT id FROM login WHERE username = ?))",
        [req.body.username]
      );

      const f = module.find(element => element.module_name === 'Sub-Admin');
      if (!f) {
        res.status(403).send({ error: true, status: false, message: 'You are not Capable to Create Admin' });
        return;
      }

      const check = await queryAsync("SELECT id FROM login WHERE username = ?", [req.body.nusername]);

      if (check.length > 0) {
        if (check[0].id === req.body.id) {
          await queryAsync(
            "UPDATE login SET username = ?, name = ? WHERE id = ?",
            [req.body.nusername, req.body.name, req.body.id]
          );

          await queryAsync(
            "UPDATE role_assign SET role_id = ? WHERE user_id = ?",
            [req.body.role, req.body.id]
          );

          res.status(200).send({ error: false, status: true, message: 'Admin Details Updated Successfully' });
        } else {
          res.status(302).send({ error: true, status: false, message: 'Username already exists' });
        }
      } else {
        await queryAsync(
          "UPDATE login SET username = ?, name = ? WHERE id = ?",
          [req.body.nusername, req.body.name, req.body.id]
        );

        await queryAsync(
          "UPDATE role_assign SET role_id = ? WHERE user_id = ?",
          [req.body.role, req.body.id]
        );

        res.status(200).send({ error: false, status: true, message: 'Admin Details Updated Successfully' });
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/get-admin", verifytoken, async (req, res) => {
  try {
    const check = await getRoleCheck(req.body.username, 'view');
    if (check[0].check === "true") {
      const result = await queryAsync(
        "SELECT l.id, l.name, l.username, (IFNULL((SELECT role.display_name FROM role WHERE role.id = ra.role_id), 'Not Assign')) as role, l.date, l.is_active, l.status FROM login as l LEFT JOIN role_assign as ra ON l.id = ra.user_id"
      );

      res.status(200).send({ error: false, status: true, data: result });
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/del-admin", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'delete_d');
    if (value[0].check === "true") {
      const result = await queryAsync("DELETE FROM role_assign WHERE user_id = ?", [req.body.id]);

      if (result.affectedRows > 0) {
        await queryAsync("DELETE FROM login WHERE id = ?", [req.body.id]);
        res.status(200).send({ error: false, status: true, message: 'Your Admin has been Deleted Successfully' });
      } else {
        await queryAsync("DELETE FROM login WHERE id = ?", [req.body.id]);
        res.status(200).send({ error: false, status: true, message: 'Your Admin has been Deleted Successfully' });
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/change-admin-password", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'delete_d');
    if (value[0].check == "true") {
      const result = await queryAsync("DELETE FROM role_assign WHERE user_id = ?", [req.body.id]);
      if (result.affectedRows > 0) {
        await queryAsync("DELETE FROM login WHERE id = ?", [req.body.id]);
        res.status(200).send({ error: false, status: true, message: 'Your Admin has been Deleted Successfully' });
      } else {
        await queryAsync("DELETE FROM login WHERE id = ?", [req.body.id]);
        res.status(200).send({ error: false, status: true, message: 'Your Admin has been Deleted Successfully' });
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});

app.post("/get-user", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'view');
    if (value[0].check === "true") {
      const result = await queryAsync("SELECT * FROM `user`");
      if (result) {
        res.status(200).send({ error: false, status: true, data: result });
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/del-user", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'delete_d');
    if (value[0].check === "true") {
      const result = await queryAsync("DELETE FROM `user` WHERE `id` = ?", [req.body.id]);
      if (result) {
        res.status(200).send({ error: false, status: true, message: 'Your User has been Deleted SuccessFully' })
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post('/add-activity_maping', verifytoken, async (req, res) => {
  try {
    const { name, url, status, manu } = req.body;
    const existingActivity = await queryAsync('SELECT * FROM activity_maping WHERE activity_name = ?', [name]);
    if (existingActivity.length > 0) {
      return res.status(400).send('Display name already exists');
    }
    await queryAsync('INSERT INTO activity_maping (activity_name, active_url, is_active, show_manu) VALUES (?, ?, ?, ?)',
      [name, url, status, manu]
    );
    res.status(200).send(true);
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});

app.post('/get-user', verifytoken, async (req, res) => {
  try {
    const users = await queryAsync('SELECT * FROM `user`');
    res.status(200).send({ data: users });
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});
app.post('/del-user', verifytoken, async (req, res) => {
  try {
    const { id } = req.body;
    const result = await queryAsync('DELETE FROM `user` WHERE `id` = ?', [id]);
    if (result.affectedRows > 0) {
      res.status(200).send({ error: false, status: true, message: 'Your User has been Deleted Successfully' });
    } else {
      res.status(404).send({ error: true, status: false, message: 'User not found' });
    }
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});
app.post('/status-user', verifytoken, async (req, res) => {
  try {
    const { status, id } = req.body;
    await queryAsync('UPDATE `user` SET `status` = ? WHERE `id` = ?', [status, id]);
    res.status(200).send(true);
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});
app.post("/get-total-data", verifytoken, (req, res) => {
  con.query("SELECT 'id' as 'id','mobile' as 'a';", (err, result) => {
    if (err) throw err;
    if (result) {
      res.status(200).json({ error: false, status: true, data: result });
      // const video = result.reduce((prev, current) => ((prev.video > current.video) ? prev : current), 0);
      // const like = result.reduce((prev, current) => ((prev.like > current.like) ? prev : current), 0);
      // const comment = result.reduce((prev, current) => ((prev.comment > current.comment) ? prev : current), 0);
      // con.query("select (SELECT COUNT(*) FROM `tasks_with_name` WHERE `type` = 'LIKE' and date(`date`) = CURRENT_DATE()) as 'like', (SELECT COUNT(*) FROM `tasks_with_name` WHERE `type` = 'VIDEO' and date(`date`) = CURRENT_DATE()) as video, (SELECT COUNT(*) FROM `tasks_with_name` WHERE `type` = 'COMMENT' and date(`date`) = CURRENT_DATE()) as comment", (err, resultt) => {
      //   if (err) throw err;
      //   if (resultt) {
      //     con.query("select (SELECT ifnull(COUNT(*),0) FROM `assign_task` WHERE `status` = 'Pending') as p_request,? as 'today_task_video',? as 'video',? as 'today_task_like',? as 'like',? as 'today_task_comment', ? as comment,(select IFNULL(COUNT(*), 0) from user_details) as total_user, (select IFNULL(COUNT(*), 0) from user_details WHERE is_active = 'Y') as active_user, (SELECT ifnull(SUM(`balance`), 0) FROM `deposit` WHERE `payment_type` = 'Deposit' and `status` = 'Success') as total_d, (SELECT ifnull(COUNT(`balance`), 0) FROM `deposit` WHERE `payment_type` = 'Deposit' and `status` = 'Pending') as total_d_p, (SELECT ifnull(SUM(`balance`), 0) FROM `deposit` WHERE `payment_type` = 'Deposit' and `status` = 'Success' AND date(`date`) = CURRENT_DATE()) as today_d, (SELECT ifnull(SUM(`balance`), 0) FROM `deposit` WHERE `payment_type` = 'Withdrawal' and `status` = 'Success') as total_w, (SELECT ifnull(SUM(`balance`), 0) FROM `deposit` WHERE `payment_type` = 'Withdrawal' and `status` = 'Success' AND date(`date`) = CURRENT_DATE()) as today_w, (SELECT ifnull(COUNT(`balance`), 0) FROM `deposit` WHERE `payment_type` = 'Withdrawal' and `status` = 'Pending') as total_w_p",
      //       [resultt[0].video, video.video, resultt[0].like, like.like, resultt[0].comment, comment.comment],(errr,resulttt)=>{
      //         if(errr){throw errr}
      //         if(resulttt){
      //           res.status(200).json({
      //             error: false,
      //             status: true,
      //             data: resulttt
      //           })
      //         }
      //       })
      //   }
      // })
    }
  })
});

app.post('/get-menu', verifytoken, async (req, res) => {
  try {
    const roleResult = await queryAsync(
      "SELECT role_id FROM role_assign WHERE user_id = (SELECT id FROM `login` WHERE `username` = ?);",
      [req.body.username]
    );
    if (roleResult.length > 0) {
      const menuResult = await queryAsync(
        `SELECT am.id, m.module_name, m.url, am.status, am.date 
         FROM assign_module as am 
         INNER JOIN module as m 
         ON am.module = m.id 
         WHERE role = ? 
         ORDER BY am.position ASC;`,
        [roleResult[0].role_id]
      );
      res.status(200).json({
        error: false,
        status: true,
        data: menuResult
      });
    } else {
      res.status(404).json({
        error: true,
        status: false,
        message: "This user is not assigned a role"
      });
    }
  } catch (error) {
    res.status(500).json({
      error: true,
      status: false,
      message: 'Internal Server Error'
    });
  }
});

app.post("/add-role", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'add_d');
    if (value[0].check === "true") {
      const result = await queryAsync("select * from role where display_name = ?", [req.body.display_name]);
      if (result.length > 0) {
        res.status(302).send("Display name is already exist");
      } else {
        const ab = await queryAsync("INSERT INTO `role`(`name`, `display_name`, `view`, `delete_d`, `update_d`, `add_d`,`status_d`) VALUES (?,?,?,?,?,?,?)", [req.body.name, req.body.display_name, (req.body.view_d).toString(), (req.body.delete_d).toString(), (req.body.update_d).toString(), (req.body.add_d).toString(), (req.body.status_d).toString()])
        if (ab) {
          res.status(200).json({
            error: false,
            status: true,
          });
        }
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/get-role", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'view');
    if (value[0].check === "true") {
      const result = await queryAsync("select * from role");
      if (result) {
        res.status(200).json({ error: false, status: true, data: result });
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/status-role", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'status_d');
    if (value[0].check === "true") {
      const result = await queryAsync("UPDATE `role` SET `status`= ? WHERE `id` = ?", [req.body.status, req.body.id]);
      if (result) {
        res.status(200).send({ error: false, status: true })
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/update-role", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'update_d');
    if (value[0].check === "true") {
      const result = await queryAsync("UPDATE `role` SET `name` = ?, `display_name` = ?, `view` = ?, `delete_d` = ?, `update_d` = ?, `add_d` = ?,`status_d`=? WHERE `id` = ?", [req.body.name, req.body.dname, (req.body.view_d).toString(), (req.body.delete_d).toString(), (req.body.update_d).toString(), (req.body.add_d).toString(), (req.body.status_d).toString(), req.body.id]);
      if (result) {
        res.status(200).send({ error: false, status: true })
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/get-role-not-assign", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'view');
    if (value[0].check === "true") {
      const result = await queryAsync("select * from role where role_assign = 'N'");
      if (result) {
        res.status(200).send({ error: false, status: true, data: result })
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/get-role-assign", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'view');
    if (value[0].check === "true") {
      const result = await queryAsync("select * from role where role_assign = 'Y'");
      if (result) {
        res.status(200).send({ error: false, status: true, data: result })
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});

app.post("/add-module", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'add_d');
    if (value[0].check === "true") {
      const result = await queryAsync("select * from module where module_name = ?", [req.body.module_name]);
      if (result[0] == null) {
        const ab = await queryAsync("INSERT INTO `module`(`url`, `module_name`) VALUES (?,?)", [req.body.url, req.body.module_name])
        if (ab) {
          res.status(200).send(true);
        }
      } else {
        res.send("Module name is already exist");
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/get-module", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'view');
    if (value[0].check === "true") {
      const result = await queryAsync("select * from `module`");
      if (result) {
        res.status(200).send({ error: false, status: true, data: result })
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post('/update-assign-module', verifytoken, async (req, res) => {
  try {
    const { role_id, module } = req.body;
    await queryAsync('DELETE FROM `assign_module` WHERE `role` = ?', [role_id]);
    const results = await queryAsync('SELECT MAX(`position`) as max FROM `assign_module`', []);
    let max = results[0].max + 1;
    for (const mod of module) {
      await queryAsync('INSERT INTO `assign_module`(`role`, `module`, `position`) VALUES (?, ?, ?)', [role_id, mod, max]);
      max++;
    }
    res.status(200).json({
      error: false,
      status: true,
      message: 'Module Assign Updated Successfully'
    });
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});
app.post('/get-assign-module-id', verifytoken, async (req, res) => {
  try {
    const { id } = req.body;
    const result = await queryAsync('SELECT am.module FROM assign_module am INNER JOIN module m ON am.module = m.id INNER JOIN role r ON am.role = r.id WHERE am.role = ?', [id]);
    if (result.length > 0) {
      res.status(200).json({
        error: false,
        status: true,
        data: result
      });
    } else {
      res.status(404).json({
        error: true,
        status: false,
        message: 'No modules found for the given role ID'
      });
    }
  } catch (err) {
    res.status(500).json({
      error: true,
      status: false,
      message: 'Internal Server Error'
    });
  }
});
app.post('/update-position', verifytoken, async (req, res) => {
  try {
    const username = req.body.username;
    const data = req.body.data;
    const roleResult = await queryAsync('SELECT role_id FROM role_assign WHERE user_id = (SELECT id FROM `login` WHERE `username` = ?)', [username]);
    if (roleResult.length === 0) {
      return res.status(400).send('User role not found');
    }
    const roleId = roleResult[0].role_id;
    const roleModules = await queryAsync('SELECT am.id, m.module_name, m.url, am.position, am.status, am.date FROM assign_module AS am INNER JOIN module AS m ON am.module = m.id WHERE role = ? ORDER BY am.position ASC', [roleId]);
    for (let index = 0; index < data.length; index++) {
      const moduleId = data[index].id;
      const newPosition = roleModules[index].position;
      await queryAsync('UPDATE `assign_module` SET `position` = ? WHERE `id` = ?', [newPosition, moduleId]);
    }
    res.status(200).json({
      error: false,
      status: true,
    });
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});


app.post("/get-module-id", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'view');
    if (value[0].check === "true") {
      const result = await queryAsync("select * from `module` where id = ?", [req.body.id]);
      if (result) {
        res.status(200).send(result);
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/update-module", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'update_d');
    if (value[0].check === "true") {
      const result = await queryAsync("UPDATE `module` SET `module_name` = ?, `url` = ? WHERE `id` = ?", [req.body.module_name, req.body.url, req.body.id]);
      if (result) {
        res.status(200).send(true);
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/del-module", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'delete_d');
    if (value[0].check === "true") {
      const result = await queryAsync("DELETE FROM `module` where id = ?", [req.body.id]);
      if (result) {
        res.status(200).send(true);
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});

app.post('/get-game-number', verifytoken, async (req, res) => {
  try {
    const result = await queryAsync('SELECT * FROM game_number');
    res.status(200).send({ data: result });
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});

app.post('/get-pay-method', verifytoken, async (req, res) => {
  try {
    const result = await queryAsync('SELECT * FROM payment_method');
    res.status(200).send({
      error: false,
      status: true,
      data: result,
    });
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});
app.post('/add-payment-details-upi', upload.single('qr_code'), verifytoken, async (req, res) => {
  try {
    const body = req.body;
    const existingUPI = await queryAsync('SELECT * FROM payment_details WHERE UPI_id = ?', [body.upi_id]);
    if (existingUPI.length > 0) {
      return res.status(302).json({
        error: true,
        status: false,
        message: 'UPI Id is already exist'
      });
    }
    let icons = '';
    if (req.body.payment_method === 'Google Pay') {
      icons = 'googlepay.png';
    } else if (req.body.payment_method === 'Phone Pe') {
      icons = 'phonepe.png';
    } else {
      icons = 'paytm.png';
    }
    const result = await queryAsync(
      'INSERT INTO `payment_details`(`paymethod_id`, `name`, `UPI_id`, `QR_code`, `icons`, `mobile_no`) VALUES (?,?,?,?,?,?)',
      [
        body.payment_method,
        body.name,
        body.upi_id,
        req.file.filename,
        icons,
        body.upinumber || null
      ]
    );
    if (result.affectedRows > 0) {
      let message = '';
      if (req.body.payment_method === 'Google Pay') {
        message = 'Insert Google Pay Details Successfully';
      } else if (req.body.payment_method === 'Phone Pe') {
        message = 'Insert Phone Pe Details Successfully';
      } else {
        message = 'Insert Paytm Details Successfully';
      }
      res.status(200).json({
        error: false,
        status: true,
        message: message
      });
    } else {
      res.status(500).json({
        error: true,
        status: false,
        message: 'Failed to insert payment details'
      });
    }
  } catch (error) {
    res.status(500).json({
      error: true,
      status: false,
      message: 'Internal Server Error'
    });
  }
});
app.post('/add-payment-detail-upi', verifytoken, async (req, res) => {
  try {
    const body = req.body;
    const existingUPI = await queryAsync('SELECT * FROM payment_details WHERE UPI_id = ?', [body.upi_id]);
    if (existingUPI.length > 0) {
      return res.status(302).json({
        error: true,
        status: false,
        message: 'UPI Id is already exist',
      });
    }
    const insertResult = await queryAsync(
      'INSERT INTO payment_details (paymethod_id, name, UPI_id, icons) VALUES (?, ?, ?, ?)',
      [body.payment_method, body.name, body.upi_id, 'upi.png']
    );
    if (insertResult) {
      return res.status(200).json({
        error: false,
        status: true,
        message: 'Insert UPI Details Successfully',
      });
    }
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});
app.post('/add-payment-details-bank', verifytoken, async (req, res) => {
  try {
    const body = req.body;
    const existingPaymentDetails = await queryAsync('SELECT * FROM payment_details WHERE account_no = ?', [body.account_no]);
    if (existingPaymentDetails.length > 0) {
      return res.status(302).json({
        error: true,
        status: false,
        message: 'Account Number already exists',
      });
    }
    const insertResult = await queryAsync(
      'INSERT INTO payment_details (paymethod_id, name, bank_name, account_no, ifsc_code, account_type) VALUES (?, ?, ?, ?, ?, ?)',
      [
        parseInt(body.payment_method),
        body.name,
        body.bank_name,
        body.account_no,
        body.ifsc_code,
        body.account_type,
      ]
    );
    if (insertResult) {
      return res.status(200).json({
        error: false,
        status: true,
        message: 'Inserted Bank Details Successfully',
      });
    }
  } catch (err) {
    res.status(500).json({
      error: true,
      status: false,
      message: 'Internal Server Error',
    });
  }
});
app.post('/get-payment-details', verifytoken, async (req, res) => {
  try {
    const { method } = req.body;
    const query = `
      SELECT pd.id, pm.id as pm_id, pm.name as payment_method, pd.name, pd.mobile_no, pd.UPI_id,
             pd.QR_code, pd.bank_name, pd.account_no, pd.ifsc_code, pd.account_type, pm.icon, pd.status
      FROM payment_details as pd
      INNER JOIN payment_method as pm ON pd.paymethod_id = pm.id
      WHERE pm.name = ?
    `;
    const paymentDetails = await queryAsync(query, [method]);
    res.status(200).send({ data: paymentDetails });
  } catch (error) {
    res.status(500).send('Internal Server Error');
  }
});
app.post('/status-payment-details', verifytoken, async (req, res) => {
  try {
    const { method, id } = req.body;
    const result = await queryAsync('UPDATE payment_details SET status = ? WHERE id = ?', [method, id]);
    if (result.affectedRows > 0) {
      res.status(200).json({
        error: false,
        status: true,
        message: 'Status Changed Successfully',
      });
    } else {
      res.status(400).json({
        error: true,
        status: false,
        message: 'No records updated',
      });
    }
  } catch (error) {
    res.status(500).json({
      error: true,
      status: false,
      message: 'Internal Server Error',
    });
  }
});
app.post('/del-payment-details', verifytoken, async (req, res) => {
  try {
    const { id } = req.body;
    const checkDeposits = await queryAsync('SELECT * FROM deposit WHERE paymethod_id = ?', [id]);
    if (checkDeposits.length > 0) {
      return res.status(405).json({
        error: true,
        status: false,
        message: 'This payment method is already used.'
      });
    }
    await queryAsync('DELETE FROM payment_details WHERE id = ?', [id]);
    res.status(200).json({
      error: false,
      status: true,
      message: 'Your payment details have been deleted.'
    });
  } catch (err) {
    if (err.sqlMessage && err.sqlMessage.includes("Cannot delete or update a parent row")) {
      res.status(405).json({
        error: true,
        status: false,
        message: 'This payment method is already used.'
      });
    } else {
      res.status(500).json({
        error: true,
        status: false,
        message: 'Internal Server Error'
      });
    }
  }
});
app.post('/update-payment-details', upload.single('qr_code'), verifytoken, async (req, res) => {
  try {
    const { name, upi_id, id } = req.body;
    const qr_code = req.file ? req.file.filename : null;
    const result = await queryAsync('UPDATE `payment_details` SET `name` = ?, `UPI_id` = ?, `QR_code` = ? WHERE `id` = ?', [name, upi_id, qr_code, id]);
    if (result.affectedRows > 0) {
      res.status(200).send({
        error: false,
        status: true,
        message: 'Update Details Successfully',
      });
    } else {
      res.status(404).send({
        error: true,
        status: false,
        message: 'Payment details not found or not updated',
      });
    }
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      res.status(403).send('UPI Id already exists');
    } else {
      res.status(500).send('Internal Server Error');
    }
  }
});
app.post('/update-bank-payment-details', verifytoken, async (req, res) => {
  try {
    const { id, name, bank_name, account_no, ifsc_code, account_type } = req.body;
    const existingDetails = await queryAsync('SELECT id FROM payment_details WHERE account_no = ?', [account_no]);
    if (existingDetails.length > 0 && existingDetails[0].id !== id) {
      return res.status(302).send({ error: true, status: false, message: 'Account No is already in use' });
    }
    const updateQuery = `
      UPDATE payment_details 
      SET name = ?, bank_name = ?, account_no = ?, ifsc_code = ?, account_type = ? 
      WHERE id = ?
    `;
    await queryAsync(updateQuery, [name, bank_name, account_no, ifsc_code, account_type, id]);
    res.status(200).send({ error: false, status: true, message: 'Details updated successfully' });
  } catch (error) {
    res.status(500).send('Internal Server Error');
  }
});

app.post('/get-user-details', verifytoken, async (req, res) => {
  try {
    const query = `
      SELECT ud.id AS id, ud.mobile, ud.username, ud.email, ud.address, ud.uid, ud.status, ud.date 
      FROM user_details AS ud
    `;
    const userDetails = await queryAsync(query);
    const formattedData = userDetails.map(user => ({
      id: user.id,
      mobile: user.mobile,
      username: user.username,
      email: user.email,
      address: user.address ? JSON.parse(user.address) : [],
      uid: user.uid,
      status: user.status,
      date: user.date
    }));
    res.status(200).json({
      error: false,
      status: true,
      data: formattedData
    });
  } catch (error) {
    res.status(500).json({
      error: true,
      message: 'Internal Server Error'
    });
  }
});
app.post('/status-user-details', verifytoken, async (req, res) => {
  try {
    const { status, id } = req.body;
    await queryAsync('UPDATE `user_details` SET `status` = ? WHERE `id` = ?', [status, id]);
    res.status(200).json({
      error: false,
      status: true,
      message: 'Status Changed Successfully',
    });
  } catch (err) {
    res.status(500).json({
      error: true,
      status: false,
      message: 'Failed to change status',
    });
  }
});
app.post('/del-user-details', verifytoken, async (req, res) => {
  try {
    const { wid, id } = req.body;
    await queryAsync('DELETE FROM product_ratings WHERE user_id = ?', [wid]);
    await queryAsync('DELETE FROM user_details WHERE id = ?', [id]);
    await queryAsync('DELETE FROM wallet WHERE id = ?', [wid]);
    res.status(200).json({
      error: false,
      status: true,
      message: 'Your details have been deleted.',
    });
  } catch (err) {
    res.status(500).json({
      error: true,
      status: false,
      message: 'Failed to delete user details.',
    });
  }
});
app.post('/update-user-details', verifytoken, async (req, res) => {
  const { name, upi_id, id } = req.body;
  const qr_code = req.file ? req.file.filename : null;
  try {
    const existingUser = await queryAsync('SELECT * FROM payment_details WHERE UPI_id = ? AND id != ?', [upi_id, id]);
    if (existingUser.length > 0) {
      return res.status(403).send('UPI Id is already in use');
    }
    const result = await queryAsync('UPDATE payment_details SET name = ?, UPI_id = ?, QR_code = ? WHERE id = ?', [name, upi_id, qr_code, id]);
    if (result.affectedRows > 0) {
      res.status(200).json({
        error: false,
        status: true,
      });
    } else {
      res.status(404).send('User not found');
    }
  } catch (error) {
    res.status(500).send('Internal Server Error');
  }
});

app.post('/get-assign-task', verifytoken, async (req, res) => {
  try {
    let sqlQuery = `
      SELECT ast.id, ud.username AS name, ud.mobile, ast.username, ast.url, 
             twn.task_url, twn.type, 
             (SELECT p.name FROM platforms AS p WHERE p.id = twn.platform_id) AS platform,
             twn.comment_details, ast.status, ast.approved_declined_by, ast.date 
      FROM assign_task AS ast 
      INNER JOIN tasks_with_name AS twn ON ast.task_id = twn.id 
      INNER JOIN user_details AS ud ON ast.user_id = ud.id`;
    const queryParams = [];
    if (req.body.status === 'Completed') {
      sqlQuery += ' WHERE ast.status = ?';
      queryParams.push('Completed');
    } else if (req.body.status === 'Verifying') {
      sqlQuery += ' WHERE ast.status = ?';
      queryParams.push('Verifying');
    } else if (req.body.status === 'Failed') {
      sqlQuery += ' WHERE ast.status = ?';
      queryParams.push('Failed');
    } else {
      sqlQuery += ' WHERE ast.status != ?';
      queryParams.push('Pending');
    }
    const result = await queryAsync(sqlQuery, queryParams);
    res.status(200).send({
      error: false,
      status: true,
      data: result,
    });
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});
app.post('/approve-assign-task', verifytoken, async (req, res) => {
  try {
    const { username, id, mobile } = req.body;
    await queryAsync(
      "UPDATE `assign_task` SET `status` = 'Completed', `approved_declined_by` = ? WHERE `id` = ?",
      [username, id]
    );
    const updateWalletQuery = `
      UPDATE wallet
      SET winning_wallet = ROUND(winning_wallet + (
        SELECT IF(twn.type = 'COMMENT', 0.75, IF(twn.type = 'LIKE', 0.40, 1.67)) AS price
        FROM tasks_with_name AS twn
        WHERE twn.id = at.task_id
      ), 2)
      WHERE user_name = ?
    `;
    await queryAsync(updateWalletQuery, [mobile]);
    const insertStatementQuery = `
      INSERT INTO statement(mobile, type, amount, total_balance)
      VALUES (?, (SELECT twn.type FROM tasks_with_name AS twn WHERE twn.id = at.task_id), 
              ROUND((SELECT IF(twn.type = 'COMMENT', 0.75, IF(twn.type = 'LIKE', 0.40, 1.66)) AS price
                    FROM tasks_with_name AS twn
                    WHERE twn.id = at.task_id), 2), 
              (SELECT w.winning_wallet FROM wallet AS w WHERE w.user_name = ?))
    `;
    await queryAsync(insertStatementQuery, [mobile, id, id, mobile]);
    res.status(200).send({
      error: false,
      status: true,
      message: "Wallet Update Successfully",
    });
  } catch (error) {
    res.status(500).send("Internal Server Error");
  }
});
app.post('/decline-assign-task', verifytoken, async (req, res) => {
  try {
    const { username, id } = req.body;
    const result = await queryAsync(
      'UPDATE assign_task SET status = ?, Approved_declined_By = ? WHERE id = ?',
      ['Canceled', username, id]
    );
    if (result.affectedRows > 0) {
      res.status(200).send({
        error: false,
        status: true,
        message: 'Update Details Successfully',
      });
    } else {
      res.status(404).send({
        error: true,
        status: false,
        message: 'Task not found or update failed',
      });
    }
  } catch (error) {
    res.status(500).send({
      error: true,
      status: false,
      message: 'Internal Server Error',
    });
  }
});

app.post('/get-deposit-request', verifytoken, async (req, res) => {
  try {
    let queryStr = "SELECT cd.id, cd.user_name, cd.image, cd.transaction_id, cd.reason, cd.payment_type, cd.balance, cd.status, cd.Approved_declined_By, cd.date FROM `deposit` as cd WHERE cd.payment_type = 'Deposit'";
    if (req.body.status === 'Pending') {
      queryStr += " AND cd.`status` = 'Pending'";
    } else if (req.body.status === 'Success') {
      queryStr += " AND cd.`status` = 'Success'";
    } else if (req.body.status === 'Canceled') {
      queryStr += " AND cd.`status` = 'Canceled'";
    }
    const result = await queryAsync(queryStr);
    res.status(200).send({
      error: false,
      status: true,
      data: result,
    });
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});
app.post('/approve-deposit-request', verifytoken, async (req, res) => {
  try {
    const { username, id, mobile } = req.body;
    const updateDepositQuery = 'UPDATE deposit SET status = ?, Approved_declined_By = ? WHERE id = ?';
    await queryAsync(updateDepositQuery, ['Success', username, id]);
    const selectBalanceQuery = 'SELECT balance FROM deposit WHERE id = ?';
    const depositResult = await queryAsync(selectBalanceQuery, [id]);
    const depositBalance = depositResult[0].balance;
    const updateWalletQuery = 'UPDATE wallet SET wallet_balance = wallet_balance + ? WHERE user_name = ?';
    await queryAsync(updateWalletQuery, [depositBalance, mobile]);
    res.status(200).send({
      error: false,
      status: true,
      message: 'Wallet Update Successfully',
    });
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});
app.post('/decline-deposit-request', verifytoken, async (req, res) => {
  try {
    const { reason, username, id } = req.body;
    const result = await queryAsync(
      'UPDATE deposit SET status = ?, reason = ?, Approved_declined_By = ? WHERE id = ?',
      ['Canceled', reason, username, id]
    );
    if (result.affectedRows > 0) {
      res.status(200).send({
        error: false,
        status: true,
        message: 'Update Details Successfully',
      });
    } else {
      res.status(404).send({
        error: true,
        status: false,
        message: 'Deposit request not found or not updated',
      });
    }
  } catch (err) {
    res.status(500).send({
      error: true,
      status: false,
      message: 'Internal Server Error',
    });
  }
});

app.post('/get-bank-details', verifytoken, async (req, res) => {
  try {
    let sql = "SELECT * FROM `userbankdeatils`";
    let params = [];
    if (req.body.status) {
      sql += " WHERE `status` = ?";
      params.push(req.body.status);
    }
    const result = await queryAsync(sql, params);
    res.status(200).send({ error: false, status: true, data: result });
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});
app.post('/approve-bank-details', verifytoken, async (req, res) => {
  const { username, id } = req.body;
  try {
    const result = await queryAsync(
      'UPDATE `userbankdeatils` SET `status` = ?, `approved_or_denied_by` = ? WHERE `id` = ?',
      ['Success', username, id]
    );
    if (result.affectedRows > 0) {
      res.status(200).send({
        error: false,
        status: true,
        message: 'Bank details approved successfully',
      });
    } else {
      res.status(404).send({
        error: true,
        status: false,
        message: 'Bank details not found or update failed',
      });
    }
  } catch (error) {
    res.status(500).send({
      error: true,
      status: false,
      message: 'Internal Server Error',
    });
  }
});
app.post('/decline-bank-details', verifytoken, async (req, res) => {
  try {
    const { reason, username, id } = req.body;
    const result = await queryAsync(
      'UPDATE `userbankdeatils` SET `status` = ?, `reason` = ?, `approved_or_denied_by` = ? WHERE `id` = ?',
      ['Canceled', reason, username, id]
    );
    if (result.affectedRows > 0) {
      res.status(200).send({
        error: false,
        status: true,
        message: 'Declined Bank Details!',
      });
    } else {
      res.status(404).send({
        error: true,
        status: false,
        message: 'Bank details not found or update failed.',
      });
    }
  } catch (err) {
    res.status(500).send({
      error: true,
      status: false,
      message: 'Internal Server Error',
    });
  }
});

app.post('/get-withdrawal-request', verifytoken, async (req, res) => {
  try {
    let sqlQuery = "SELECT cd.id, cd.user_name, ud.bank_name, ud.ifsc_code, ud.ac_no, ud.ac_name, cd.reason, cd.payment_type, cd.balance, cd.status, cd.Approved_declined_By, cd.date FROM `deposit` as cd INNER JOIN user_details as ud ON cd.user_name = ud.mobile WHERE cd.payment_type = 'Withdrawal'";
    const { status } = req.body;
    if (status) {
      sqlQuery += ` AND cd.status = '${status}'`;
    }
    const result = await queryAsync(sqlQuery);
    res.status(200).send({ error: false, status: true, data: result });
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});
app.post('/approve-withdrawal-request', verifytoken, async (req, res) => {
  try {
    const { username, id, mobile } = req.body;
    const result = await queryAsync(
      "UPDATE deposit SET Approved_declined_By=?, status='Success' WHERE id=? AND user_name=?",
      [username, id, mobile]
    );
    if (result.affectedRows > 0) {
      res.status(200).send({
        error: false,
        status: true,
        message: "Withdrawal request approved successfully."
      });
    } else {
      res.status(404).send({
        error: true,
        status: false,
        message: "Withdrawal request not found or could not be updated."
      });
    }
  } catch (error) {
    res.status(500).send({
      error: true,
      status: false,
      message: "Internal Server Error"
    });
  }
});
app.post('/decline-withdrawal-request', verifytoken, async (req, res) => {
  try {
    const { reason, username, id } = req.body;
    const updateDepositQuery = 'UPDATE deposit SET reason = ?, Approved_declined_By = ?, status = "Canceled" WHERE id = ?';
    await queryAsync(updateDepositQuery, [reason, username, id]);
    const updateWalletQuery = `
      UPDATE wallet 
      SET wallet_balance = wallet_balance + (SELECT balance FROM deposit WHERE id = ?) 
      WHERE user_name = (SELECT user_name FROM deposit WHERE id = ?)
    `;
    await queryAsync(updateWalletQuery, [id, id]);
    res.status(200).send({
      error: false,
      status: true,
      message: "Wallet Update Successfully"
    });
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});

app.post('/add-platform', verifytoken, async (req, res) => {
  try {
    const { name } = req.body;
    await queryAsync('INSERT INTO platforms (name) VALUES (?)', [name]);
    res.status(200).send({
      error: false,
      status: true,
      message: 'Added Details Successfully'
    });
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});
app.post('/add-category', upload.array('image', 8), verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'add_d');
    if (value[0].check !== "true") {
      return res.status(401).json({ error: true, status: false, message: "You are not authorized!" });
    }
    const { name, cat_id } = req.body;
    const files = req.files;
    const existingCategory = await queryAsync('SELECT * FROM category WHERE name = ?', [name]);
    if (existingCategory.length > 0) {
      if (files.length > 0) {
        deleteImage('img/' + files[0].filename);
      }
      return res.status(302).json({
        error: true,
        status: false,
        message: "Category name already exists."
      });
    }
    if (files.length === 0) {
      await queryAsync('INSERT INTO `category`(`name`, `category_id`) VALUES (?, ?)', [name, cat_id]);
    } else {
      await queryAsync('INSERT INTO `category`(`name`, `category_id`, `image_url`) VALUES (?, ?, ?)', [name, cat_id, files[0].filename]);
    }
    res.status(200).json({
      error: false,
      status: true,
      message: "Category name added successfully."
    });
  } catch (error) {
    res.status(500).json({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/get-category", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'view');
    if (value[0].check == "true") {
      const result = await queryAsync(
        "SELECT `id`,`name`,image_url,`status`,`date` FROM `category`"
      );
      res.status(200).json({
        error: false,
        status: true,
        data: result,
      });
    } else {
      res.status(401).json({
        error: true,
        status: false,
        message: "You Are Not Authorized!",
      });
    }
  } catch (err) {
    res.status(500).json({
      error: true,
      status: false,
      message: "Internal Server Error",
    });
  }
});
app.post("/status-category", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'status_d');
    if (value[0].check == "true") {
      const result = await queryAsync(
        "UPDATE `category` SET `status`= ? WHERE `id` = ?",
        [req.body.status, req.body.id]
      );
      res.status(200).send({
        error: false,
        status: true,
        message: "Status Changed Successfully.",
      });
    } else {
      res.status(401).json({
        error: true,
        status: false,
        message: "You Are Not Authorized!",
      });
    }
  } catch (err) {
    res.status(500).json({
      error: true,
      status: false,
      message: "Internal Server Error",
    });
  }
});
app.post("/update-category", upload.array("image", 8), verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'update_d');
    if (value[0].check == "true") {
      if (req.files.length == 0) {
        try {
          const result = await queryAsync(
            "UPDATE `category` SET `name` = ? WHERE `id` = ?",
            [req.body.name, req.body.id]
          );
          res.status(200).json({
            error: false,
            status: true,
            message: "Category Updated Successfully."
          });
        } catch (err) {
          if (err.code == "ER_DUP_ENTRY") {
            res.status(302).json({
              error: true,
              status: false,
              message: "Category name already exists."
            });
          } else {
            throw err;
          }
        }
      } else {
        try {
          const result = await queryAsync(
            "UPDATE `category` SET `name` = ?,`image_url`=? WHERE `id` = ?",
            [req.body.name, req.files[0].filename, req.body.id]
          );
          deleteImage("img/" + req.body.old_image);
          res.status(200).json({
            error: false,
            status: true,
            message: "Category Updated Successfully."
          });
        } catch (err) {
          if (err.code == "ER_DUP_ENTRY") {
            deleteImage("img/" + req.files[0].filename);
            res.status(302).json({
              error: true,
              status: false,
              message: "Category name already exists."
            });
          } else {
            throw err;
          }
        }
      }
    } else {
      res.status(401).json({
        error: true,
        status: false,
        message: "You Are Not Authorized!"
      });
    }
  } catch (err) {
    res.status(500).json({ error: true, message: "Internal Server Error" });
  }
});
app.post("/del-category", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'delete_d');
    if (value[0].check === "true") {
      const result = await queryAsync("DELETE FROM `category` WHERE `id` = ?", [req.body.id]);
      if (result) {
        res.status(200).json({ error: false, status: true, message: "Category Deleted SuccessFully." });
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});

app.post("/get-sub-category-by-id", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'view');
    if (value[0].check == "true") {
      const result = await queryAsync(
        "SELECT `id`,`name`,(select c.name from category as c WHERE c.id = `category_id`) as cat_name,image_url,`status`,`date` FROM `sub_category` WHERE `category_id` = ?", [req.body.cat_id]
      );
      res.status(200).json({
        error: false,
        status: true,
        data: result,
      });
    } else {
      res.status(401).json({
        error: true,
        status: false,
        message: "You Are Not Authorized!",
      });
    }
  } catch (err) {
    res.status(500).json({
      error: true,
      status: false,
      message: "Internal Server Error",
    });
  }
});
app.post("/add-sub-category", upload.array("image", 8), verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'add_d');

    if (value[0].check === "true") {
      const { name, cat_id } = req.body;
      const files = req.files;

      const existingSubCategory = await queryAsync("SELECT * FROM sub_category WHERE name = ?", [name]);

      if (existingSubCategory.length > 0) {
        if (files.length > 0) {

          deleteImage("img/" + files[0].filename);
        }
        return res.status(302).json({
          error: true,
          status: false,
          message: "Sub-Category name already exists."
        });
      }

      if (files.length === 0) {
        await queryAsync("INSERT INTO `sub_category`(`name`,`category_id`) VALUES (?,?)", [name, cat_id]);
      } else {
        await queryAsync("INSERT INTO `sub_category`(`name`,`category_id`,`image_url`) VALUES (?,?,?)", [name, cat_id, files[0].filename]);
      }

      res.status(200).json({
        error: false,
        status: true,
        message: "Sub-Category name added successfully."
      });

    } else {
      res.status(401).json({ error: true, status: false, message: "You are not authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/get-sub-category", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'view');
    if (value[0].check == "true") {
      const result = await queryAsync(
        "SELECT `id`,`name`,(select c.name from category as c WHERE c.id = `category_id`) as cat_name,image_url,`status`,`date` FROM `sub_category` WHERE 1"
      );
      res.status(200).json({
        error: false,
        status: true,
        data: result,
      });
    } else {
      res.status(401).json({
        error: true,
        status: false,
        message: "You Are Not Authorized!",
      });
    }
  } catch (err) {
    res.status(500).json({
      error: true,
      status: false,
      message: "Internal Server Error",
    });
  }
});
app.post("/status-sub-category", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'status_d');
    if (value[0].check == "true") {
      const result = await queryAsync(
        "UPDATE `sub_category` SET `status`= ? WHERE `id` = ?",
        [req.body.status, req.body.id]
      );
      res.status(200).send({
        error: false,
        status: true,
        message: "Status Changed Successfully.",
      });
    } else {
      res.status(401).json({
        error: true,
        status: false,
        message: "You Are Not Authorized!",
      });
    }
  } catch (err) {
    res.status(500).json({
      error: true,
      status: false,
      message: "Internal Server Error",
    });
  }
});
app.post("/update-sub-category", upload.array("image", 8), verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'update_d');
    if (value[0].check == "true") {
      if (req.files.length == 0) {
        try {
          const result = await queryAsync(
            "UPDATE `sub_category` SET `name` = ?,`category_id`=? WHERE `id` = ?",
            [req.body.name, req.body.cat_id, req.body.id]
          );
          res.status(200).json({
            error: false,
            status: true,
            message: "Sub-Category Updated Successfully."
          });
        } catch (err) {
          if (err.code == "ER_DUP_ENTRY") {
            res.status(302).json({
              error: true,
              status: false,
              message: "Sub-Category name already exists."
            });
          } else {
            throw err;
          }
        }
      } else {
        try {
          const result = await queryAsync(
            "UPDATE `sub_category` SET `name` = ?,`category_id`=?,`image_url`=? WHERE `id` = ?",
            [req.body.name, req.body.cat_id, req.files[0].filename, req.body.id]
          );
          deleteImage(`img/${req.body.old_image}`);
          res.status(200).json({
            error: false,
            status: true,
            message: "Sub-Category Updated Successfully."
          });
        } catch (err) {
          if (err.code == "ER_DUP_ENTRY") {
            deleteImage(`img/${req.files[0].filename}`);
            res.status(302).json({
              error: true,
              status: false,
              message: "Sub-Category name already exists."
            });
          } else {
            throw err;
          }
        }
      }
    } else {
      res.status(401).json({
        error: true,
        status: false,
        message: "You Are Not Authorized!"
      });
    }
  } catch (err) {
    res.status(500).json({ error: true, message: "Internal Server Error" });
  }
});
app.post('/update-task-details', verifytoken, async (req, res) => {
  try {
    const { url, type, platform, comment, date, id } = req.body;
    const result = await queryAsync(
      'UPDATE tasks_with_name SET task_url = ?, type = ?, platform_id = ?, comment_details = ?, date = ? WHERE id = ?',
      [url, type, platform, comment, date, id]
    );
    if (result.affectedRows > 0) {
      res.status(200).send({
        error: false,
        status: true,
        message: 'Updated Details Successfully',
      });
    } else {
      res.status(404).send({
        error: true,
        status: false,
        message: 'No record found or update failed',
      });
    }
  } catch (err) {
    res.status(500).send({
      error: true,
      status: false,
      message: 'Internal Server Error',
    });
  }
});

app.post('/add-video-task', vupload.single('video'), verifytoken, async (req, res) => {
  try {
    const videoPath = req.file.destination + '/' + req.file.filename;
    const { type, platform } = req.body;
    await queryAsync('INSERT INTO tasks_with_name (task_url, type, platform_id) VALUES (?, ?, ?)',
      [videoPath, type, platform]
    );
    res.status(200).send({
      error: false,
      status: true,
      message: 'Added Details Successfully'
    });
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});
app.post('/add-shopping-details', upload.single('s_image'), verifytoken, async (req, res) => {
  try {
    const { filename } = req.file;
    const { oprice, dprice } = req.body;
    const result = await queryAsync('INSERT INTO items (item_image, item_oprice, item_dprice) VALUES (?, ?, ?)',
      [filename, oprice, dprice]
    );
    res.status(200).send({
      error: false,
      status: true,
      message: 'Added Details Successfully',
    });
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});
app.post('/get-shopping-details', verifytoken, async (req, res) => {
  try {
    const results = await queryAsync('SELECT * FROM items');
    res.status(200).send({ error: false, status: true, data: results });
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});

app.post("/get-product", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'view');
    if (value[0].check === "true") {
      const result = await queryAsync(
        "SELECT `id`,`name`,(select c.name from `category` as c WHERE c.id = `category_id`) as 'category',`category_id` as 'cat_id',(select sc.name from `sub_category` as sc WHERE sc.id = `sub_category_id`) as 'sub_category',`sub_category_id` as 'sub_cat_id',`tags`,`colorDetails`,`date` FROM `product`"
      );
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
      res.status(200).json({
        error: false,
        status: true,
        data: transformedData
      });
    } else {
      res.status(401).json({
        error: true,
        status: false,
        message: "You Are Not Authorized!"
      });
    }
  } catch (error) {
    res.status(500).json({
      error: true,
      status: false,
      message: error.message
    });
  }
});
app.post("/update-product", upload.array("image"), verifytoken, async (req, res) => {
  // app.post("/update-product",  async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'update_d');
    if (value[0].check === "true") {
      let bodydata = [];
      if (Array.isArray(req.body.color)) {
        for (let index = 0; index < req.body.color.length; index++) {
          bodydata.push({
            color: req.body.color[index],
            image_url: req.body.imagessss[index],
            gender: req.body.gender[index],
            promoted: req.body.promoted[index],
            top_selling: req.body.top_selling[index],
            shipping_note: req.body.shipping_note[index],
            sizeDetails: req.body.sizeDetails[index],
            extra_info: req.body.extra_info[index],
            description: req.body.description[index]
          })
          if ((req.body.color.length - 1) == index) {
            const multipleadd = await queryAsync("UPDATE `product` SET `name`=?,`category_id`=?,`sub_category_id`=?,`tags`=?,`colorDetails`=? WHERE `id` = ?", [req.body.name, req.body.cat_id, req.body.sub_cat_id, req.body.tags, JSON.stringify(bodydata), req.body.id])
            if (multipleadd.affectedRows > 0) {
              return res.status(200).json({
                error: false,
                status: true,
                message: 'Updated Product SuccessFully'
              });
            } else {
              return res.status(500).json({
                error: true,
                status: false,
                message: 'Failed to add Product'
              });
            }
          }
        }
      } else {
        const singleadd = await queryAsync("INSERT INTO `product`(`name`, `category_id`, `sub_category_id`, `tags`, `colorDetails`) VALUES (?,?,?,?,?)", [req.body.name, req.body.cat_id, req.body.sub_cat_id, req.body.tags, JSON.stringify([{ color: req.body.color, image_url: JSON.stringify(array), gender: req.body.gender, promoted: req.body.promoted, top_selling: req.body.top_selling, shipping_note: req.body.shipping_note, sizeDetails: req.body.sizeDetails, extra_info: req.body.extra_info, description: req.body.description, count: false }])]);
        if (singleadd.affectedRows > 0) {
          return res.status(200).json({
            error: false,
            status: true,
            message: 'Product Added SuccessFully'
          });
        } else {
          return res.status(500).json({
            error: true,
            status: false,
            message: 'Failed to add Product'
          });
        }
      }
    } else {
      res.status(401).json({
        error: true,
        status: false,
        message: "You Are Not Authorized!"
      });
    }
  } catch (error) {
    res.status(500).json({
      error: true,
      status: false,
      message: error.message
    });
  }
});
app.post("/del-product", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'delete_d');
    if (value[0].check !== "true") {
      return res.status(401).json({
        error: true,
        status: false,
        message: "You Are Not Authorized!"
      });
    }
    const deleteCartResult = await queryAsync("DELETE FROM `add_to_cart` WHERE `product_id`=?", [req.body.id]);
    if (!deleteCartResult) {
      return res.status(500).json({ error: true, message: "Failed to delete from cart" });
    }
    const productResult = await queryAsync("SELECT * FROM `product` WHERE `id`=?", [req.body.id]);
    if (!productResult || productResult.length === 0) {
      return res.status(404).json({ error: true, message: "Product not found" });
    }
    const colorDetails = JSON.parse(productResult[0].colorDetails).map(detail => ({
      ...detail,
      image_url: JSON.parse(detail.image_url),
      sizeDetails: JSON.parse(detail.sizeDetails)
    }));
    for (const color of colorDetails) {
      for (const image of color.image_url) {
        deleteImage(`img/${image.url}`);
      }
    }
    const deleteProductResult = await queryAsync("DELETE FROM `product` WHERE `id`=?", [req.body.id]);
    if (!deleteProductResult) {
      return res.status(500).json({ error: true, message: "Failed to delete product" });
    }
    res.status(200).json({ error: false, status: true, message: "Deleted Product Successfully." });
  } catch (err) {
    res.status(500).json({ error: true, message: "Internal Server Error" });
  }
});
app.post("/add-product", upload.array("image"), verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'add_d');
    if (value[0].check === "true") {
      let array = [];
      let bodydata = [];
      let bodya = [];
      for (let i = 0; i < req.files.length; i++) {
        const e = req.files[i];
        array.push({
          url: e.filename
        })
      }
      if (Array.isArray(req.body.color)) {
        for (let index = 0; index < req.body.color.length; index++) {
          let subset = array.slice((index == 0 ? 0 : req.body.image_length[index - 1]), req.body.image_length[index]);
          for (let ab = 0; ab < subset.length; ab++) {
            const al = subset[ab];
            bodya.push({
              id: ab + 1,
              url: al.url
            })
          }
          bodydata.push({
            color: req.body.color[index],
            image_url: JSON.stringify(bodya),
            gender: req.body.gender[index],
            promoted: req.body.promoted[index],
            top_selling: req.body.top_selling[index],
            shipping_note: req.body.shipping_note[index],
            sizeDetails: req.body.sizeDetails[index],
            extra_info: req.body.extra_info[index],
            description: req.body.description[index]
          })
          bodya = [];
          if ((req.body.color.length - 1) == index) {
            const multipleadd = await queryAsync("INSERT INTO `product`(`name`, `category_id`, `sub_category_id`, `tags`, `colorDetails`) VALUES (?,?,?,?,?)", [req.body.name, req.body.cat_id, req.body.sub_cat_id, req.body.tags, JSON.stringify(bodydata)])
            if (multipleadd.affectedRows > 0) {
              return res.status(200).json({
                error: false,
                status: true,
                message: 'Product Added SuccessFully'
              });
            } else {
              return res.status(500).json({
                error: true,
                status: false,
                message: 'Failed to add Product'
              });
            }
          }
        }
      } else {
        const singleadd = await queryAsync("INSERT INTO `product`(`name`, `category_id`, `sub_category_id`, `tags`, `colorDetails`) VALUES (?,?,?,?,?)", [req.body.name, req.body.cat_id, req.body.sub_cat_id, req.body.tags, JSON.stringify([{ color: req.body.color, image_url: JSON.stringify(array), gender: req.body.gender, promoted: req.body.promoted, top_selling: req.body.top_selling, shipping_note: req.body.shipping_note, sizeDetails: req.body.sizeDetails, extra_info: req.body.extra_info, description: req.body.description, count: false }])]);
        if (singleadd.affectedRows > 0) {
          return res.status(200).json({
            error: false,
            status: true,
            message: 'Product Added SuccessFully'
          });
        } else {
          return res.status(500).json({
            error: true,
            status: false,
            message: 'Failed to add Product'
          });
        }
      }
    } else {
      res.status(401).json({
        error: true,
        status: false,
        message: "You Are Not Authorized!"
      });
    }
  } catch (error) {
    res.status(500).json({
      error: true,
      status: false,
      message: error.message
    });
  }
});

app.post("/add-promoted", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'add_d');
    if (value[0].check === "true") {
      const del = await queryAsync("DELETE FROM `promoted_sub-cat`");
      if (del)
        for (let index = 0; index < req.body.sub_cat.length; index++) {
          const e = req.body.sub_cat[index];
          await queryAsync("INSERT INTO `promoted_sub-cat`(`name`, `sub_cat`) VALUES (?,?)", [req.body.name, e])
          if ((req.body.sub_cat.length - 1) == index) {
            res.status(200).json({ error: false, status: true, message: 'Added Promoted' })
          }
        }
    } else {
      res.status(401).json({
        error: true,
        status: false,
        message: "You Are Not Authorized!"
      });
    }
  } catch (error) {
    res.status(500).json({
      error: true,
      status: false,
      message: error.message
    });
  }
});
app.post("/get-promoted", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'view');
    if (value[0].check === "true") {
      const result = await queryAsync(
        "SELECT ps.id as pid,ps.sub_cat as id,sc.name,ps.name as promoted_name,ps.status,ps.date FROM `promoted_sub-cat` as ps INNER join sub_category as sc on ps.sub_cat = sc.id where  ps.name = 'Sub-Category'"
      );
      res.status(200).json({
        error: false,
        status: true,
        data: result
      });
    } else {
      res.status(401).json({
        error: true,
        status: false,
        message: "You Are Not Authorized!"
      });
    }
  } catch (error) {
    res.status(500).json({
      error: true,
      status: false,
      message: error.message
    });
  }
});
app.post("/del-promoted", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'delete_d');
    if (value[0].check === "true") {
      const result = await queryAsync("DELETE FROM `promoted_sub-cat` WHERE `id` = ?", [req.body.id]);
      if (result) {
        res.status(200).json({ error: false, status: true, message: "Promoted Deleted SuccessFully." });
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/status-promoted", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'status_d');
    if (value[0].check == "true") {
      const result = await queryAsync(
        "UPDATE `promoted_sub-cat` SET `status`=? WHERE `id`= ?",
        [req.body.status, req.body.id]
      );
      if (result)
        res.status(200).send({
          error: false,
          status: true,
          message: "Status Changed Successfully.",
        });
    } else {
      res.status(401).json({
        error: true,
        status: false,
        message: "You Are Not Authorized!",
      });
    }
  } catch (err) {
    res.status(500).json({
      error: true,
      status: false,
      message: "Internal Server Error",
    });
  }
});

app.post("/add-banner", upload.array("image", 8), verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'add_d');
    if (value[0].check === "true") {
      const { name } = req.body;
      await queryAsync("INSERT INTO `banner`(`banner_name`, `Image_url`) VALUES (?,?)", [name, req.files[0].filename]);
      res.status(200).json({
        error: false,
        status: true,
        message: `Added ${name} successfully.`
      });

    } else {
      res.status(401).json({ error: true, status: false, message: "You are not authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/get-banner", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'view');
    if (value[0].check == "true") {
      const result = await queryAsync(
        "SELECT `id`,`banner_name` as name,image_url,`status`,`date` FROM `banner`"
      );
      res.status(200).json({
        error: false,
        status: true,
        data: result,
      });
    } else {
      res.status(401).json({
        error: true,
        status: false,
        message: "You Are Not Authorized!",
      });
    }
  } catch (err) {
    res.status(500).json({
      error: true,
      status: false,
      message: "Internal Server Error",
    });
  }
});
app.post("/update-banner", upload.array("image", 1), verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'update_d');
    if (value[0].check == "true") {
      if (req.files.length == 0) {
        const result = await queryAsync(
          "UPDATE `banner` SET `banner_name` = ? WHERE `id` = ?",
          [req.body.name, req.body.id]
        );
        if (result)
          res.status(200).json({
            error: false,
            status: true,
            message: "Updated Banner Details Successfully."
          });

      } else {
        const result = await queryAsync(
          "UPDATE `banner` SET `banner_name` = ?,`image_url`=? WHERE `id` = ?",
          [req.body.name, req.files[0].filename, req.body.id]
        );
        if (result)
          deleteImage("img/" + req.body.old_image);
        res.status(200).json({
          error: false,
          status: true,
          message: "Updated Banner Details Successfully."
        });
      }
    } else {
      res.status(401).json({
        error: true,
        status: false,
        message: "You Are Not Authorized!"
      });
    }
  } catch (err) {
    res.status(500).json({ error: true, message: "Internal Server Error" });
  }
});
app.post("/del-banner", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'delete_d');
    if (value[0].check === "true") {
      const result = await queryAsync("DELETE FROM `banner` WHERE `id` = ?", [req.body.id]);
      if (result) {
        res.status(200).json({ error: false, status: true, message: "Banner Deleted SuccessFully." });
      }
    } else {
      res.status(401).json({ error: true, status: false, message: "You Are Not Authorized!" });
    }
  } catch (error) {
    res.status(500).send({ error: true, status: false, message: 'Internal Server Error' });
  }
});
app.post("/status-banner", verifytoken, async (req, res) => {
  try {
    const value = await getRoleCheck(req.body.username, 'status_d');
    if (value[0].check == "true") {
      const result = await queryAsync(
        "UPDATE `banner` SET `status`=? WHERE `id`= ?",
        [req.body.status, req.body.id]
      );
      if (result)
        res.status(200).send({
          error: false,
          status: true,
          message: "Status Changed Successfully.",
        });
    } else {
      res.status(401).json({
        error: true,
        status: false,
        message: "You Are Not Authorized!",
      });
    }
  } catch (err) {
    res.status(500).json({
      error: true,
      status: false,
      message: "Internal Server Error",
    });
  }
});
app.get("/routes", (req, res) => {
  res.json([
    { path: '', redirectTo: 'home', pathMatch: 'full' },
    { path: 'login', component: 'LoginComponent' },
    {
      path: 'home', component: 'HomeComponent', canActivate: ['AdminGuard'],
      children: [
        { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
        { path: 'role', component: 'RollsComponent' },
        { path: 'dashboard', component: 'DashboardComponent' },
        { path: 'module', component: 'ModuleComponent' },
        { path: 'activity-mapping', component: 'ActivityMappingComponent' },
        { path: 'user-details', component: 'UserDetailsComponent' },
        { path: 'sub-admin', component: 'SubAdminComponent' },
        { path: 'contact-details', component: 'ContactDetailsComponent' },
        { path: 'pages', component: 'PagesComponent' },
        { path: 'website', component: 'WebsiteComponent' },
        { path: 'category', component: 'CategoryComponent' },
        { path: 'sub-category', component: 'SubCategoryComponent' },
        { path: 'product', component: 'ProductComponent' },
        { path: 'psub-cat', component: 'PromotedSubCatComponent' },
        { path: 'banner', component: 'BannerComponent' },
        { path: 'offer', component: 'OfferComponent' },
      ]
    },
    { path: 'refresh', component: 'RefreshComponent' },
    { path: '**', component: 'PnfComponent' },
  ]);
});
async function verifytoken(req, res, next) {
  const bearerHeader = req.headers["authorization"];
  if (typeof bearerHeader !== "undefined") {
    const bearer = bearerHeader.split(" ");
    const bearerToken = bearer[1];
    req.token = bearerToken;
    try {
      let auth = jwt.verify(req.token, SECRET_KEY_ADMIN);
      if (auth.username != req.body.username) {
        res.status(403).send("false");
      } else {
        next();
      }
    } catch (err) {
      try {
        let auth = jwt.verify(req.token, SECRET_KEY_SUPERADMIN);
        if (auth.username != req.body.username) {
          res.status(403).send("false");
        } else {
          next();
        }
      } catch (err) {
        res.status(403).send('Token Invaild');
      }
    }
  } else {
    res.sendStatus(403);
  }
};
function agent(amount, user) {
  const percentage2 = ((5 / 100) * parseFloat(amount)).toFixed(2);
  const percentage3 = ((3 / 100) * parseFloat(amount)).toFixed(2);
  const percentage4 = ((2 / 100) * parseFloat(amount)).toFixed(2);
  const percentage5 = ((2 / 100) * parseFloat(amount)).toFixed(2);
  const percentage6 = ((1 / 100) * parseFloat(amount)).toFixed(2);
  const percentage7 = ((1 / 100) * parseFloat(amount)).toFixed(2);
  con.query("SELECT `reffer_code` as rc FROM `user_details` WHERE `user_name` = ?", [user], (err, result) => {
    if (err) throw err;
    if (result) {
      con.query("SELECT * FROM `user_level` WHERE `user_reffral` = ?", [result[0].rc], (err, level1) => {
        if (err) throw err;
        if (level1[0].level_1) {
          con.query("UPDATE `wallet` SET `agents_wallet` = `agents_wallet` + ? WHERE `user_name` = (SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?)", [percentage2, level1[0].level_1]);
          con.query("INSERT INTO `agents_statement`(`mobile`, `amount`, `discription`) VALUES ((SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?), ?, ?)", [level1[0].level_1, percentage2, 'Level 1']);
          if (level1[0].level_2 != null) {
            con.query("UPDATE `wallet` SET `agents_wallet` = `agents_wallet` + ? WHERE `user_name` = (SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?)", [percentage3, level1[0].level_2]);
            con.query("INSERT INTO `agents_statement`(`mobile`, `amount`, `discription`) VALUES ((SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?), ?, ?)", [level1[0].level_2, percentage3, 'Level 2']);
            if (level1[0].level_3 != null) {
              con.query("UPDATE `wallet` SET `agents_wallet` = `agents_wallet` + ? WHERE `user_name` = (SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?)", [percentage4, level1[0].level_3]);
              con.query("INSERT INTO `agents_statement`(`mobile`, `amount`, `discription`) VALUES ((SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?), ?, ?)", [level1[0].level_3, percentage4, 'Level 3']);
              if (level1[0].level_4 != null) {
                con.query("UPDATE `wallet` SET `agents_wallet` = `agents_wallet` + ? WHERE `user_name` = (SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?)", [percentage5, level1[0].level_4]);
                con.query("INSERT INTO `agents_statement`(`mobile`, `amount`, `discription`) VALUES ((SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?), ?, ?)", [level1[0].level_4, percentage5, 'Level 4']);
                if (level1[0].level_5 != null) {
                  con.query("UPDATE `wallet` SET `agents_wallet` = `agents_wallet` + ? WHERE `user_name` = (SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?)", [percentage6, level1[0].level_5]);
                  con.query("INSERT INTO `agents_statement`(`mobile`, `amount`, `discription`) VALUES ((SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?), ?, ?)", [level1[0].level_5, percentage6, 'Level 5']);
                  if (level1[0].level_6 != null) {
                    con.query("UPDATE `wallet` SET `agents_wallet` = `agents_wallet` + ? WHERE `user_name` = (SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?)", [percentage7, level1[0].level_6]);
                    con.query("INSERT INTO `agents_statement`(`mobile`, `amount`, `discription`) VALUES ((SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?), ?, ?)", [level1[0].level_6, percentage7, 'Level 6']);
                  } else {
                    con.query("UPDATE `wallet` SET `agents_wallet` = `agents_wallet` + ? WHERE `user_name` = (SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?)", [((parseFloat(amount)) - percentage7).toFixed(2), level1[0].level_1]);
                    con.query("INSERT INTO `agents_statement`(`mobile`, `amount`, `discription`) VALUES ((SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?), ?, ?)", [level1[0].level_1, ((parseFloat(amount)) - percentage7).toFixed(2), 'Level 1']);
                  }
                } else {
                  con.query("UPDATE `wallet` SET `agents_wallet` = `agents_wallet` + ? WHERE `user_name` = (SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?)", [((parseFloat(amount)) - percentage6).toFixed(2), level1[0].level_1]);
                  con.query("INSERT INTO `agents_statement`(`mobile`, `amount`, `discription`) VALUES ((SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?), ?, ?)", [level1[0].level_1, ((parseFloat(amount)) - percentage6).toFixed(2), 'Level 1']);
                }
              } else {
                con.query("UPDATE `wallet` SET `agents_wallet` = `agents_wallet` + ? WHERE `user_name` = (SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?)", [((parseFloat(amount)) - percentage5).toFixed(2), level1[0].level_1]);
                con.query("INSERT INTO `agents_statement`(`mobile`, `amount`, `discription`) VALUES ((SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?), ?, ?)", [level1[0].level_1, ((parseFloat(amount)) - percentage5).toFixed(2), 'Level 1']);
              }
            } else {
              con.query("UPDATE `wallet` SET `agents_wallet` = `agents_wallet` + ? WHERE `user_name` = (SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?)", [((parseFloat(amount)) - percentage4).toFixed(2), level1[0].level_1]);
              con.query("INSERT INTO `agents_statement`(`mobile`, `amount`, `discription`) VALUES ((SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?), ?, ?)", [level1[0].level_1, ((parseFloat(amount)) - percentage4).toFixed(2), 'Level 1']);
            }
          } else {
            con.query("UPDATE `wallet` SET `agents_wallet` = `agents_wallet` + ? WHERE `user_name` = (SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?)", [((parseFloat(amount)) - percentage3).toFixed(2), level1[0].level_1]);
            con.query("INSERT INTO `agents_statement`(`mobile`, `amount`, `discription`) VALUES ((SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?), ?, ?)", [level1[0].level_1, ((parseFloat(amount)) - percentage3).toFixed(2), 'Level 1']);
          }
        } else {
          con.query("UPDATE `wallet` SET `agents_wallet` = `agents_wallet` + ? WHERE `user_name` = (SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?)", [((parseFloat(amount)) - percentage2).toFixed(2), level1[0].level_1]);
          con.query("INSERT INTO `agents_statement`(`mobile`, `amount`, `discription`) VALUES ((SELECT `user_name` FROM `user_details` WHERE `reffer_code` = ?), ?, ?)", [level1[0].level_1, ((parseFloat(amount)) - percentage2).toFixed(2), 'Level 1']);
        }
      })
    }
  })
};
const getRoleCheck = async (username, checkField) => {
  return new Promise((resolve, reject) => {
    con.query(`SELECT r.${checkField} as 'check' FROM role as r WHERE r.id = (SELECT ra.role_id FROM role_assign as ra WHERE ra.user_id = (SELECT lo.id FROM login as lo WHERE lo.username = ?))`,
      [username], (err, results) => {
        if (err) {
          reject(err);
        } else {
          resolve(results);
        }
      });
  });
};
function queryAsync(query, params) {
  return new Promise((resolve, reject) => {
    con.query(query, params, (error, results) => {
      if (error) {
        return reject(error);
      }
      resolve(results);
    });
  });
};
function deleteImage(relativeImagePath) {
  const imagePath = path.resolve(__dirname, '../../assets', relativeImagePath);
  fs.access(imagePath, fs.constants.F_OK, (err) => {
    if (err) {
      return;
    }
    fs.unlink(imagePath, (err) => {
      if (err) {
        return;
      }
    });
  });
};
module.exports = app;