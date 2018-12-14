const express = require('express');
const router = express.Router();
const mongoClient = require("mongodb").MongoClient;
const event = require("events");
const fs = require("fs");

const jwt = require("jwt-simple");


// nodejs 加密模块;
const crypto = require('crypto');

class MyEvent extends event{};
const me = new MyEvent();


// 加密; (加密的明文, 秘钥);
let Encrypt = (data, key) => {
    const cipher = crypto.createCipher('aes192', key);
    var crypted = cipher.update(data, 'utf8', 'hex');
    crypted += cipher.final('hex');
    return crypted;
}
// 解密密; (加密后的密文, 秘钥);
let Decrypt = (encrypted, key) => {
    const decipher = crypto.createDecipher('aes192', key);
    var decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}



// 事件函数的绑定;
// me.on("hello",(e)=>{
//   console.log("hello",e);
// })
// 事件参数的传递;
// me.emit("hello",{a:10})

let url = "mongodb://localhost:27017";
let dbName = "users";

router.post('/:type', dis , login);
router.post('/:type', (req,res,next)=>{
  // res.send(req.cookies);
    let secret =  fs.readFileSync("./server.pem");
    let token = req.cookies["USER.ID"];

    if(!token) return res.send({status:"error",statuCode : 0});

    let payload = jwt.decode(token,secret);
    // console.log(payload);
    //tocken 过期;
    if(payload.exp <= Date.now()){
      res.clearCookie("USER.ID");
      res.send({status:"error",statuCode : 0});
    }else{
      res.send(Object.assign(payload,{status:"success",statuCode : 0}));
    }
});


// 分配需求;
function dis(req , res , next){


  if(req.params.type == "login") return next();
  // 注册逻辑;
  if(req.params.type != "register") return next("route");

  // res.send("欢迎注册");
  const body = req.body;
  let usr = body.username;
  let pwd = body.password;
  // 1. 用户名重复查询;
  const params = {
     usr : usr,
     pwd : pwd,
     req : req,
     res : res
  }
  // console.log(params);
  me.emit("searchUsers",params);
}
me.on("searchUsers" , (e) =>{
    mongoClient.connect(url , (err , client)=>{
        if(err)  return e.res.send(err+":"+"数据库错误");
        //选中数据库;
        const db = client.db(dbName);
        //选中collection
        const collection = db.collection("user_collection");  
        //查询;
        collection.find({username : e.usr}).toArray( (err , data) => {
          //通过数组数量的判断决定是否重名;
          if(data.length == 0){
            //没有重复用户名;
            // e.res.send("没有重复用户名");
            // 把用户名密码放入到 数据库之中;
            me.emit("insertUser",Object.assign(e,{collection:collection,client:client}));
          }else{
            //用户名重复;
            e.res.send("用户名重复");
            client.close();
          }
        })
    })
}) 
me.on("insertUser" , (e)=> {
    // e.res.send("hello world");
    let pemKey = fs.readFileSync("./server.pem");
    var cryPwd = Encrypt(e.pwd , pemKey);
    // console.log("密文"+cryPwd,"解密"+pwd);
    e.collection.insert({
        username : e.usr,
        password : cryPwd,
        admin : true
    })
    //关闭数据库连接;
    e.client.close();
    e.res.json({
      type:"register",
      statu :"success"
    })
})

// // 登陆逻辑;
function login(req , res , next){
  const body = req.body;
  let usr = body.username;
  let pwd = body.password;

  let vaildePromise = valideUser(usr,pwd) // promise ;

  vaildePromise.then((user)=>{
    // 登陆成功;
    // 加密并设置tocken;
    let secret =  fs.readFileSync("./server.pem");
    let payload = {
      username : user.username ,
      admin : user.admin,
      exp : Date.now() + 1000 * 60 * 60 * 2
    }
    let token = jwt.encode(payload,secret);

    res.cookie("USER.ID",token);

    res.send(Object.assign(user,{status : "success" , statuCode : 1}));
  },(err)=>{
    // res.send(err)
    if(err == 1){
      res.send({status : "error" , statuCode : 5})
    }else if(err == 2){
      res.send({status : "error" , statuCode : 4});
    }else{
      res.send({status : "error" , statuCode : 3});
    }
  })
}
function valideUser(usr,pwd){
  // 加密密码;
  let pemKey = fs.readFileSync("./server.pem");
  var cryPwd = Encrypt(pwd , pemKey);

  return new Promise((resolve , reject)=>{
    // 连接数据库;
    mongoClient.connect(url , (err , client)=>{
      if(err) return reject("服务器连接错误");
      // 连接数据库;
      const db = client.db(dbName);
      // 连接数集合;
      const collection = db.collection("user_collection");
      // 查询用户名;
      collection.find({username : usr}).toArray((err,data)=>{
        if(err) return reject("数据解析错误");
        if(data.length == 0) return reject(1);

        let valide = false;
       
        // 比对密码;
        data.forEach((user,index)=>{
          console.log(user.password,cryPwd)
          if(user.password == cryPwd){
            valide = true;
            resolve(user);
          }
        })
        if(!valide){
          reject(2)
        }
      })

    })
  })
}

module.exports = router;

// XXXXXXX.XXXXXXX.XXXXXXX