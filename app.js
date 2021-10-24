const express = require('express')
const path =require('path')
const cors = require('cors')
const bcrptjs = require('bcryptjs')
const mongoose=require('mongoose')
const jwt = require('jsonwebtoken')
const User = require('./model/user')
const JWT_SECRET='djkjfkjlajijdtjiusudifjfa fjkfdjkjfsdajdjfafj'
mongoose.connect('mongodb+srv://mimlal:mimlal1@cluster0.nhbiv.mongodb.net/userlogin1?retryWrites=true&w=majority',{
    useNewUrlParser:true,
    useUnifiedTopology:true
})
const port = process.env.PORT || 3000

const app = express()
app.use(cors())

app.use('/',express.static(path.join(__dirname,'static')))
app.use(express.urlencoded({extended:true}))
app.use(express.json())


app.post('/api/change-password',async (req,res)=>{
    const {token,newpassword:plainTextPassword}=req.body
  
    if(!plainTextPassword || typeof plainTextPassword !=='string'){
        return res.json ({status:'error',error:'Invalid username'})
    }
    if(plainTextPassword.length < 5){
        return res.json({
            status:'error',
            error:'password is too small,must be aleast 8 character'
        })
    }
    try{
        const user = jwt.verify(token,JWT_SECRET)
        const _id = user.id
        const password = await bcrptjs.hash(plainTextPassword,10)
        await User.updateOne({_id},
            {
               $set:{password} 
        })

    }catch(error){
        res.json({status:'error',error:'invalid password'})
    }
    res.json({status:'ok'})



})

app.post('/api/login',async (req,res)=>{
    const {username,password}=req.body
    const user =await User.findOne({username}).lean()
    if(!user){
        return res.json({status:'error',error:'invalid username/password'})
    }
    if(await bcrptjs.compare(password,user.password)){
        const token = jwt.sign({
            id:user._id,
            username:user.username
        },JWT_SECRET)
        return res.json({status:'ok',data:token})
    }
    res.json({status:'error',error:'invalid username/password'})
})




app.post('/api/register',async(req,res)=>{
     const{username,password:plainTextPassword}=req.body;
     if(!username || typeof username !=='string'){
         return res.json ({status:'error',error:'Invalid username'})
     }
     if(!plainTextPassword || typeof plainTextPassword !=='string'){
         return res.json ({status:'error',error:'Invalid username'})
     }
     if(plainTextPassword.length < 5){
         return res.json({
             status:'error',
             error:'password is too small,must be aleast 8 character'
         })
     }
    //  hashing password
    const password = await bcrptjs.hash(plainTextPassword,10)
      try{
       const response = await User.create({
            username,
            password
        })
        console.log("user created successfully",response)
      }catch(error){
          if(error.code === 11000){
              return res.json({status:'error',error:'Username is already exits'})
          }
          throw error
     }
    res.json({status:'ok'})
  
})

app.listen(port,()=>{
    console.log(`server is running at ${port}`)
})