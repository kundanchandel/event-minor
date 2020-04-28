const express   =require('express'),
      bodyParser=require('body-parser'),
      mongoose  =require('mongoose'),
      cors      =require('cors'),
      dotenv    =require('dotenv'),
      app       =express();
 

app.use(bodyParser.urlencoded({extended: true}));
 //middleware     
dotenv.config();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('./public'));


//db coonection
//const db_uri=process.env.MONGO_URI;

mongoose.connect('mongodb://localhost/event01',{
    useNewUrlParser:true,
    useCreateIndex:true
}).then(()=>{
    console.log("Database Connected ...")}).catch((err)=>{
        console.log(err);
    });


//API 
app.use('/api/events/',require('./routes/api/events'));
app.use('/api/user/',require('./routes/api/user'));

//server config
const port=process.env.PORT||5000;
app.listen(port, () => {
    console.log(`server listening on port ${port}`);
});
