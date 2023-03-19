const mongoose = require('mongoose');


const dbConnect = async()=>{
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('Connected to mongoDB');
    } catch (error) {
        console.error(error.message);
        process.exit(1);
    }
}

module.exports = dbConnect