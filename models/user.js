const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs')

delete mongoose.connection.models['user'];

const userSchema = new Schema({
  email: { type:String, unique: true, lowercase: true },
  password: String,
});

userSchema.pre('save', function(next){
  const user = this;
  bcrypt.genSalt(10, function(error, salt) {
    if (error) {
      return next(error)
    }
    bcrypt.hash(user.password, salt, null, function(error, hash) {
      if (error) {
        return next(error)
      }
      user.password = hash;
      next();
    })
  })
});

//instance method for password comparison between saved/hashed password
//and newly inputted candidatePassword
userSchema.methods.comparePasswords = function(candidatePassword, callback) {
  bcrypt.compare(candidatePassword, this.password, function(error, isMatch){
    if (error) {
      return callback(error)
    };
    callback(null, isMatch)
  });
};

const ModelClass = mongoose.model('user', userSchema);

module.exports = ModelClass;