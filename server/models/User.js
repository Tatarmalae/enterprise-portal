const mongoose = require('mongoose');
const { Schema, model, Types } = require('mongoose');
const config = require('config');
const logger = require('../errorHandler');

mongoose.connect(
  config.get('mongoUri'),
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true,
  },
  async (err) => {
    if (err) await logger.logError(err);
  }
);

const schema = new Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String },
  token: { type: String },
  expired_at: { type: Date },
  created_at: { type: Date, default: Date.now() },
  updated_at: { type: Date, default: Date.now() },
  name: { type: String },
  last_name: { type: String },
  position: { type: String },
  links: [{ type: Types.ObjectId, ref: 'Link' }],
});

module.exports = model('User', schema);
