const config = require('config');
const Koa = require('koa');
const cors = require('@koa/cors');
const Routes = require('./routes/auth.routes');

const PORT = config.get('PORT') || 3000;

const app = new Koa();
const httpServer = require('http').createServer(app.callback());

let options = {
  origin: false,
  credentials: true,
};
app.use(cors(options));
app.use(Routes.routes()).use(Routes.allowedMethods());

httpServer.listen(PORT, () => {
  console.log('Application is starting on port ' + PORT);
});
