const config = require('config');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const randToken = require('rand-token');
const koaBody = require('koa-body');
const Joi = require('joi');
const Router = require('koa-router');

const User = require('../models/User');

const router = new Router();

router
  .post('/api/user/auth', koaBody(), async (ctx) => {
    ctx.body = JSON.parse(JSON.stringify(ctx.request.body));

    const schema = Joi.object().keys({
      email: Joi.string().email().required().messages({
        'string.email': 'Пожалуйста, введите действительный адрес электронной почты',
      }),
      password: Joi.string().min(3).required().messages({
        'string.min': 'Минимальная длина пароля {#limit} символа',
      }),
    });
    const result = schema.validate(ctx.body);
    const { error } = result;
    const valid = error == null;

    try {
      if (!valid) {
        ctx.body = {
          errors: error.message,
          message: 'Некорректные данные при входе в систему',
        };
        ctx.status = 401;
        return;
      }
      const { email, password } = ctx.body;

      const user = await User.findOne({ email });
      if (!user) {
        ctx.body = { message: 'Пользователь не найден' };
        ctx.status = 401;
        return;
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        ctx.body = { message: 'Неверный пароль, попробуйте снова' };
        ctx.status = 401;
        return;
      }

      const token = jwt.sign(
        {
          id: user.id,
        },
        config.get('jwtSecret'),
        { expiresIn: '1h' }
      );
      const refreshToken = {
        token: randToken.generate(36),
        expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // TODO: UTC+3 учесть и сконвертировать в дальнейшем
      };
      User.updateOne(
        {
          _id: user.id,
        },
        {
          $set: {
            token: refreshToken.token,
            expired_at: refreshToken.expires,
            updated_at: Date.now(),
          },
        },
        { upsert: false },
        function (err, user) {}
      );

      ctx.cookies.set('refreshToken', refreshToken.token, {
        httpOnly: true,
        expires: refreshToken.expires,
        //secure: true,//TODO: включить при использовании ssl-сертификата
      });
      ctx.body = {
        token: token,
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          name: user.name,
          last_name: user.last_name,
          position: user.position,
        },
      };
      ctx.status = 200;
    } catch (e) {
      ctx.body = { message: 'Что-то пошло не так, попробуйте снова' };
      ctx.status = 400;
    }
  })
  .get('/api/user/profile', async (ctx) => {
    let token = ctx.headers['x-access-token'] || ctx.headers['authorization'];

    if (token.startsWith('Bearer ')) {
      token = token.replace(/^Bearer\s/, '');
    }

    try {
      const decoded = jwt.verify(token, config.get('jwtSecret'));
      const user = await User.findById(decoded.id);

      if (!user) {
        ctx.body = {
          message: 'Пользователь не найден',
        };
        ctx.status = 401;
        return;
      }
      ctx.body = {
        id: user.id,
        email: user.email,
        role: user.role,
        name: user.name,
        last_name: user.last_name,
        position: user.position,
      };
      ctx.status = 200;
    } catch (err) {
      ctx.body = err;
      ctx.status = 403;
    }
  })
  .get('/api/user/:id', async (ctx) => {
    const id = ctx.params.id;
    let token = ctx.headers['x-access-token'] || ctx.headers['authorization'];

    if (token.startsWith('Bearer ')) {
      token = token.replace(/^Bearer\s/, '');
    }

    try {
      jwt.verify(token, config.get('jwtSecret'));
      const user = await User.findById(id);

      if (!user) {
        ctx.body = {
          message: 'Пользователь не найден',
        };
        ctx.status = 401;
        return;
      }
      ctx.body = {
        id: user.id,
        email: user.email,
        role: user.role,
        name: user.name,
        last_name: user.last_name,
        position: user.position,
      };
      ctx.status = 200;
    } catch (err) {
      ctx.body = err;
      ctx.status = 403;
    }
  })
  .post('/api/user/logout', async (ctx) => {
    ctx.cookies.set('refreshToken', '', { httpOnly: true });
    ctx.status = 200;
  })
  // https://gist.github.com/zmts/802dc9c3510d79fd40f9dc38a12bccfc/339778999d35a9c81f115a3755ea3035681f2702
  // https://stackoverflow.com/questions/52617942/how-to-use-a-jwt-refresh-token-to-generate-a-new-access-token
  // https://www.google.com/search?rlz=1C1SQJL_ruRU775RU775&ei=0HuJX_6qLvKFrwSxmqS4Ag&q=jsonwebtoken+refresh+&oq=jsonwebtoken+refresh+&gs_lcp=CgZwc3ktYWIQAzIECAAQQzIGCAAQFhAeMgYIABAWEB4yBggAEBYQHjIGCAAQFhAeMgYIABAWEB4yBggAEBYQHjoECAAQR1DVjipY1Y4qYOaPKmgAcAV4AIABXIgBXJIBATGYAQCgAQGqAQdnd3Mtd2l6yAEIwAEB&sclient=psy-ab&ved=0ahUKEwj-0pis-bjsAhXywosKHTENCScQ4dUDCA0&uact=5
  .post('/api/user/refresh-token', async (ctx) => {
    let refreshToken = ctx.cookies.get('refreshToken');

    if (!refreshToken) {
      ctx.body = { message: 'Токен не найден' };
      ctx.status = 401;
      return;
    }

    const user = await User.findOne({ token: refreshToken });
    if (!user) {
      ctx.body = { message: 'Пользователь не найден' };
      ctx.status = 401;
      return;
    }

    const token = jwt.sign(
      {
        id: user.id,
      },
      config.get('jwtSecret'),
      { expiresIn: '1h' }
    );

    refreshToken = {
      token: randToken.generate(36),
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // TODO: UTC+3 учесть и сконвертировать в дальнейшем
    };
    User.updateOne(
      {
        _id: user.id,
      },
      {
        $set: {
          token: refreshToken.token,
          expired_at: refreshToken.expires,
          updated_at: Date.now(),
        },
      },
      { upsert: false },
      function (err, user) {}
    );

    ctx.cookies.set('refreshToken', refreshToken.token, {
      httpOnly: true,
      expires: refreshToken.expires,
      //secure: true,//TODO: включить при использовании ssl-сертификата
    });

    ctx.body = {
      token: token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        name: user.name,
        last_name: user.last_name,
        position: user.position,
      },
    };
    ctx.status = 200;
  });

module.exports = router;
