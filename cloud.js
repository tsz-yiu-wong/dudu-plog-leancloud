const AV = require('leanengine')
const fs = require('fs')
const path = require('path')

/**
 * Loads all cloud functions under the `functions` directory.
 */
fs.readdirSync(path.join(__dirname, 'functions')).forEach( file => {
  require(path.join(__dirname, 'functions', file))
})

/**
 * A simple cloud function.
 */
AV.Cloud.define('hello', function(request) {
  return 'Hello world!'
})

// 用户注册
AV.Cloud.define('register', async (request) => {
  const { username, password } = request.params;
  const user = new AV.User();
  user.setUsername(username);
  user.setPassword(password);
  try {
    await user.signUp();
    return { success: true };
  } catch (error) {
    throw error;
  }
});

// 用户登录状态检查中间件
function requireAuth(req, res, next) {
  if (!req.currentUser) {
    res.redirect('/login');
  } else {
    next();
  }
}

module.exports = { requireAuth };
