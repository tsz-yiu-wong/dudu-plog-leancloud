'use strict'

const express = require('express')
const AV = require('leanengine')
const path = require('path')
const multer = require('multer')
const session = require('express-session')
const bodyParser = require('body-parser')
const { requireAuth } = require('./cloud')

const app = express()

// 静态文件服务
app.use(express.static(path.join(__dirname, 'public')))

// 配置模板引擎
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

// 使用 body-parser 解析请求体
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

// 配置 session（使用内存存储）
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true
}))

// 将 currentUser 添加到所有路由
app.use(async (req, res, next) => {
  const sessionToken = req.session.sessionToken
  if (sessionToken) {
    try {
      req.currentUser = await AV.User.become(sessionToken)
      res.locals.currentUser = req.currentUser
    } catch (error) {
      // session token 无效
      delete req.session.sessionToken
    }
  }
  next()
})


// 文件上传配置
const storage = multer.memoryStorage()
const upload = multer({ storage: storage })

// 主页
app.get('/', (req, res) => {
  if (req.currentUser) {
    res.redirect('/album-list')
  } else {
    res.render('login')
  }
})

app.get('/login', (req, res) => {
  if (req.currentUser) {
    res.redirect('/album-list')
  } else {
    res.render('login')
  }
})

app.post('/login', async (req, res) => {
  try {
    const user = await AV.User.logIn(req.body.username, req.body.password)
    req.session.sessionToken = user.getSessionToken()
    res.redirect('/album-list')
  } catch (error) {
    res.render('login', { error: error.message })
  }
})

app.get('/register', (req, res) => {
  if (req.currentUser) {
    res.redirect('/album-list')
  } else {
    res.render('register')
  }
})

app.post('/register', async (req, res) => {
  const { username, password, confirmPassword, registerKey } = req.body
  
  // 验证注册码
  if (!isValidRegisterKey(registerKey)) {
    return res.render('register', { 
      error: '无效的注册码' 
    })
  }

  // 验证两次输入的密码是否一致
  if (password !== confirmPassword) {
    return res.render('register', { 
      error: '两次输入的密码不一致' 
    })
  }

  try {
    // 创建新用户
    const user = new AV.User()
    user.setUsername(username)
    user.setPassword(password)
    await user.signUp()
    
    // 注册成功后自动登录
    req.session.sessionToken = user.getSessionToken()
    res.redirect('/album-list')
  } catch (error) {
    // 处理用户名已存在等错误
    res.render('register', { 
      error: error.message || '注册失败，请稍后重试' 
    })
  }
})

function isValidRegisterKey(key) {
  // TODO: 实现真实的注册码验证逻辑
  return false
}

app.get('/logout', (req, res) => {
  req.session.destroy()
  res.redirect('/?logout=true')
})


// 相册列表
app.get('/album-list', requireAuth, async (req, res) => {
  const query = new AV.Query('Album')
    .include('cover')
    .ascending('index')
  const albums = await query.find()
  res.render('album-list', { albums })
})

app.post('/album-list', requireAuth, async (req, res) => {
  const { title, description, isPublic } = req.body
  
  // 检查用户是否有权限创建相册
  const roles = await req.currentUser.getRoles()
  const canCreate = roles.some(role => 
    role.getName() === 'admin' || role.getName() === 'vip'
  )
  if (!canCreate) {
    return res.status(403).send('没有权限创建相册')
  }

  // 创建相册
  const album = new AV.Object('Album')
  album.set('title', title)
  album.set('description', description || '')
  album.set('creator', req.currentUser)
  album.set('images', [])
  album.set('cover', null)
  album.set('isPublic', isPublic === 'true')
  
  // 设置 ACL
  const acl = new AV.ACL()
  acl.setWriteAccess(req.currentUser, true)  // 创建者可写
  
  if (isPublic === 'true') {
    acl.setPublicReadAccess(true)  // 公开可读
  } else {
    acl.setReadAccess(req.currentUser, true)  // 仅创建者可读
  }
  
  // 管理员可读写
  const adminRole = await new AV.Query(AV.Role)
    .equalTo('name', 'admin')
    .first()
  acl.setRoleReadAccess(adminRole, true)
  acl.setRoleWriteAccess(adminRole, true)

  album.setACL(acl)
  
  await album.save()
  res.redirect('/album-list')
})


// 照片列表
/*
app.post('/album-list/:albumId/photos/upload', requireAuth, upload.single('photo'), async (req, res) => {
  const { photoName } = req.body
  
  try {
    // 检查用户是否有权限上传照片
    const roles = await req.currentUser.getRoles()
    const canUpload = roles.some(role => 
      role.getName() === 'admin' || role.getName() === 'vip'
    )
    
    if (!canUpload) {
      return res.status(403).send('没有权限上传照片')
    }

    const album = await new AV.Query('Album')
      .get(req.params.albumId)

    // 检查用户是否是相册创建者或管理员
    const isCreator = album.get('creator').id === req.currentUser.id
    const isAdmin = roles.some(role => role.getName() === 'admin')
    if (!isAdmin && !isCreator) {
      return res.status(403).send('没有权限修改此相册')
    }

    const file = new AV.File(req.file.originalname, req.file.buffer)
    await file.save()
    
    // 获取当前相册的图片数组
    const images = album.get('images') || []
    
    // 创建照片对象
    const photo = new AV.Object('Photo')
    photo.set({
      name: photoName,
      file: file,
      creator: req.currentUser,
      albumId: album.id  // 只存储相册ID而不是整个相册对象
    })
    
    // 设置照片的 ACL
    const photoAcl = new AV.ACL()
    photoAcl.setWriteAccess(req.currentUser, true)
    photoAcl.setReadAccess(req.currentUser, true)
    
    if (album.get('isPublic')) {
      photoAcl.setPublicReadAccess(true)
    }
    
    const adminRole = await new AV.Query(AV.Role)
      .equalTo('name', 'admin')
      .first()
    photoAcl.setRoleReadAccess(adminRole, true)
    photoAcl.setRoleWriteAccess(adminRole, true)
    
    photo.setACL(photoAcl)
    await photo.save()
    
    // 只存储照片的ID到相册的images数组中
    images.push(photo.id)
    
    // 如果还没有封面图片，将第一张图片设为封面
    if (!album.get('cover') && images.length === 1) {
      album.set('cover', {
        url: file.url(),
        __type: 'File',
        id: file.id,
        name: file.name()
      })
    }
    
    // 更新相册的图片数组
    album.set('images', images)
    await album.save()
    
    res.redirect(`/album-list/${req.params.albumId}`)
  } catch (error) {
    console.error('上传照片失败:', error)
    res.status(500).send('上传照片失败: ' + error.message)
  }
})
*/
// 上传照片
app.post('/album-list/:albumId/photos/upload', requireAuth, upload.single('photo'), async (req, res) => {
  try {
    const { photoName } = req.body
    const albumId = req.params.albumId

    // 获取相册
    const album = await new AV.Query('Album')
      .get(albumId)

    // 检查权限
    const roles = await req.currentUser.getRoles()
    const isAdmin = roles.some(role => role.getName() === 'admin')
    const isCreator = album.get('creator').id === req.currentUser.id
    
    if (!isAdmin && !isCreator) {
      return res.status(403).send('没有权限上传照片到此相册')
    }

    // 上传文件到 LeanCloud
    const file = await new AV.File(req.file.originalname, req.file.buffer).save()
    
    // 获取当前相册的照片列表
    const images = album.get('images') || []

    // 创建照片对象
    const photo = new AV.Object('Photo')
    photo.set({
      name: photoName,
      file: file,
      creator: req.currentUser,
      album: album
    })

    // 设置照片的 ACL
    const photoAcl = new AV.ACL()
    photoAcl.setWriteAccess(req.currentUser, true)
    photoAcl.setReadAccess(req.currentUser, true)
    
    if (album.get('isPublic')) {
      photoAcl.setPublicReadAccess(true)
    }
    
    const adminRole = await new AV.Query(AV.Role)
      .equalTo('name', 'admin')
      .first()
    photoAcl.setRoleReadAccess(adminRole, true)
    photoAcl.setRoleWriteAccess(adminRole, true)
    
    photo.setACL(photoAcl)
    await photo.save()
    
    // 只存储照片的ID到相册的images数组中
    images.push(photo.id)
    
    // 更新相册的图片数组
    album.set('images', images)
    await album.save()
    
    res.redirect(`/album-list/${albumId}`)

  } catch (error) {
    console.error('上传照片失败:', error)
    res.status(500).send('上传照片失败: ' + error.message)
  }
})

// 相册详情页面
app.get('/album-list/:id', requireAuth, async (req, res) => {
  const album = await new AV.Query('Album')
    .include('cover')
    .get(req.params.id)
  
  // 获取相册的所有照片
  const imageIds = album.get('images') || []
  const images = await Promise.all(
    imageIds.map(id => 
      new AV.Query('Photo')
        .include('file')
        .get(id)
    )
  )
  album.set('images', images)
  
  // 检查访问权限
  const roles = await req.currentUser.getRoles()
  const isAdmin = roles.some(role => role.getName() === 'admin')
  const isCreator = album.get('creator').id === req.currentUser.id
  const isPublic = album.get('isPublic')
  
  if (!isAdmin && !isCreator && !isPublic) {
    return res.status(403).send('没有权限访问此相册')
  }
  
  res.render('album', { album, isAdmin, isCreator })
})


// 编辑相册
app.post('/album-list/:id/edit', requireAuth, async (req, res) => {
  const { title, description, isPublic } = req.body
  
  const album = await new AV.Query('Album')
    .get(req.params.id)
  
  // 检查权限
  const roles = await req.currentUser.getRoles()
  const isAdmin = roles.some(role => role.getName() === 'admin')
  const isCreator = album.get('creator').id === req.currentUser.id
  
  if (!isAdmin && !isCreator) {
    return res.status(403).send('没有权限修改此相册')
  }

  album.set('title', title)
  album.set('description', description || '')
  album.set('isPublic', isPublic === 'true')
  
  // 更新 ACL
  const acl = new AV.ACL()
  acl.setWriteAccess(album.get('creator'), true)
  if (isPublic === 'true') {
    acl.setPublicReadAccess(true)
  } else {
    acl.setReadAccess(album.get('creator'), true)
  }
  
  // 管理员权限
  const adminRole = await new AV.Query(AV.Role)
    .equalTo('name', 'admin')
    .first()
  acl.setRoleReadAccess(adminRole, true)
  acl.setRoleWriteAccess(adminRole, true)
  
  album.setACL(acl)
  await album.save()
  
  res.redirect(`/album-list/${req.params.id}`)
})

// 删除相册
app.post('/album-list/:id/delete', requireAuth, async (req, res) => {
  const album = await new AV.Query('Album')
    .get(req.params.id)
  
  // 检查权限
  const roles = await req.currentUser.getRoles()
  const isAdmin = roles.some(role => role.getName() === 'admin')
  const isCreator = album.get('creator').id === req.currentUser.id
  
  if (!isAdmin && !isCreator) {
    return res.status(403).send('没有权限删除此相册')
  }

  await album.destroy()
  res.redirect('/album-list')
})

// 检查创建权限
app.get('/check-create-permission', requireAuth, async (req, res) => {
  try {
    const roles = await req.currentUser.getRoles()
    const canCreate = roles.some(role => 
      role.getName() === 'admin' || role.getName() === 'vip'
    )
    res.json({ canCreate })
  } catch (error) {
    console.error('检查权限失败:', error)
    res.status(500).json({ error: '检查权限失败' })
  }
})

// 检查照片上传权限
app.get('/check-upload-permission/:albumId', requireAuth, async (req, res) => {
  try {
    // 获取相册信息
    const album = await new AV.Query('Album')
      .get(req.params.albumId)
    
    // 检查是否是管理员
    const roles = await req.currentUser.getRoles()
    const isAdmin = roles.some(role => role.getName() === 'admin')
    
    // 检查是否是创建者
    const isCreator = album.get('creator').id === req.currentUser.id
    
    res.json({ canUpload: isAdmin || isCreator })
  } catch (error) {
    console.error('检查上传权限失败:', error)
    res.status(500).json({ error: '检查权限失败' })
  }
})

// 设置相册封面
app.post('/album-list/:albumId/set-cover/:photoId', requireAuth, async (req, res) => {
  try {
    const album = await new AV.Query('Album')
      .get(req.params.albumId)
    
    const photo = await new AV.Query('Photo')
      .include('file')
      .get(req.params.photoId)

    // 从 photo 对象中获取文件信息
    const file = photo.get('file')
    
    // 直接使用文件的原始数据
    const coverData = {
      objectId: file.id,
      createdAt: file.createdAt,
      updatedAt: file.updatedAt,
      name: file.attributes.name,
      url: file.attributes.url,
      provider: file.provider,
      bucket: file.attributes.bucket,
      mime_type: file.attributes.mime_type,
      key: file.key,
      metaData: file.attributes.metaData
    }
    
    // 设置封面
    album.set('cover', coverData)

    await album.save(null, { useMasterKey: true })
    res.sendStatus(200)
  } catch (error) {
    console.error('设置封面失败:', error)
    console.error('错误详情:', {
      code: error.code,
      message: error.message,
      rawMessage: error.rawMessage
    })
    res.status(500).send('设置封面失败')
  }
})

// 删除照片
app.post('/album-list/:albumId/photos/:photoId/delete', requireAuth, async (req, res) => {
  try {
    const album = await new AV.Query('Album')
      .get(req.params.albumId)
    
    // 检查权限
    const roles = await req.currentUser.getRoles()
    const isAdmin = roles.some(role => role.getName() === 'admin')
    const isCreator = album.get('creator').id === req.currentUser.id
    
    if (!isAdmin && !isCreator) {
      return res.status(403).send('没有权限删除照片')
    }

    // 从相册的图片数组中移除
    const images = album.get('images').filter(id => id !== req.params.photoId)
    album.set('images', images)
    await album.save()

    // 删除照片对象
    const photo = AV.Object.createWithoutData('Photo', req.params.photoId)
    await photo.destroy()

    res.sendStatus(200)
  } catch (error) {
    console.error('删除照片失败:', error)
    res.status(500).send('删除照片失败')
  }
})

// 重命名照片
app.post('/album-list/:albumId/photos/:photoId/rename', requireAuth, async (req, res) => {
  try {
    const album = await new AV.Query('Album')
      .get(req.params.albumId)
    
    // 检查权限
    const roles = await req.currentUser.getRoles()
    const isAdmin = roles.some(role => role.getName() === 'admin')
    const isCreator = album.get('creator').id === req.currentUser.id
    
    if (!isAdmin && !isCreator) {
      return res.status(403).send('没有权限修改照片')
    }

    const photo = await new AV.Query('Photo')
      .get(req.params.photoId)
    
    photo.set('name', req.body.name)
    await photo.save()

    res.sendStatus(200)
  } catch (error) {
    console.error('重命名照片失败:', error)
    res.status(500).send('重命名照片失败')
  }
})

module.exports = app;
