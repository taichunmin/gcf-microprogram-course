const _ = require('lodash')
const { google } = require('googleapis')
const { OAuth2Client } = require('google-auth-library')
const createError = require('http-errors')
const CryptoJS = require('crypto-js')
const express = require('express')

const SPREADSHEET_ID = '1dJhB5_auh5Fzqy7VfUnmFPpiT7OYF5BvpZ6nmrV9RJo'

/**
 * 取得 process.env.[key] 的輔助函式，且可以有預設值
 */
exports.getenv = (key, defaultval) => {
  return _.get(process, ['env', key], defaultval)
}

exports.parseCourse = async jwt => {
  if (!jwt || !_.isString(jwt)) throw createError(400, 'course 必填')
  const parts = jwt.split('.')
  if (parts.length !== 3) throw createError(400, 'course 格式錯誤')

  const secret = await exports.jwtSecret()
  const sign = exports.atob(CryptoJS.HmacSHA256(`${parts[0]}.${parts[1]}`, secret))
  if (sign !== parts[2]) throw createError(401, 'course 簽章驗證錯誤')

  return JSON.parse(exports.btoa(parts[1]))
}

exports.jwtSecret = (() => {
  let secret = null
  return async () => {
    if (!secret) {
      const sheetsAPI = await exports.sheetsAPI()
      const res = await sheetsAPI.developerMetadata.get({
        spreadsheetId: SPREADSHEET_ID,
        metadataId: 1,
      })
      // console.log(res)
      const { metadataKey: key, metadataValue: value } = _.get(res, 'data')
      secret = key === 'jwt-secret' ? value : null
    }
    return secret
  }
})()

exports.sheetsAPI = (() => {
  let sheetsAPI = null
  return async () => {
    if (!sheetsAPI) {
      const auth = await google.auth.getClient({
        scopes: ['https://www.googleapis.com/auth/spreadsheets']
      })
      sheetsAPI = google.sheets({ version: 'v4', auth }).spreadsheets
    }
    return sheetsAPI
  }
})()

exports.atob = str => {
  if (_.isString(str)) str = CryptoJS.enc.Utf8.parse(str)
  return CryptoJS.enc.Base64.stringify(str)
    .replace(/[+\/=]/g, c => _.get({'+': '-', '/': '_'}, c, ''))
}

exports.btoa = str => {
  str = str.replace(/[-_]/g, c => _.get({'-': '+', '_': '/'}, c, ''))
  return CryptoJS.enc.Utf8.stringify(CryptoJS.enc.Base64.parse(str))
}

exports.parseIdToken = (() => {
  const CLIENT_ID = '417954202747-62a0pn2ankrsco790jr1h29n9vnf92lm.apps.googleusercontent.com'
  const client = new OAuth2Client(CLIENT_ID)
  return async idToken => {
    try {
      if (!idToken || !_.isString(idToken)) throw createError(400, 'idToken 必填')
      const ticket = await client.verifyIdToken({
        idToken,
        audience: CLIENT_ID,
      })
      const payload = ticket.getPayload()
      return {
        id: payload.sub,
        email: payload.email,
        domain: payload.hd,
        name: payload.name,
        imageUrl: payload.picture,
        locale: payload.locale,
      }
    } catch (err) {
      err.status = err.status || 401
      throw err
    }
  }
})()

exports.handler = async (req, res) => {
  try {
    const [course, user] = await Promise.all([
      exports.parseCourse(req.body.c || req.query.c),
      exports.parseIdToken(req.body.g || req.query.g),
    ])
    res.status(200).json({ course, user })
  } catch (err) {
    console.log(err)
    const status = err.status || 500
    res.status(status).json({
      message: err.message,
      status,
    })
  }
}

/** 定義 router */
const router = express.Router()
router.use(require('cors')()) // cors

router.get('/', exports.handler)
router.post('/', exports.handler)

exports.main = router