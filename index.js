const _ = require('lodash')
const { google } = require('googleapis')
const { OAuth2Client } = require('google-auth-library')
const createError = require('http-errors')
const CryptoJS = require('crypto-js')
const express = require('express')
const moment = require('moment')

const SPREADSHEET_ID = '1dJhB5_auh5Fzqy7VfUnmFPpiT7OYF5BvpZ6nmrV9RJo'

const log = (...args) => {
  _.each(args, (arg, i) => {
    console.log(i, _.truncate(JSON.stringify(arg), { length: 1000 }))
  })
}

/**
 * 取得 process.env.[key] 的輔助函式，且可以有預設值
 */
exports.getenv = (key, defaultval) => {
  return _.get(process, ['env', key], defaultval)
}

exports.getNow = () => moment().utcOffset(8)

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
        // https://developers.google.com/sheets/api/guides/concepts#partial_responses
        fields: 'metadataKey,metadataValue',
      })
      // log(JSON.stringify(res.data))
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

exports.sheetAppend = async (range, row) => {
  const sheetsAPI = await exports.sheetsAPI()
  const res = await sheetsAPI.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range,
    valueInputOption: 'RAW',
    insertDataOption: 'INSERT_ROWS',
    responseValueRenderOption: 'FORMATTED_VALUE',
    responseDateTimeRenderOption: 'FORMATTED_STRING',
    // https://developers.google.com/sheets/api/guides/concepts#partial_responses
    fields: 'updates',
    resource: {
      range,
      majorDimension: 'ROWS',
      values: [row],
    }
  })
  log('sheetAppend', res.data)
  return res.data
}

exports.sheetSetRowMetadata = async (range, key, value) => {
  const sheetsAPI = await exports.sheetsAPI()
  const res = await sheetsAPI.batchUpdate({
    spreadsheetId: SPREADSHEET_ID,
    // https://developers.google.com/sheets/api/guides/concepts#partial_responses
    fields: 'replies',
    resource: _.set({}, 'requests.0.createDeveloperMetadata.developerMetadata', {
      metadataKey: key,
      metadataValue: value,
      visibility: 'DOCUMENT',
      location: await exports.sheetRowToLocation(range),
    })
  })
  log('sheetSetRowMetadata', res.data)
  return res.data
}

exports.sheetDelMetadata = async metadata => {
  const sheetsAPI = await exports.sheetsAPI()
  const res = await sheetsAPI.batchUpdate({
    spreadsheetId: SPREADSHEET_ID,
    // https://developers.google.com/sheets/api/guides/concepts#partial_responses
    fields: 'replies',
    resource: _.set({}, 'requests.0.deleteDeveloperMetadata.dataFilter.developerMetadataLookup', {
      metadataKey: metadata.key,
      metadataValue: metadata.value,
    })
  })
  log('sheetSetRowMetadata', res.data)
  return _.get(res, 'data.replies.0.deleteDeveloperMetadata.deletedDeveloperMetadata.length', 0)
}

exports.sheetRowToLocation = async range => {
  const sheetsAPI = await exports.sheetsAPI()
  const res = await sheetsAPI.get({
    spreadsheetId: SPREADSHEET_ID,
    includeGridData: false,
    ranges: [range],
    // https://developers.google.com/sheets/api/guides/concepts#partial_responses
    fields: 'sheets(data.startRow,properties.sheetId)',
  })
  log('sheetRowToLocation', res.data)
  const startIndex = _.get(res, 'data.sheets.0.data.0.startRow')
  return {
    dimensionRange: {
      sheetId: _.get(res, 'data.sheets.0.properties.sheetId'),
      dimension: 'ROWS',
      startIndex: startIndex,
      endIndex: startIndex + 1,
    }
  }
}

exports.sheetUpdateByMetadata = async ({ row, metadata }) => {
  const sheetsAPI = await exports.sheetsAPI()
  const res = await sheetsAPI.values.batchUpdateByDataFilter({
    spreadsheetId: SPREADSHEET_ID,
    fields: 'totalUpdatedCells',
    resource: {
      valueInputOption: 'RAW',
      data: [{
        majorDimension: 'ROWS',
        values: [row],
        dataFilter: {
          developerMetadataLookup: {
            metadataKey: metadata.key,
            metadataValue: metadata.value,
          }
        },
      }]
    }
  })
  log('sheetUpdateByMetadata', res.data)
  return _.get(res, 'data.totalUpdatedCells', 0)
}

exports.upsertUser = async (user, nowStr) => {
  // 先嘗試使用更新
  const updated = await exports.sheetUpdateByMetadata({
    row: [user.id, user.name, user.email, user.imageUrl, null, nowStr],
    metadata: { key: 'gid', value: user.id }
  })
  if (updated) return

  // 沒有更新成功，改用新增的
  const userRow = [user.id, user.name, user.email, user.imageUrl, nowStr, nowStr]
  const range = _.get(await exports.sheetAppend('users!A:F', userRow), 'updates.updatedRange')
  await exports.sheetSetRowMetadata(range, 'gid', user.id)
}

exports.checkInCourse = async (user, course, nowStr) => {
  // 先嘗試找到課程並把使用者紀錄上去
  const metadata = { key: 'nonce', value: course.nonce }
  const updated = await exports.sheetUpdateByMetadata({
    row: [user.id, null, null, null, nowStr],
    metadata,
  })
  if (!updated) throw createError(404, '這個課程網址已失效，請重新取得')

  const deleted = await exports.sheetDelMetadata(metadata)
  if (!deleted) throw createError(500, '課程 metadata 刪除失敗')
}

exports.handler = async (req, res) => {
  try {
    const [course, user] = await Promise.all([
      exports.parseCourse(req.body.c || req.query.c),
      exports.parseIdToken(req.body.g || req.query.g),
    ])
    const nowStr = exports.getNow().format('YYYY-MM-DD HH:mm:ss')
    await exports.checkInCourse(user, course, nowStr)
    await exports.upsertUser(user, nowStr)
    res.status(200).json({ course, user })
  } catch (err) {
    log('handler', err)
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