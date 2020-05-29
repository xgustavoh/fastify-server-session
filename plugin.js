'use strict'

const fp = require('fastify-plugin')
const {
  sign,
  unsign
} = require('cookie-signature')
const uidgen = require('uid-safe')
const {
  v4: uuidv4
} = require('uuid')
const merge = require('merge-options')
const MAX_AGE = 1800000 // 30 minutes
const MAX_AGE_USER = 1296000000 // 15 Dias
const defaultOptions = {
  cookie: {
    domain: undefined,
    expires: MAX_AGE,
    httpOnly: true,
    path: undefined,
    sameSite: true
  },
  secretKey: undefined,
  sessionCookieName: 'sessionid',
  sessionMaxAge: MAX_AGE,
  userMaxAge: MAX_AGE_USER
}
const getSession = require('./lib/session')
const {
  symbols: syms
} = getSession

function plugin(fastify, options, pluginRegistrationDone) {
  const _options = Function.prototype.isPrototypeOf(options) ? {} : options
  const opts = merge({}, defaultOptions, _options)

  if (!opts.secretKey) {
    return pluginRegistrationDone(Error('must supply secretKey'))
  }
  // https://security.stackexchange.com/a/96176/38214
  if (opts.secretKey.length < 32) {
    return pluginRegistrationDone(
      Error('secretKey must be at least 32 characters')
    )
  }
  if (opts.cookie.expires && !Number.isInteger(opts.cookie.expires)) {
    return pluginRegistrationDone(
      Error('cookie expires time must be a value in milliseconds')
    )
  }

  function getIP(request) {
    let forwarded = request.ip
    if (request.headers['cf-connecting-ip']) {
      forwarded = request.headers['cf-connecting-ip']
    } else if (request.headers['x-forwarded-for']) {
      forwarded = request.headers['x-forwarded-for']
    } else if (Array.isArray(request.ips) && request.ips.length > 0) {
      ;
      [forwarded] = request.ips
    }

    if (forwarded.indexOf(',') >= 0) {
      forwarded = forwarded.substr(0, forwarded.indexOf(','))
    }

    return forwarded
  }

  function getUserAgent(request) {
    return encodeURIComponent(request.headers['user-agent'])
  }

  function getStation(request) {
    const info = (request.req.url || '').split('/')
    for (let i = 0; i < info.length; i += 1) {
      if (info[i] !== '') {
        return info[i].replace('.m3u8', '').trim()
      }
    }
    return 'unk'
  }

  function getUserID(request, done) {
    const userKey = `ht-user:${getIP(request)}:${getUserAgent(request)}`
    this.cache.get(userKey, (err, cached) => {
      let userID = err || !cached ? cached : uuidv4()
      this.cache.set(userKey, userID, opts.userMaxAge, () => {
        done({
          userID
        })
      })
    })
  }

  function getSessionID(req, done) {
    if (req.cookies[opts.sessionCookieName]) {
      const sessionId = unsign(
        req.cookies[opts.sessionCookieName],
        opts.secretKey
      )
      req.log.trace('sessionId: %s', sessionId)

      if (sessionId) {
        return done(null, {
          id: sessionId,
          enc: req.cookies[opts.sessionCookieName]
        })
      }
    }

    if (req.query[opts.sessionCookieName]) {
      const sessionId = unsign(
        req.query[opts.sessionCookieName],
        opts.secretKey
      )
      req.log.trace('sessionId: %s', sessionId)

      if (sessionId) {
        return done(null, {
          id: sessionId,
          enc: req.query[opts.sessionCookieName]
        })
      }
    }

    const keySession = `ht-session:${req.userID}:${getStation(req)}`
    this.cache.get(keySession, (err, cached) => {
      if (err || !cached) {
        uidgen(
          18,
          function (err, sessionId) {
            if (err) {
              req.log.trace('could not store session with invalid id')
              done(err)
            } else if (!sessionId) {
              req.log.trace('could not store session with missing id')
              done(Error('missing session id'))
            } else {
              this.cache.set(keySession, sessionId, opts.sessionMaxAge, () => {
                done(null, {
                  id: sessionId,
                  enc: sign(sessionId, opts.secretKey)
                })
              })
            }
          }.bind(this)
        )
      } else {
        done(null, {
          id: cached.item,
          enc: sign(cached.item, opts.secretKey)
        })
      }
    })
  }

  fastify.decorateRequest('session', getSession())
  fastify.addHook('onRequest', function (req, reply, hookFinished) {
    getUserID.bind(this)(req, (userID) => {
      req.userID = userID
      getSessionID.bind(this)(
        req,
        function (err, session) {
          if (err || !session) {
            req.session = getSession()
          } else {
            this.cache.get(session.id, (err, cached) => {
              if (err) {
                req.log.trace('could not retrieve session data')
                hookFinished(err)
              } else if (!cached) {
                req.log.trace('session data missing (new/expired)')
                req.session = getSession(session)
                hookFinished()
              } else {
                req.session = getSession(session, cached.item)
                req.log.trace('session restored: %j', req.session)
                hookFinished()
              }
            })
          }
        }.bind(this)
      )
    })
  })

  fastify.addHook('onSend', function (req, reply, payload, hookFinished) {
    if (req.session[syms.kSessionModified] === false) {
      hookFinished()
    } else {
      this.cache.set(
        req.session[syms.kSessionID],
        req.session,
        opts.sessionMaxAge,
        (err) => {
          if (err) {
            req.log.trace('error saving session: %s', err.message)
            hookFinished(err)
          } else {
            const cookieExiresMs = opts.cookie && opts.cookie.expires
            const cookieOpts = merge({}, opts.cookie, {
              expires: !cookieExiresMs ?
                undefined : new Date(Date.now() + cookieExiresMs)
            })
            reply.setCookie(
              opts.sessionCookieName,
              req.session[syms.kSessionToken],
              cookieOpts
            )
            hookFinished()
          }
        }
      )
    }
  })

  pluginRegistrationDone()
}

module.exports = fp(plugin, {
  fastify: '^2.0.0',
  dependencies: ['fastify-cookie'],
  decorators: {
    fastify: ['cache']
  }
})