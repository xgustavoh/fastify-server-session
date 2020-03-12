"use strict";

const fp = require("fastify-plugin");
const { sign, unsign } = require("cookie-signature");
const uidgen = require("uid-safe");
const merge = require("merge-options");
const MAX_AGE = 1800000; // 30 minutes
const defaultOptions = {
  cookie: {
    domain: undefined,
    expires: MAX_AGE,
    httpOnly: true,
    path: undefined,
    sameSite: true
  },
  secretKey: undefined,
  sessionCookieName: "sessionid",
  sessionMaxAge: MAX_AGE
};
const getSession = require("./lib/session");
const { symbols: syms } = getSession;

function plugin(fastify, options, pluginRegistrationDone) {
  const _options = Function.prototype.isPrototypeOf(options) ? {} : options;
  const opts = merge({}, defaultOptions, _options);

  if (!opts.secretKey) {
    return pluginRegistrationDone(Error("must supply secretKey"));
  }
  // https://security.stackexchange.com/a/96176/38214
  if (opts.secretKey.length < 32) {
    return pluginRegistrationDone(
      Error("secretKey must be at least 32 characters")
    );
  }
  if (opts.cookie.expires && !Number.isInteger(opts.cookie.expires)) {
    return pluginRegistrationDone(
      Error("cookie expires time must be a value in milliseconds")
    );
  }

  function getSessionID(req, done) {
    if (req.cookies[opts.sessionCookieName]) {
      const sessionId = unsign(
        req.cookies[opts.sessionCookieName],
        opts.secretKey
      );
      req.log.trace("sessionId: %s", sessionId);

      if (sessionId) {
        return done(null, {
          id: sessionId,
          enc: req.cookies[opts.sessionCookieName]
        });
      }
    }

    if (req.query[opts.sessionCookieName]) {
      const sessionId = unsign(
        req.query[opts.sessionCookieName],
        opts.secretKey
      );
      req.log.trace("sessionId: %s", sessionId);

      if (sessionId) {
        return done(null, {
          id: sessionId,
          enc: req.query[opts.sessionCookieName]
        });
      }
    }

    uidgen(18, storeSession.bind(this));
    function storeSession(err, sessionId) {
      if (err) {
        req.log.trace("could not store session with invalid id");
        done(err);
      } else if (!sessionId) {
        req.log.trace("could not store session with missing id");
        done(Error("missing session id"));
      } else {
        done(null, { id: sessionId, enc: sign(sessionId, opts.secretKey) });
      }
    }
  }

  fastify.decorateRequest("session", getSession());
  fastify.addHook("onRequest", function(req, reply, hookFinished) {
    getSessionID(req, function(err, session) {
      if (err || !session) {
        req.session = getSession();
      } else {
        this.cache.get(session.id, (err, cached) => {
          if (err) {
            req.log.trace("could not retrieve session data");
            hookFinished(err);
          } else if (!cached) {
            req.log.trace("session data missing (new/expired)");
            req.session = getSession(session);
            hookFinished();
          } else {
            req.session = getSession(session, cached.item);
            req.log.trace("session restored: %j", req.session);
            hookFinished();
          }
        });
      }
    });
  });

  fastify.addHook("onSend", function(req, reply, payload, hookFinished) {
    if (req.session[syms.kSessionModified] === false) {
      hookFinished();
    } else {
      this.cache.set(
        req.session[syms.kSessionID],
        req.session,
        opts.sessionMaxAge,
        err => {
          if (err) {
            req.log.trace("error saving session: %s", err.message);
            hookFinished(err);
          } else {
            const cookieExiresMs = opts.cookie && opts.cookie.expires;
            const cookieOpts = merge({}, opts.cookie, {
              expires: !cookieExiresMs
                ? undefined
                : new Date(Date.now() + cookieExiresMs)
            });
            reply.setCookie(
              opts.sessionCookieName,
              req.session[syms.kSessionToken],
              cookieOpts
            );
            hookFinished();
          }
        }
      );
    }
  });

  pluginRegistrationDone();
}

module.exports = fp(plugin, {
  fastify: "^2.0.0",
  dependencies: ["fastify-cookie"],
  decorators: {
    fastify: ["cache"]
  }
});
