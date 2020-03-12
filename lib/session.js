"use strict";

const syms = {
  kSessionID: "id",
  kSessionToken: "token",
  kSessionModified: Symbol("fastify-servier-session.sessionModified")
};

module.exports = function getSession(info, fromObject) {
  let session;
  if (fromObject) {
    session = fromObject;
    session[syms.kSessionID] = info ? info.id || -1 : -1;
    session[syms.kSessionToken] = info ? info.enc || "" : "";
    session[syms.kSessionModified] = false;
  } else {
    session = {
      get [Symbol.toStringTag]() {
        return "fastify-server-session.session-object";
      },
      [syms.kSessionID]: info ? info.id || -1 : -1,
      [syms.kSessionToken]: info ? info.enc || "" : "",
      [syms.kSessionModified]: false
    };
  }

  const proxy = new Proxy(session, {
    set(target, prop, value, receiver) {
      if (target[syms.kSessionModified] === false) {
        target[syms.kSessionModified] = true;
      }

      if (
        prop !== syms.kSessionID &&
        prop !== syms.kSessionToken &&
        prop !== syms.kSessionModified
      ) {
        target[prop] = value;
      }
      return receiver;
    }
  });
  return proxy;
};

module.exports.symbols = syms;
