/// <reference types="node" />
import * as fastify from "fastify";
import { IncomingMessage } from "http";
import { Http2ServerRequest } from "http2";

type HttpRequest = IncomingMessage | Http2ServerRequest;
type HttpResponse = ServerResponse | Http2ServerResponse;

declare module "fastify" {
  interface FastifyRequest<
    HttpRequest,
    Query = fastify.DefaultQuery,
    Params = fastify.DefaultParams,
    Headers = fastify.DefaultHeaders,
    Body = any
  > {
    /** Allows to access or modify the session data. */
    userID: string;
    session: Session;
  }

  interface Session extends Record<string, any> {
    sessionID: string;
    sessionToken: string;
  }
}

declare function FastifyServerSessionPlugin(): void;

declare interface FastifyServerSessionPlugin<
  HttpServer,
  HttpRequest,
  HttpResponse
>
  extends fastify.Plugin<
    HttpServer,
    HttpRequest,
    HttpResponse,
    FastifyServerSessionPlugin.Options
  > {}

declare namespace FastifyServerSessionPlugin {
  interface Options {
    cookie?: CookieOptions;
    secretKey: string;
    sessionCookieName?: string;
    sessionMaxAge?: string;
  }

  interface CookieOptions {
    domain?: string;
    expires?: number;
    httpOnly?: boolean;
    path?: string;
    sameSite?: boolean;
  }
}

declare var FastifyServerSessionPlugin: FastifyServerSessionPlugin<
  any,
  any,
  any
>;

export = fastifyServerSession;
