var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// .wrangler/tmp/bundle-6ayZCp/checked-fetch.js
var urls = /* @__PURE__ */ new Set();
function checkURL(request, init) {
  const url = request instanceof URL ? request : new URL(
    (typeof request === "string" ? new Request(request, init) : request).url
  );
  if (url.port && url.port !== "443" && url.protocol === "https:") {
    if (!urls.has(url.toString())) {
      urls.add(url.toString());
      console.warn(
        `WARNING: known issue with \`fetch()\` requests to custom HTTPS ports in published Workers:
 - ${url.toString()} - the custom port will be ignored when the Worker is published using the \`wrangler deploy\` command.
`
      );
    }
  }
}
__name(checkURL, "checkURL");
globalThis.fetch = new Proxy(globalThis.fetch, {
  apply(target, thisArg, argArray) {
    const [request, init] = argArray;
    checkURL(request, init);
    return Reflect.apply(target, thisArg, argArray);
  }
});

// dist/worker.js
var n = { async fetch(e) {
  return new URL(e.url).pathname === "/" ? new Response(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Stasher</title>
    <style>
        body {
            font-family: 'Fira Code', 'Monaco', 'Consolas', monospace;
            margin: 0;
            padding: 24px;
            padding-top: 80px;
            background: #1e1e1e;
            color: #cccccc;
            overflow: hidden;
        }
        
        .branding {
            position: absolute;
            top: 16px;
            left: 12px;
            color: #00bfff;
            font-size: 36px;
            font-weight: bold;
        }
        
        .version {
            position: absolute;
            bottom: 16px;
            left: 12px;
            color: #565656;
            font-size: 12px;
        }
        
        .operations {
            margin-top: 8px;
            padding: 0 12px;
        }
        
        .button-group {
            display: flex;
            gap: 0px;
            justify-content: flex-end;
        }
        
        .operation {
            background: none;
            border: none;
            font-family: inherit;
            font-size: 18px;
            font-weight: normal;
            cursor: pointer;
            padding: 12px 6px;
            transition: all 0.2s ease;
            text-transform: lowercase;
        }
        
        .operation.enstash {
            color: #90ee90;
        }
        
        .operation.destash {
            color: #daa520;
        }
        
        .operation.unstash {
            color: #cd5c5c;
        }

        .operation:hover {
            opacity: 0.8;
        }
        
        .operation:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .input-section {
            margin-bottom: 24px;
            padding: 0 12px;
            position: relative;
        }
        
        .clear-section {
            display: flex;
            justify-content: flex-end;
            margin-bottom: 16px;
            padding: 0 12px;
        }
        
        .clear-button {
            background: none;
            border: none;
            color: #969696;
            font-family: inherit;
            font-size: 10px;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .clear-button:hover {
            opacity: 0.8;
        }
        
        .clear-button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .input {
            width: calc(100% - 32px);
            background: #2d2d30;
            border: 1px solid #3e3e42;
            border-radius: 6px;
            padding: 14px 16px;
            color: #cccccc;
            font-family: inherit;
            font-size: 14px;
            resize: none;
            min-height: 20px;
            max-height: 20px;
            overflow: hidden;
            text-align: left;
            box-shadow: inset 0 1px 3px rgba(0,0,0,0.3);
        }
        
        .input:focus {
            outline: none;
            border-color: #00bfff;
            box-shadow: 0 0 0 2px rgba(0, 191, 255, 0.2), inset 0 1px 3px rgba(0,0,0,0.3);
        }
        
        .input::placeholder {
            color: #565656;
        }
        
        .message {
            margin-top: 16px;
            font-size: 12px;
            color: #565656;
            text-align: left;
            min-height: 16px;
        }
        
        .message.success {
            color: #90ee90;
        }
        
        .message.error {
            color: #cd5c5c;
        }
    </style>
</head>
<body>
    <div class="branding">stasher</div>
    
    <div class="clear-section">
        <button class="clear-button" id="clear-button">clear</button>
    </div>
    
    <div class="input-section">
        <input type="text" class="input" id="main-input" placeholder="enter secret, token, or uuid" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false">
        <div class="message" id="message"></div>
    </div>
    
    <div class="operations">
        <div class="button-group">
            <button class="operation enstash" data-mode="enstash">enstash</button>
            <button class="operation destash" data-mode="destash">destash</button>
            <button class="operation unstash" data-mode="unstash">unstash</button>
        </div>
    </div>
    
    <div class="version">v1.0</div>
    
    <script type="module" src="./popup.js"><\/script>
</body>
</html>`, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=3600", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self' https://api.stasher.dev;" } }) : new Response("Not Found", { status: 404 });
} };

// ../../.nvm/versions/node/v22.15.0/lib/node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// ../../.nvm/versions/node/v22.15.0/lib/node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-6ayZCp/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = n;

// ../../.nvm/versions/node/v22.15.0/lib/node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-6ayZCp/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=worker.js.map
