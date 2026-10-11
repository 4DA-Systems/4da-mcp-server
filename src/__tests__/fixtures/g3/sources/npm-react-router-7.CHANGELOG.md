# `react-router`

## 7.0.0

### Major Changes

- Remove the original `defer` implementation in favor of using raw promises via single fetch and `turbo-stream`. This removes these exports from React Router: ([#11744](https://github.com/remix-run/react-router/pull/11744))

  - `defer`
  - `AbortedDeferredError`
  - `type TypedDeferredData`
  - `UNSAFE_DeferredData`
  - `UNSAFE_DEFERRED_SYMBOL`,

- - Collapse `@remix-run/router` into `react-router` ([#11505](https://github.com/remix-run/react-router/pull/11505))
  - Collapse `react-router-dom` into `react-router`
  - Collapse `@remix-run/server-runtime` into `react-router`
  - Collapse `@remix-run/testing` into `react-router`

- Remove single_fetch future flag. ([#11522](https://github.com/remix-run/react-router/pull/11522))

- Drop support for Node 16, React Router SSR now requires Node 18 or higher ([#11391](https://github.com/remix-run/react-router/pull/11391))

- Remove `future.v7_startTransition` flag ([#11696](https://github.com/remix-run/react-router/pull/11696))

- - Expose the underlying router promises from the following APIs for compsition in React 19 APIs: ([#11521](https://github.com/remix-run/react-router/pull/11521))
    - `useNavigate()`
    - `useSubmit`
    - `useFetcher().load`
    - `useFetcher().submit`
    - `useRevalidator.revalidate`

- Remove `future.v7_normalizeFormMethod` future flag ([#11697](https://github.com/remix-run/react-router/pull/11697))

- For Remix consumers migrating to React Router, the `crypto` global from the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) is now required when using cookie and session APIs. This means that the following APIs are provided from `react-router` rather than platform-specific packages: ([#11837](https://github.com/remix-run/react-router/pull/11837))

  - `createCookie`
  - `createCookieSessionStorage`
  - `createMemorySessionStorage`
  - `createSessionStorage`

  For consumers running older versions of Node, the `installGlobals` function from `@remix-run/node` has been updated to define `globalThis.crypto`, using [Node's `require('node:crypto').webcrypto` implementation.](https://nodejs.org/api/webcrypto.html)

  Since platform-specific packages no longer need to implement this API, the following low-level APIs have been removed:

  - `createCookieFactory`
  - `createSessionStorageFactory`
  - `createCookieSessionStorageFactory`
  - `createMemorySessionStorageFactory`

- Imports/Exports cleanup ([#11840](https://github.com/remix-run/react-router/pull/11840))

  - Removed the following exports that were previously public API from `@remix-run/router`
    - types
      - `AgnosticDataIndexRouteObject`
      - `AgnosticDataNonIndexRouteObject`
      - `AgnosticDataRouteMatch`
      - `AgnosticDataRouteObject`
      - `AgnosticIndexRouteObject`
      - `AgnosticNonIndexRouteObject`
      - `AgnosticRouteMatch`
      - `AgnosticRouteObject`
      - `TrackedPromise`
      - `unstable_AgnosticPatchRoutesOnMissFunction`
      - `Action` -> exported as `NavigationType` via `react-router`
      - `Router` exported as `DataRouter` to differentiate from RR's `<Router>`
    - API
      - `getToPathname` (`@private`)
      - `joinPaths` (`@private`)
      - `normalizePathname` (`@private`)
      - `resolveTo` (`@private`)
      - `stripBasename` (`@private`)
      - `createBrowserHistory` -> in favor of `createBrowserRouter`
      - `createHashHistory` -> in favor of `createHashRouter`
      - `createMemoryHistory` -> in favor of `createMemoryRouter`
      - `createRouter`
      - `createStaticHandler` -> in favor of wrapper `createStaticHandler` in RR Dom
      - `getStaticContextFromError`
  - Removed the following exports that were previously public API from `react-router`
    - `Hash`
    - `Pathname`
    - `Search`

- update minimum node version to 18 ([#11690](https://github.com/remix-run/react-router/pull/11690))

- Remove `future.v7_prependBasename` from the ionternalized `@remix-run/router` package ([#11726](https://github.com/remix-run/react-router/pull/11726))

- Migrate Remix type generics to React Router ([#12180](https://github.com/remix-run/react-router/pull/12180))

  - These generics are provided for Remix v2 migration purposes
  - These generics and the APIs they exist on should be considered informally deprecated in favor of the new `Route.*` types
  - Anyone migrating from React Router v6 should probably not leverage these new generics and should migrate straight to the `Route.*` types
  - For React Router v6 users, these generics are new and should not impact your app, with one exception
    - `useFetcher` previously had an optional generic (used primarily by Remix v2) that expected the data type
    - This has been updated in v7 to expect the type of the function that generates the data (i.e., `typeof loader`/`typeof action`)
    - Therefore, you should update your usages:
      - ❌ `useFetcher<LoaderData>()`
      - ✅ `useFetcher<typeof loader>()`

- Remove `future.v7_throwAbortReason` from internalized `@remix-run/router` package ([#11728](https://github.com/remix-run/react-router/pull/11728))

- Add `exports` field to all packages ([#11675](https://github.com/remix-run/react-router/pull/11675))

- node package no longer re-exports from react-router ([#11702](https://github.com/remix-run/react-router/pull/11702))

- renamed RemixContext to FrameworkContext ([#11705](https://github.com/remix-run/react-router/pull/11705))

- updates the minimum React version to 18 ([#11689](https://github.com/remix-run/react-router/pull/11689))

- PrefetchPageDescriptor replaced by PageLinkDescriptor ([#11960](https://github.com/remix-run/react-router/pull/11960))

- - Consolidate types previously duplicated across `@remix-run/router`, `@remix-run/server-runtime`, and `@remix-run/react` now that they all live in `react-router` ([#12177](https://github.com/remix-run/react-router/pull/12177))
    - Examples: `LoaderFunction`, `LoaderFunctionArgs`, `ActionFunction`, `ActionFunctionArgs`, `DataFunctionArgs`, `RouteManifest`, `LinksFunction`, `Route`, `EntryRoute`
    - The `RouteManifest` type used by the "remix" code is now slightly stricter because it is using the former `@remix-run/router` `RouteManifest`
      - `Record<string, Route> -> Record<string, Route | undefined>`
    - Removed `AppData` type in favor of inlining `unknown` in the few locations it was used
    - Removed `ServerRuntimeMeta*` types in favor of the `Meta*` types they were duplicated from

- - Remove the `future.v7_partialHydration` flag ([#11725](https://github.com/remix-run/react-router/pull/11725))
    - This also removes the `<RouterProvider fallbackElement>` prop
      - To migrate, move the `fallbackElement` to a `hydrateFallbackElement`/`HydrateFallback` on your root route
    - Also worth nothing there is a related breaking changer with this future flag:
      - Without `future.v7_partialHydration` (when using `fallbackElement`), `state.navigation` was populated during the initial load
      - With `future.v7_partialHydration`, `state.navigation` remains in an `"idle"` state during the initial load

- Remove `v7_relativeSplatPath` future flag ([#11695](https://github.com/remix-run/react-router/pull/11695))

- Drop support for Node 18, update minimum Node vestion to 20 ([#12171](https://github.com/remix-run/react-router/pull/12171))

  - Remove `installGlobals()` as this should no longer be necessary

- Remove remaining future flags ([#11820](https://github.com/remix-run/react-router/pull/11820))

  - React Router `v7_skipActionErrorRevalidation`
  - Remix `v3_fetcherPersist`, `v3_relativeSplatPath`, `v3_throwAbortReason`

- rename createRemixStub to createRoutesStub ([#11692](https://github.com/remix-run/react-router/pull/11692))

- Remove `@remix-run/router` deprecated `detectErrorBoundary` option in favor of `mapRouteProperties` ([#11751](https://github.com/remix-run/react-router/pull/11751))

- Add `react-router/dom` subpath export to properly enable `react-dom` as an optional `peerDependency` ([#11851](https://github.com/remix-run/react-router/pull/11851))

  - This ensures that we don't blindly `import ReactDOM from "react-dom"` in `<RouterProvider>` in order to access `ReactDOM.flushSync()`, since that would break `createMemoryRouter` use cases in non-DOM environments
  - DOM environments should import from `react-router/dom` to get the proper component that makes `ReactDOM.flushSync()` available:
    - If you are using the Vite plugin, use this in your `entry.client.tsx`:
      - `import { HydratedRouter } from 'react-router/dom'`
    - If you are not using the Vite plugin and are manually calling `createBrowserRouter`/`createHashRouter`:
      - `import { RouterProvider } from "react-router/dom"`

- Remove `future.v7_fetcherPersist` flag ([#11731](https://github.com/remix-run/react-router/pull/11731))

- Update `cookie` dependency to `^1.0.1` - please see the [release notes](https://github.com/jshttp/cookie/releases) for any breaking changes ([#12172](https://github.com/remix-run/react-router/pull/12172))

### Minor Changes

- - Add support for `prerender` config in the React Router vite plugin, to support existing SSG use-cases ([#11539](https://github.com/remix-run/react-router/pull/11539))
    - You can use the `prerender` config to pre-render your `.html` and `.data` files at build time and then serve them statically at runtime (either from a running server or a CDN)
    - `prerender` can either be an array of string paths, or a function (sync or async) that returns an array of strings so that you can dynamically generate the paths by talking to your CMS, etc.

  ```ts
  // react-router.config.ts
  import type { Config } from "@react-router/dev/config";

  export default {
    async prerender() {
      let slugs = await fakeGetSlugsFromCms();
      // Prerender these paths into `.html` files at build time, and `.data`
      // files if they have loaders
      return ["/", "/about", ...slugs.map((slug) => `/product/${slug}`)];
    },
  } satisfies Config;

  async function fakeGetSlugsFromCms() {
    await new Promise((r) => setTimeout(r, 1000));
    return ["shirt", "hat"];
  }
  ```

- Params, loader data, and action data as props for route component exports ([#11961](https://github.com/remix-run/react-router/pull/11961))

  ```tsx
  export default function Component({ params, loaderData, actionData }) {}

  export function HydrateFallback({ params }) {}
  export function ErrorBoundary({ params, loaderData, actionData }) {}
  ```

- Remove duplicate `RouterProvider` impliementations ([#11679](https://github.com/remix-run/react-router/pull/11679))

- ### Typesafety improvements ([#12019](https://github.com/remix-run/react-router/pull/12019))

  React Router now generates types for each of your route modules.
  You can access those types by importing them from `./+types.<route filename without extension>`.
  For example:

  ```ts
  // app/routes/product.tsx
  import type * as Route from "./+types.product";

  export function loader({ params }: Route.LoaderArgs) {}

  export default function Component({ loaderData }: Route.ComponentProps) {}
  ```

  This initial implementation targets type inference for:

  - `Params` : Path parameters from your routing config in `routes.ts` including file-based routing
  - `LoaderData` : Loader data from `loader` and/or `clientLoader` within your route module
  - `ActionData` : Action data from `action` and/or `clientAction` within your route module

  In the future, we plan to add types for the rest of the route module exports: `meta`, `links`, `headers`, `shouldRevalidate`, etc.
  We also plan to generate types for typesafe `Link`s:

  ```tsx
  <Link to="/products/:id" params={{ id: 1 }} />
  //        ^^^^^^^^^^^^^          ^^^^^^^^^
  // typesafe `to` and `params` based on the available routes in your app
  ```

  Check out our docs for more:

  - [_Explanations > Type Safety_](https://reactrouter.com/dev/guides/explanation/type-safety)
  - [_How-To > Setting up type safety_](https://reactrouter.com/dev/guides/how-to/setting-up-type-safety)

- Stabilize `unstable_dataStrategy` ([#11969](https://github.com/remix-run/react-router/pull/11969))

- Stabilize `unstable_patchRoutesOnNavigation` ([#11970](https://github.com/remix-run/react-router/pull/11970))

### Patch Changes

- No changes ([`506329c4e`](https://github.com/remix-run/react-router/commit/506329c4e2e7aba9837cbfa44df6103b49423745))

- chore: re-enable development warnings through a `development` exports condition. ([#12269](https://github.com/remix-run/react-router/pull/12269))

- Remove unstable upload handler. ([#12015](https://github.com/remix-run/react-router/pull/12015))

- Remove unneeded dependency on @web3-storage/multipart-parser ([#12274](https://github.com/remix-run/react-router/pull/12274))

- Fix redirects returned from loaders/actions using `data()` ([#12021](https://github.com/remix-run/react-router/pull/12021))

- fix(react-router): (v7) fix static prerender of non-ascii characters ([#12161](https://github.com/remix-run/react-router/pull/12161))

- Replace `substr` with `substring` ([#12080](https://github.com/remix-run/react-router/pull/12080))

- Remove the deprecated `json` utility ([#12146](https://github.com/remix-run/react-router/pull/12146))

  - You can use [`Response.json`](https://developer.mozilla.org/en-US/docs/Web/API/Response/json_static) if you still need to construct JSON responses in your app

- Remove unneeded dependency on source-map ([#12275](https://github.com/remix-run/react-router/pull/12275))

## 6.28.0

### Minor Changes
