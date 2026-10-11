# Changelog

## v4.11.0 - 2023-07-14


**Fixes**

* Fixes the proxy middleware concurrency issue of calling the Next() proxy target on Round Robin Balancer [#2409](https://github.com/labstack/echo/pull/2409)
* Fix `group.RouteNotFound` not working when group has attached middlewares [#2411](https://github.com/labstack/echo/pull/2411)
* Fix global error handler return error message when message is an error [#2456](https://github.com/labstack/echo/pull/2456)
* Do not use global timeNow variables [#2477](https://github.com/labstack/echo/pull/2477)


**Enhancements**

* Added a optional config variable to disable centralized error handler in recovery middleware [#2410](https://github.com/labstack/echo/pull/2410)
* refactor: use `strings.ReplaceAll` directly [#2424](https://github.com/labstack/echo/pull/2424)
* Add support for Go1.20 `http.rwUnwrapper` to Response struct [#2425](https://github.com/labstack/echo/pull/2425)
* Check whether is nil before invoking centralized error handling [#2429](https://github.com/labstack/echo/pull/2429)
* Proper colon support in `echo.Reverse` method [#2416](https://github.com/labstack/echo/pull/2416)
* Fix misuses of a vs an in documentation comments [#2436](https://github.com/labstack/echo/pull/2436)
* Add link to slog.Handler library for Echo logging into README.md [#2444](https://github.com/labstack/echo/pull/2444)
* In proxy middleware Support retries of failed proxy requests [#2414](https://github.com/labstack/echo/pull/2414)
* gofmt fixes to comments [#2452](https://github.com/labstack/echo/pull/2452)
* gzip response only if it exceeds a minimal length [#2267](https://github.com/labstack/echo/pull/2267)
* Upgrade packages [#2475](https://github.com/labstack/echo/pull/2475)


## v4.10.2 - 2023-02-22

**Security**
