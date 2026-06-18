"""JSON-RPC over HTTP client for the integration tests.

Derived from Jeff Garzik's AuthServiceProxy (2011), under the MIT/LGPL terms of
the original. Kept deliberately small and stdlib-only (http.client): the tests
talk to a localhost fluxd, and parsing every JSON number as Decimal is required
for satoshi-exact assertions -- something a general-purpose HTTP client would
not give us for free.
"""

import base64
import decimal
import http.client
import json
import logging
from typing import Any
from urllib.parse import urlparse

USER_AGENT = "AuthServiceProxy/0.1"

HTTP_TIMEOUT = 600

log = logging.getLogger("FluxRPC")


class JSONRPCException(Exception):
    def __init__(self, rpc_error: dict[str, Any]) -> None:
        super().__init__(rpc_error.get("message", "JSON-RPC error"))
        self.error = rpc_error


def EncodeDecimal(o: Any) -> float:
    if isinstance(o, decimal.Decimal):
        return float(round(o, 8))
    raise TypeError(f"{o!r} is not JSON serializable")


class AuthServiceProxy:
    __id_count = 0
    # Set in __init__; declared here so static analysis knows the attribute and
    # it does not get intercepted by __getattr__.
    url: str = ""

    def __init__(
        self,
        service_url: str,
        service_name: str | None = None,
        timeout: float = HTTP_TIMEOUT,
        connection: http.client.HTTPConnection | None = None,
    ) -> None:
        self.__service_url = service_url
        self.__service_name = service_name
        self.__url = urlparse(service_url)
        self.url = service_url
        if self.__url.hostname is None:
            raise ValueError(f"missing host in service URL: {service_url}")
        self.__hostname = self.__url.hostname
        port = 80 if self.__url.port is None else self.__url.port
        user = (self.__url.username or "").encode("utf8")
        passwd = (self.__url.password or "").encode("utf8")
        self.__auth_header = "Basic " + base64.b64encode(user + b":" + passwd).decode("ascii")

        if connection:
            # Callables reuse the connection of the original proxy.
            self.__conn = connection
        elif self.__url.scheme == "https":
            self.__conn = http.client.HTTPSConnection(self.__hostname, port, timeout=timeout)
        else:
            self.__conn = http.client.HTTPConnection(self.__hostname, port, timeout=timeout)

    def __getattr__(self, name: str) -> "AuthServiceProxy":
        if name.startswith("__") and name.endswith("__"):
            # Python internal stuff.
            raise AttributeError(name)
        if self.__service_name is not None:
            name = f"{self.__service_name}.{name}"
        return AuthServiceProxy(self.__service_url, name, connection=self.__conn)

    def _request(self, method: str, path: str, postdata: str) -> dict[str, Any]:
        """Do an HTTP request, reconnecting once if the keep-alive connection was dropped."""
        headers = {
            "Host": self.__hostname,
            "User-Agent": USER_AGENT,
            "Authorization": self.__auth_header,
            "Content-type": "application/json",
        }
        try:
            self.__conn.request(method, path, postdata, headers)
            return self._get_response()
        except (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError):
            # The persistent connection was closed by the server; reconnect and retry once.
            self.__conn.close()
            self.__conn.request(method, path, postdata, headers)
            return self._get_response()

    def __call__(self, *args: Any) -> Any:
        AuthServiceProxy.__id_count += 1
        log.debug(
            "-%s-> %s %s",
            AuthServiceProxy.__id_count,
            self.__service_name,
            json.dumps(args, default=EncodeDecimal),
        )
        postdata = json.dumps(
            {
                "version": "1.1",
                "method": self.__service_name,
                "params": args,
                "id": AuthServiceProxy.__id_count,
            },
            default=EncodeDecimal,
        )
        response = self._request("POST", self.__url.path, postdata)
        if response["error"] is not None:
            raise JSONRPCException(response["error"])
        if "result" not in response:
            raise JSONRPCException({"code": -343, "message": "missing JSON-RPC result"})
        return response["result"]

    def _batch(self, rpc_call_list: list[dict[str, Any]]) -> dict[str, Any]:
        postdata = json.dumps(list(rpc_call_list), default=EncodeDecimal)
        log.debug("--> %s", postdata)
        return self._request("POST", self.__url.path, postdata)

    def _get_response(self) -> dict[str, Any]:
        http_response = self.__conn.getresponse()
        if http_response is None:
            raise JSONRPCException({"code": -342, "message": "missing HTTP response from server"})

        responsedata = http_response.read().decode("utf8")
        response = json.loads(responsedata, parse_float=decimal.Decimal)
        if "error" in response and response["error"] is None:
            log.debug(
                "<-%s- %s",
                response["id"],
                json.dumps(response["result"], default=EncodeDecimal),
            )
        else:
            log.debug("<-- %s", responsedata)
        return response
