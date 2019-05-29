#!/usr/bin/env python
#
# File: helpers.py
# by @BitK_
#
from json import dumps as json_dumps, loads as json_loads
from java.lang import Thread as JThread
from java.awt import Dimension
from java.net import URL
from burp import IParameter

import context


def same_size(*els):
    maxWidth = 0
    maxHeight = 0

    for el in els:
        size = el.getPreferredSize()
        maxWidth = max(size.width, maxWidth)
        maxHeight = max(size.height, maxHeight)

    for el in els:
        el.setPreferredSize(Dimension(maxWidth, maxHeight))


def noop(*args, **kwargs):
    return args, kwargs


def async_call(func, callback=lambda x: x, callback_error=None):
    def wrapper():
        try:
            result = func()
        except Exception as e:
            if callback_error:
                callback_error(e)
            else:
                raise
        else:
            callback(result)

    return JThread(wrapper).start()


class Response(object):
    def __init__(self, data, info):
        headers = info.getHeaders()
        body_offset = info.getBodyOffset()

        self.text = "".join(chr(c) for c in data[body_offset:])
        self.status_code = info.getStatusCode()
        self.headers = {
            name: value
            for name, value in [header.split(":", 1) for header in headers[1:]]
        }

    def json(self):
        return json_loads(self.text)


class BurpHTTP(object):
    def __init__(self):
        self.helpers = context.callbacks.getHelpers()

    def _fetch(self, url, request):
        https = url.getProtocol() == "https"
        port = 443 if https else 80
        response = context.callbacks.makeHttpRequest(
            url.getHost(), port, https, request
        )
        info = self.helpers.analyzeResponse(response)
        return Response(response, info)

    def _add_params(self, request, params, type):
        for name, value in params.items():
            param = self.helpers.buildParameter(name, value, type)
            request = self.helpers.addParameter(request, param)
        return request

    def get(self, urlstr, params={}, headers={}):
        url = URL(urlstr)

        head = [
            "GET {} HTTP/1.1".format(url.getPath()),
            "Host: {}".format(url.getHost()),
            "Accept: application/json",
        ]
        for name, value in headers.items():
            head.append("{}: {}".format(name, value))

        request = self.helpers.buildHttpMessage(head, None)
        request = self._add_params(request, params, IParameter.PARAM_URL)

        return self._fetch(url, request)

    def post(self, urlstr, json={}, headers={}):
        url = URL(urlstr)
        head = [
            "POST {} HTTP/1.1".format(url.getPath()),
            "Host: {}".format(url.getHost()),
            "Content-type: application/json",
        ]

        for name, value in headers.items():
            head.append("{}: {}".format(name, value))

        body = json_dumps(json)
        request = self.helpers.buildHttpMessage(head, body)

        return self._fetch(url, request)
