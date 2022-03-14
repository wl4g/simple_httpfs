#!/usr/bin/env python3

import base64
from fileinput import filename
import os
import re
import shutil
import string
import sys
import time
from typing import List
import urllib

import cgi
import http.server
import ssl
import configparser


class SimpleHTTPfsRequestHandler(http.server.BaseHTTPRequestHandler):
    tpl_file = '/etc/simple_httpfs/index.tpl'
    data_dir = os.getcwd()

    # Replace server headers from "Server: BaseHTTP/0.6 Python/3.6.7"
    server_version = "SimpleHTTPFS/2"
    sys_version = ""  # replaces Python/3.6.7

    def is_authenticated(self):
        if self.path == '/':
            return True

        basic_auth_key = ""
        for authc in self.basic_authc_list:
            # Request uri path regex matches
            matched = re.match(authc["authc_uri"],
                               self.path, re.M | re.I) != None
            if matched:
                basic_auth_key = "Basic " + authc["authc_info"]

        authorization_header = self.headers["Authorization"]
        if authorization_header != basic_auth_key:
            self.log_message(
                "Failure basic authentication. request authorization: '%s', path: '%s'", authorization_header, self.path)
            self.do_authentication()
            self.close_connection = True
            return False

        return True

    def do_authentication(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Basic realm=HttpBasicRealm")
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_HEAD(self):
        # self.log_message("do_head ...")
        return self.do_get_index_page(False)

    def do_GET(self):
        # self.log_message("do_get ...")
        return self.do_get_index_page(False)

    def do_POST(self):
        # self.log_message("do_post ...", self.path)
        if not self.is_authenticated():
            return self.do_GET()

        post_form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": self.headers['Content-Type']
            }
        )

        # current work path.
        # dir_path = os.path.dirname(os.path.realpath(__file__))
        dir_path = data_dir   # configured basedir path.
        file_name = urllib.parse.unquote(post_form["file"].filename)

        with open(dir_path + self.path + "/" + file_name, 'wb') as file_object:
            shutil.copyfileobj(post_form["file"].file, file_object)

        return self.do_get_index_page(True)

    def do_get_index_page(self, is_redirect):
        if not self.is_authenticated():
            return

        uri_path = re.split(r'\?|\#', self.path)[0]
        req_file_path = data_dir + uri_path

        if is_redirect:
            self.send_response(301)
            location = self.get_request_base_uri() + uri_path
            self.log_message("Redirecting %s", location)
            self.send_header("Location", location)
            self.end_headers()  # the response to browser
            return

        # Response files html
        if os.path.isdir(req_file_path):
            contents_html = self. render_html_directies(
                req_file_path, uri_path)
            # self.log_message("Render html:\n%s", contents_html)

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.send_header("Content-Length", str(len(contents_html)))
            self.end_headers()
            self.wfile.write(contents_html)
            return

        # Response download or rendering file
        try:
            req_file_path = urllib.parse.unquote(req_file_path)

            self.send_response(200)
            self.send_header("Content-Length",
                             str(os.stat(req_file_path).st_size))
            self.send_header(
                "Last-Modified", self.date_time_string(os.stat(req_file_path).st_mtime))
            if req_file_path.endswith(('.gif', '.jpg', '.png', '.jpeg', '.bmp', '.webp', '.ico')):
                self.send_header("Content-type", "image/jpeg")
            elif req_file_path.endswith(('.mp4', '.w4a', '.w4v')):
                self.send_header("Content-type", "video/mpeg4")
            elif req_file_path.endswith(('.wov', '.w4a')):
                self.send_header("Content-type", "video/quicktime")
            elif req_file_path.endswith(('.avi')):
                self.send_header("Content-type", "video/avi")
            elif req_file_path.endswith(('.flv')):
                self.send_header("Content-type", "video/x-flv")
            elif req_file_path.endswith(('.wma')):
                self.send_header("Content-type", "video/wma")
            elif req_file_path.endswith(('.vob')):
                self.send_header("Content-type", "video/vob")
            elif req_file_path.endswith(('.mpv', 'mpeg')):
                self.send_header("Content-type", "video/mpg")
            elif req_file_path.endswith(('.3gp')):
                self.send_header("Content-type", "video/3gpp")
            elif req_file_path.endswith(('.mp3')):
                self.send_header("Content-type", "audio/mp3")
            else:
                self.send_header("Content-type", "application/octet-stream")
            self.end_headers()

            if self.command == "GET":
                request_file = open(req_file_path, 'rb')
                shutil.copyfileobj(request_file, self.wfile)

                request_file.close()
        except IOError:
            self.send_error(404, "Not found file")
            return

        return

    def get_request_base_uri(self):
        schema = self.headers.get('X-Forwarded-Proto', "http://")
        hostAndPort = self.headers.get('Host', "localhost")
        return schema + hostAndPort

    def render_html_directies(self, req_file_path, uri_path):
        self.log_message("Render html by uri: '%s' from directies: '%s'",
                         uri_path, req_file_path)
        try:
            file_list = os.listdir(req_file_path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return ""

        base_uri = self.get_request_base_uri()
        # uri_path = uri_path = '' if self.path == '/' '' else self.path
        file_list_html = "<li><a target='_self' href='../'>../</a></li>\n"
        for file_name in file_list:
            full_file_name = req_file_path + "/" + file_name
            file_href = base_uri + self.path + file_name
            file_display_name = file_name
            file_size = os.path.getsize(full_file_name)
            file_mtime = os.path.getmtime(full_file_name)
            format_mtime = time.strftime(
                "%Z %z %Y-%m-%d %H:%M:%S", time.localtime(file_mtime))

            if os.path.isdir(full_file_name):
                file_display_name = file_name + "/"
                file_href = file_href + "/"
            if os.path.islink(full_file_name):
                file_display_name = file_name + "@"

            # file_href = urllib.parse.quote(file_href)
            file_list_html = file_list_html + \
                "<li><a target='_self' href=\"{}\">{}</a><span style='position:absolute;float:right;right:55%;'>{}<span><span style='position:absolute;float:right;right:-100%;'>{} B<span></li>\n".format(
                    file_href, file_display_name, format_mtime, file_size
                )

        template = open(self.tpl_file)
        return template.read().format(uri_path, file_list_html).encode()


def start_https_server(listen_addr, listen_port, server_version, basic_authc_list,
                       certificate_file, tpl_file, data_dir):
    SimpleHTTPfsRequestHandler.server_version = server_version
    SimpleHTTPfsRequestHandler.tpl_file = tpl_file
    SimpleHTTPfsRequestHandler.data_dir = data_dir
    SimpleHTTPfsRequestHandler.basic_authc_list = basic_authc_list

    https_server = http.server.HTTPServer(
        (listen_addr, listen_port), SimpleHTTPfsRequestHandler)
    if certificate_file:
        https_server.socket = ssl.wrap_socket(
            https_server.socket, certfile=certificate_file, server_side=True)

    try:
        https_server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received, exiting bye ...")
        https_server.server_close()
        sys.exit(0)


def get_now_date():
    return time.strftime("%Z %z %Y-%m-%d %H:%M:%S",
                         time.localtime(time.time()))


def to_basic_authc(item):
    authcStr = cf.get("http.authc.basic", item)
    return {"authc_uri": item, "authc_info": base64.b64encode(authcStr.encode("utf-8")).decode("utf-8")}


if __name__ == '__main__':
    # if len(sys.argv) < 1:
    #     print("[-] USAGES: {} <CONFIG_PATH>".format(sys.argv[0]))
    #     sys.exit(1)

    # Read configuration.
    config_path = "/etc/simple_httpfs/server.ini"
    if len(sys.argv) > 1:  # The sys.argv[0] is this file.
        config_path = sys.argv[1]
    cf = configparser.ConfigParser()
    cf.read(config_path)

    listen_addr = cf.get("http.server", "listen_addr")
    listen_port = cf.getint("http.server", "listen_port")
    server_version = cf.get("http.server", "server_version")
    cert_file = cf.get("http.server", "cert_file")
    tpl_file = cf.get("fs.rendering", "tpl_file")
    data_dir = cf.get("fs.data", "data_dir")

    basic_authc_keys = cf.options("http.authc.basic")
    basic_authc_list = list(map(to_basic_authc, basic_authc_keys))
    # print(basic_authc_list[0]["authc_uri"] + " => " + basic_authc_list[0]["authc_info"])

    print("[{}] Starting simple HTTPFS server ...".format(get_now_date()))
    start_https_server(
        listen_addr,
        listen_port,
        server_version,
        basic_authc_list,
        cert_file,
        tpl_file,
        data_dir)
