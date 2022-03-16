#!/usr/bin/env python3

import base64
import datetime
from fileinput import filename
import json
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

defaultConfigPath = "/etc/simplehttpfs/server.ini"
defaultMimeTypes = "/etc/simplehttpfs/mime.types"
defaultFormTpl = "/etc/simplehttpfs/form.tpl"
defaultListingTpl = "/etc/simplehttpfs/index.tpl"
defaultServerVersion = "SimpleHTTPFS/2"
defaultAuthTokenName = "__tk"


class SimpleHTTPfsRequestHandler(http.server.BaseHTTPRequestHandler):
    mime_list = []
    form_tpl = defaultFormTpl
    data_dir = os.getcwd()
    listing_tpl = defaultListingTpl
    auth_token_name = defaultAuthTokenName
    current_authenticated_token_cookie = ""

    # Replace server headers from "Server: BaseHTTP/0.6 Python/3.6.7"
    server_version = defaultServerVersion
    sys_version = ""  # replaces Python/3.6.7

    def do_HEAD(self):
        if not self.is_authenticated("r"):
            return self.send_unauthentication()
        return self.do_get_index_page(False)

    def do_GET(self):
        if self.is_logout_request():
            return self.send_unauthentication()
        if not self.is_authenticated("r"):
            return self.send_unauthentication()
        return self.do_get_index_page(False)

    def do_POST(self):
        if not self.is_authenticated("r,w"):
            return self.send_unauthentication()

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

    def is_logout_request(self):
        uri_path = self.clean_path()
        return uri_path == "/logout"

    def is_authenticated(self, permit):
        uri_path = self.clean_path()

        request_token = self.get_auth_token()
        if request_token == None or request_token == '':
            self.log_message(
                "Failed to authentication. request auth is required! path: '%s'", self.path)
            return False

        decode_token = base64.b64decode(request_token).decode("utf-8")
        username = decode_token.split(":")[0]

        # Gets auth key by ACL
        auth_key = self.match_auth_key(username, uri_path, permit)

        # Matching authentication token
        if request_token == auth_key:
            self.set_auth_token(auth_key, 3600)
            return True
        else:
            self.log_message(
                "Failed to authentication. request auth: '%s', path: '%s'", request_token, self.path)
            return False

    def match_auth_key(self, username, uri_path, permit):
        for acl in self.acl_list:
            # Matching request username.
            if acl["username"] == username:
                # Matching request path (regex).
                for rule in acl["rules"]:
                    if re.match(rule["path"], uri_path, re.M | re.I) != None:
                        # Matching permits.
                        permit_matched = True
                        for p in permit.split(","):
                            if rule["permit"].find(p) < 0:
                                permit_matched = False
                        if permit_matched:
                            return acl["auth"]
        return None

    def get_auth_token(self):
        # First get from basic header
        token = self.headers["Authorization"]
        if token != '' and token != None:
            # remove prefix 'Basic '
            return token.split(" ")[1]
        # Second get from cookie
        cookies = self.headers.get('Cookie', '')
        if cookies != '':
            for cookie in cookies.split(";"):
                name = cookie.split("=")[0]
                value = cookie[len(self.auth_token_name)+1:]
                if name == self.auth_token_name:
                    return value
        return None

    def set_auth_token(self, token, deltaSeconds):
        schema = self.headers.get('X-Forwarded-Proto', "http://").lower()
        secure = secure = "" if schema.startswith("http") else "secure"
        domain = self.headers.get('Host', "localhost")
        # for example: "Tue, 15 Mar 2023 14:40:46 -0000"
        expiration = datetime.datetime.now() + datetime.timedelta(seconds=deltaSeconds)
        expires = expiration.strftime("%a, %d-%b-%Y %H:%M:%S PST")
        cookie = "{}={}; domain={}; path=/; expires={}; {}; HttpOnly".format(self.auth_token_name,
                                                                             token,
                                                                             domain,
                                                                             expires,
                                                                             secure)
        # Notice: 'self.send_header("Set-Cookie", cookie)' cannot be called directly, because it must be called
        # after 'self.send_response(200)', otherwise it will cause an error in the splicing http response spec.
        self.current_authenticated_token_cookie = cookie

    def send_unauthentication(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Basic realm=HttpBasicRealm")
        self.send_header("Content-type", "text/html")
        # Cleanup auth info.
        self.set_auth_token("", -1)
        self.send_header("Set-Cookie", self.current_authenticated_token_cookie)
        self.end_headers()
        self.close_connection = True
        return False

    def clean_path(self):
        # for example: http://example.com///abcd//1.jpg => /abcd/1.jpg
        cleaned_path = ""
        for part in self.path.split("/"):
            if len(part) > 0 and part != "/":
                cleaned_path += "/" + part
        endPart = ""
        if self.path.endswith("/"):
            endPart = "/"
        return cleaned_path + endPart

    # def is_root_request(self):
    #     self.clean_path()
    #     if len(self.path) <= 1:
    #         return True

    #     # for example: http://example.com// => //
    #     for part in self.path.split("/"):
    #         if len(part) > 0 and part != "/":
    #             return False
    #     return True

    def do_get_index_page(self,
                          is_redirect):
        uri_path = re.split(r'\?|\#', self.clean_path())[0]
        req_file_path = data_dir + uri_path

        if is_redirect:
            self.send_response(301)
            location = self.get_request_base_uri() + uri_path
            self.log_message("Redirecting %s", location)
            self.send_header("Location", location)
            self.end_headers()  # the response to browser
            return None

        # Response files html
        if os.path.isdir(req_file_path):
            contents_html = self. render_html_directies(
                req_file_path,
                uri_path)
            # self.log_message("Render html:\n%s", contents_html)

            self.send_response(200)
            # self.send_header("Content-type", "text/html")
            self.send_header("Content-Length", str(len(contents_html)))
            self.send_header(
                "Set-Cookie", self.current_authenticated_token_cookie)
            self.end_headers()
            self.wfile.write(contents_html)
            return None

        # Response download or rendering file
        try:
            req_file_path = urllib.parse.unquote(req_file_path)

            self.send_response(200)
            self.send_header("Content-Length",
                             str(os.stat(req_file_path).st_size))
            self.send_header(
                "Last-Modified", self.date_time_string(os.stat(req_file_path).st_mtime))

            is_find_media = False
            file_ext = req_file_path[req_file_path.rindex(".")+1:].lower()
            for media in self.mime_list:
                for suffix in media["suffixs"]:
                    if suffix.lower() == file_ext:
                        self.send_header("Content-type", media["media"])
                        is_find_media = True
                        break
            if not is_find_media:
                self.send_header("Content-type", "application/octet-stream")
            self.end_headers()

            if self.command == "GET":
                request_file = open(req_file_path, 'rb')
                shutil.copyfileobj(request_file, self.wfile)

                request_file.close()
        except IOError:
            self.send_error(404, "Not found file")
            return None

        return None

    def get_request_base_uri(self):
        schema = self.headers.get('X-Forwarded-Proto', "http")
        hostAndPort = self.headers.get('Host', "localhost")
        return schema + "://" + hostAndPort

    def render_html_directies(self,
                              req_file_path,
                              uri_path):
        self.log_message("Render html by uri: '%s' from directies: '%s'",
                         uri_path, req_file_path)
        try:
            file_list = os.listdir(req_file_path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return ""

        base_uri = self.get_request_base_uri()
        # uri_path = uri_path = '' if self.path == '/' '' else self.path
        listing_html = "<li><a target='_self' href='../'>../</a></li>\n"
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
            listing_html = listing_html + \
                "<li><a target='_self' href=\"{}\">{}</a><span style='position:absolute;float:right;right:55%;'>{}<span><span style='position:absolute;float:right;right:-100%;'>{} B<span></li>\n".format(
                    file_href, file_display_name, format_mtime, file_size
                )

        listing_tpl = open(self.listing_tpl, encoding="utf-8")
        form_content = "<!-- multipart from (non permission) -->"
        if self.is_authenticated("r,w"):
            form_content = ""
            form_lines = open(self.form_tpl, encoding="utf-8").readlines()
            for line in form_lines:
                form_content += line

        return listing_tpl.read().format(uri_path, form_content, listing_html).encode()


def start_https_server(listen_addr,
                       listen_port,
                       server_version,
                       certificate_file,
                       mime_list,
                       form_tpl,
                       listing_tpl,
                       auth_token_name,
                       acl_list,
                       data_dir):
    SimpleHTTPfsRequestHandler.server_version = server_version
    SimpleHTTPfsRequestHandler.mime_list = mime_list
    SimpleHTTPfsRequestHandler.form_tpl = form_tpl
    SimpleHTTPfsRequestHandler.listing_tpl = listing_tpl
    SimpleHTTPfsRequestHandler.auth_token_name = auth_token_name
    SimpleHTTPfsRequestHandler.acl_list = acl_list
    SimpleHTTPfsRequestHandler.data_dir = data_dir

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


def to_acl_info(item):
    username = item
    acl = json.loads(cf.get("http.acl", username))
    auth = username + ":" + acl["password"]
    auth = base64.b64encode(auth.encode("utf-8")).decode("utf-8")
    acl["auth"] = auth
    acl["username"] = username
    return acl


def to_mime_info(item):
    if len(item) > 3:
        parts = item.replace('\n', '').split("=")
        suffixs = []
        for suffix in parts[1].split(","):
            if len(suffix) > 0:
                suffixs.append(suffix)
        return {"suffixs": suffixs, "media": parts[0]}
    return None


if __name__ == '__main__':
    # Parse configuration.
    config_path = defaultConfigPath
    if len(sys.argv) > 1:  # The sys.argv[0] is this file.
        config_path = sys.argv[1]
    # Check config existing.
    if not os.path.exists(config_path):
        print("Bad configuration!\nUsage example: ./simple_httpfs ./config/server.ini, The \
default config load for: " + defaultConfigPath)
        sys.exit(1)
    cf = configparser.ConfigParser()
    cf.read(config_path)

    listen_addr = cf.get("http.server", "listen_addr")
    listen_port = cf.getint("http.server", "listen_port")
    server_version = cf.get("http.server", "server_version")
    cert_file = cf.get("http.server", "cert_file")
    auth_token_name = cf.get("http.auth", "auth_token_name")
    acl_rules = cf.options("http.acl")
    acl_list = list(map(to_acl_info, acl_rules))
    mime_types = cf.get("fs.rendering", "mime_types")
    form_tpl = cf.get("fs.rendering", "form_tpl")
    listing_tpl = cf.get("fs.rendering", "listing_tpl")
    data_dir = cf.get("fs.data", "data_dir")
    # print(acl_list[0]["auth"] + " => " + acl_list[0]["auth"])

    # mime types.
    mime_types = mime_types = defaultMimeTypes if mime_types == None or mime_types == '' else mime_types
    mime_lines = open(mime_types, encoding="utf-8").readlines()
    mime_list = list(map(to_mime_info, mime_lines))
    mime_list = [i for i in mime_list if i != None]

    print("[{}] Starting simple HTTPFS server ...".format(get_now_date()))
    start_https_server(
        listen_addr,
        listen_port,
        server_version,
        cert_file,
        mime_list,
        form_tpl,
        listing_tpl,
        auth_token_name,
        acl_list,
        data_dir)
