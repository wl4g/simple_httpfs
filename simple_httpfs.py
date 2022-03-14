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
    form_tpl = '/etc/simplehttpfs/form.tpl'
    listing_tpl = '/etc/simplehttpfs/index.tpl'
    data_dir = os.getcwd()

    # Replace server headers from "Server: BaseHTTP/0.6 Python/3.6.7"
    server_version = "SimpleHTTPFS/2"
    sys_version = ""  # replaces Python/3.6.7

    def is_authenticated(self, permits):
        uri_path = self.clean_path()

        basic_auth_key = ""
        for acl in self.acl_list:
            # Matches request path with regex.
            route_matched = re.match(acl["route_regex"],
                                     uri_path, re.M | re.I) != None
            if route_matched:
                permits_matched = True
                for p in permits.split(","):
                    if acl["permits"].find(p) < 0:
                        permits_matched = False
                if permits_matched:
                    basic_auth_key = "Basic " + acl["basic_auth"]
                    break

        authorization_header = self.headers["Authorization"]
        if authorization_header != basic_auth_key:
            self.log_message(
                "Failure basic authentication. request authorization: '%s', path: '%s'", authorization_header, self.path)
            return False

        return True

    def do_authentication(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Basic realm=HttpBasicRealm")
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.close_connection = True
        return False

    def do_HEAD(self):
        if not self.is_authenticated("r"):
            return self.do_authentication()
        return self.do_get_index_page(False)

    def do_GET(self):
        if not self.is_authenticated("r"):
            return self.do_authentication()
        return self.do_get_index_page(False)

    def do_POST(self):
        if not self.is_authenticated("r,w"):
            return self.do_authentication()

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

        return self.do_get_index_page(True, "rw")

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
            self.send_header("Content-type", "text/html")
            self.send_header("Content-Length", str(len(contents_html)))
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
            return None

        return None

    def get_request_base_uri(self):
        schema = self.headers.get('X-Forwarded-Proto', "http://")
        hostAndPort = self.headers.get('Host', "localhost")
        return schema + hostAndPort

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
                       acl_list,
                       certificate_file,
                       form_tpl,
                       listing_tpl,
                       data_dir):
    SimpleHTTPfsRequestHandler.server_version = server_version
    SimpleHTTPfsRequestHandler.form_tpl = form_tpl
    SimpleHTTPfsRequestHandler.listing_tpl = listing_tpl
    SimpleHTTPfsRequestHandler.data_dir = data_dir
    SimpleHTTPfsRequestHandler.acl_list = acl_list

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
    # for example: owner1_readwrite=admin1:123:rw:^/owner1/(.*)
    value = cf.get("http.acl", item)
    parts = value.split(":")
    basic_auth = parts[0] + ":" + parts[1]
    permits = parts[2]
    route_regex = parts[3]
    return {"basic_auth": base64.b64encode(basic_auth.encode("utf-8")).decode("utf-8"), "permits": permits, "route_regex": route_regex}


if __name__ == '__main__':
    # if len(sys.argv) < 1:
    #     print("[-] USAGES: {} <CONFIG_PATH>".format(sys.argv[0]))
    #     sys.exit(1)

    # Read configuration.
    config_path = "/etc/simplehttpfs/server.ini"
    if len(sys.argv) > 1:  # The sys.argv[0] is this file.
        config_path = sys.argv[1]
    cf = configparser.ConfigParser()
    cf.read(config_path)

    listen_addr = cf.get("http.server", "listen_addr")
    listen_port = cf.getint("http.server", "listen_port")
    server_version = cf.get("http.server", "server_version")
    cert_file = cf.get("http.server", "cert_file")
    form_tpl = cf.get("fs.rendering", "form_tpl")
    listing_tpl = cf.get("fs.rendering", "listing_tpl")
    data_dir = cf.get("fs.data", "data_dir")

    acl_routes = cf.options("http.acl")
    acl_list = list(map(to_acl_info, acl_routes))
    # print(acl_list[0]["route_regex"] + " => " + acl_list[0]["basic_auth"])

    print("[{}] Starting simple HTTPFS server ...".format(get_now_date()))
    start_https_server(
        listen_addr,
        listen_port,
        server_version,
        acl_list,
        cert_file,
        form_tpl,
        listing_tpl,
        data_dir)
