#!/usr/bin/env python3

import base64
from fileinput import filename
import os
import re
import shutil
import string
import sys
import time
import urllib

import cgi
import http.server
import ssl


class CustomBaseHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    data_dir = '.'

    # Replace server headers from "Server: BaseHTTP/0.6 Python/3.6.7"
    server_version = "Microsoft-HTTPSERVER/2.0"  # replaces BaseHTTP/0.6
    sys_version = ""  # replaces Python/3.6.7

    def is_authenticated(self):
        authorization_header = self.headers["Authorization"]

        if authorization_header != self.basic_authentication_key:
            self.do_authentication()
            self.close_connection = True
            return False

        return True

    def do_authentication(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Basic realm=\"MyRealm\"")
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_HEAD(self):
        # print("do_head ...", self)
        return self.do_get_index_page(False)

    def do_GET(self):
        # print("do_get ...", self)
        return self.do_get_index_page(False)

    def do_POST(self):
        # print("do_post ...", self)
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
        #default_req_file_path = os.getcwd() + uri_path
        req_file_path = data_dir + uri_path

        if is_redirect:
            self.send_response(301)
            schema = self.headers.get('X-Forwarded-Proto', "http://")
            hostAndPort = self.headers.get('Host', "")
            location = schema + hostAndPort + "/admin" + uri_path
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

    def render_html_directies(self, req_file_path, uri_path):
        self.log_message("Render html by uri: '%s' from directies: '%s'",
                         uri_path, req_file_path)

        # TODO: change header path
        try:
            file_list = os.listdir(req_file_path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return ""

        file_list_html = "<li><a target='_self' href='../'>../</a></li>\n"
        for file_name in file_list:
            full_file_name = req_file_path + "/" + file_name
            file_href = file_display_name = file_name
            file_size = os.path.getsize(full_file_name)
            file_mtime = os.path.getmtime(full_file_name)
            format_mtime = time.strftime(
                "%Z %Y-%m-%d %H:%M:%S", time.localtime(file_mtime))

            if os.path.isdir(file_name):
                file_display_name = file_name + "/"
                file_href = file_href + "/"
            if os.path.islink(file_name):
                file_display_name = file_name + "@"

            file_list_html = file_list_html + \
                "<li><a target='_self' href=\"{}\">{}</a><span style='position:absolute;float:right;right:70%;'>{}<span><span style='position:absolute;float:right;right:-100%;'>{} B<span></li>\n".format(
                    urllib.parse.quote(
                        file_href), file_display_name, format_mtime, file_size
                )

        return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Microsoft-HTTPSERVER/2.0</title>
            </head>
            <body>
                <h2>Index of: {}</h2>
                <hr>
                <form ENCTYPE="multipart/form-data" method="post" onsubmit="javascript:return document.getElementById('file').value.length>0;">
                    <a style='position:absolute;width:100px;height:30px;margin-top:-2px;background-color:blue;text-align:center;border-radius:30px;color:white;box-shadow:2px 2px 3px #ccacac;font-weight:600;cursor:pointer;line-height:30px;'>Choose file</a>
                    <input id="file" name="file" type="file" style='position:relative;width:189px;height:30px;left:-88px;top:-6px;z-index:300;opacity:0;border-radius:47px;cursor:pointer;'/>
                    <input type="submit" value="Upload" style='position:relative;top:-2px;width:100px;height:30px;z-index:300;border-radius:47px;cursor:pointer;background:green;color:white;border:0;box-shadow:2px 2px 3px #ccacac;transition-duration:0.3s;font-weight:600;'/>
                </form>
                <hr>
                <ul>
                    {}
                </ul>
                <hr>
            </body>
            </html>
        """.format(uri_path, file_list_html).encode()


def start_https_server(listening_port, basic_authentication_key, data_dir, certificate_file):
    CustomBaseHTTPRequestHandler.basic_authentication_key = "Basic " + \
        basic_authentication_key.decode("utf-8")
    CustomBaseHTTPRequestHandler.data_dir = data_dir

    https_server = http.server.HTTPServer(
        ("0.0.0.0", listening_port), CustomBaseHTTPRequestHandler)
    if certificate_file:
        https_server.socket = ssl.wrap_socket(
            https_server.socket, certfile=certificate_file, server_side=True)

    try:
        https_server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received, exiting...")
        https_server.server_close()
        sys.exit(0)


if __name__ == '__main__':
    # TODO: add start path
    # TODO: add fix for path traversal
    # openssl req -new -x509 -keyout .config/https_upload/server.pem -out .config/https_upload/server.pem -days 365 -nodes -subj "/C=/ST=/O=/OU=/CN="
    if len(sys.argv) < 4:
        print(
            "[-] USAGE: {} <PORT> <USERNAME:PASSWORD> <DATA_DIR> [CERTIFICATE FILE]".format(sys.argv[0]))
        sys.exit(1)

    listening_port = int(sys.argv[1])
    basic_authentication_key = base64.b64encode(
        sys.argv[2].encode("utf-8"))  # binary
    data_dir = sys.argv[3]
    certificate_file = sys.argv[4] if len(sys.argv) == 5 else False
    print("[+] Staring server...")
    start_https_server(
        listening_port, basic_authentication_key, data_dir, certificate_file)
