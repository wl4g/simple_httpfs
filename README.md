# A Simple HttpFS

## Quick start

### Run

```bash
./simple_httpfs.py
#./simple_httpfs.py config/server.ini
```

### Configuration

- Default config load at: `/etc/simple_httpfs/server.ini`

- Config items description:

| Config Key | Type | Default Value | Example Value | Description |
|---|---|---|---|---|
|[http.server].listen_addr | string | 0.0.0.0 | 192.168.2.101 | Listening http server sock address. |
|[http.server].listen_port | int | 28001 | 8888 | Listening http server sock port. |
|[http.server].server_version | string | Google-SimpleHttpFS/2.0 | Microsoft-SimpleHttpFS/2.0 | http server information. |
|[http.server].cert_file | string | nil | /etc/simple_httpfs/server.pem | https tls certificate file path. |
|[http.acl].&lt;rule_name&gt;=&lt;username&gt;:&lt;password&gt;&lt;permits&gt;:&lt;regex_uri&gt; | string | &lt;required&gt; | `owner1=admin1:123:rw:^/owner1/(.*)` | Access authentication and authorization configuration, the example shows: when the request meets regex "`^/owner1/(.*)`", basic authentication is required to access of permits `r` and `w`, the username and password are: "`admin1:123`" |
|[fs.rendering].tpl_file | string | /etc/simple_httpfs/index.tpl | ./config/index.tpl | HttpFS rendering template file. |
|[fs.data].data_dir | string | &lt;work_dir&gt; | /mnt/disk1/httpfs | The directory where the actual files of HttpFS. |

- Generate self-signed certificate: `openssl req -new -x509 -keyout ./httpfs_server.pem -out ./httpfs_server.pem -days 365 -nodes -subj "/C=/ST=/O=/OU=/CN="`

- Nginx configuration

```bash
sudo mkdir -p /etc/nginx/conf.d/
sudo cat <<-EOF >/etc/nginx/conf.d/docs.conf
#
# Site for docs configuration.
#
server {
    listen          80;
    server_name     docs.wl4g.io;

    #listen         443 ssl;             
    #server_name    docs.wl4g.com;        
    #ssl_certificate cert.d/docs.wl4g.com.pem;
    #ssl_certificate_key cert.d/docs.wl4g.com.key;
    #ssl_session_timeout 5m;           
    #ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
    #ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    #ssl_prefer_server_ciphers on;     

    proxy_set_header  Host $host;
    proxy_set_header  X-Real-IP        $remote_addr;
    proxy_set_header  X-Forwarded-For  $proxy_add_x_forwarded_for;

    location / {
      proxy_pass http://localhost:28001;
    }
}
EOF

sudo systemctl restart nginx
```
