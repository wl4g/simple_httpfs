# A Simple HttpFS

## 1. Quick deployment

- Preparing testdata

```bash
sudo mkdir -p /mnt/disk1/simplehttpfs/{dir1,dir2}
sudo echo 'Hello world' > /mnt/disk1/simplehttpfs/hello.txt
sudo echo 'Hello world 1' > /mnt/disk1/simplehttpfs/dir1/hello1.txt
sudo echo 'Hello world 2' > /mnt/disk1/simplehttpfs/dir2/hello2.txt

tree /mnt/disk1/simplehttpfs/
.
├── hello.txt
├── dir1
│   └── hello1.txt
└── dir2
    └── hello2.txt

2 directories, 3 files
```

- Configuring nginx

```bash
sudo echo '127.0.0.1  pkg.wl4g.io' >> /etc/hosts

sudo mkdir -p /etc/nginx/conf.d/
sudo cat <<-EOF >/etc/nginx/conf.d/pkg.conf
#
# Site for pkg configuration.
#
server {
    listen          80;
    server_name     pkg.wl4g.io;

    #listen         443 ssl;             
    #server_name    pkg.wl4g.io;        
    #ssl_certificate cert.d/pkg.wl4g.io.pem;
    #ssl_certificate_key cert.d/pkg.wl4g.io.key;
    #ssl_session_timeout 5m;           
    #ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
    #ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    #ssl_prefer_server_ciphers on;

    proxy_set_header  Host              $host;
    proxy_set_header  X-Real-IP         $remote_addr;
    proxy_set_header  X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header  X-Forwarded-Proto $scheme;

    location / {
      proxy_pass http://localhost:28001;
    }
}
EOF

sudo systemctl restart nginx
```

- Startup

```bash
git clone https://gitee.com/wl4g/simple_httpfs.git
cd simple_httpfs/

# Run
./apps/simple_httpfs.py config/server.ini

# Build & package
make
```

- Browser access

  - http://pkg.wl4g.io/
  - More details sample screenshots, please visit: [gitee.com/wl4g/simple_httpfs/blob/master/shots](https://gitee.com/wl4g/simple_httpfs/blob/master/shots)

## 2. Configuration items

- Default config load at: `/etc/simple_httpfs/server.ini`

- Config items description:

| Config Key | Type | Default Value | Example Value | Description |
|---|---|---|---|---|
|[http.server].listen_addr | string | 0.0.0.0 | 192.168.2.101 | Listening http server sock address. |
|[http.server].listen_port | int | 28001 | 8888 | Listening http server sock port. |
|[http.server].server_version | string | Google-SimpleHttpFS/2.0 | Microsoft-SimpleHttpFS/2.0 | http server information. |
|[http.server].cert_file | string | nil | /etc/simple_httpfs/server.pem | https tls certificate file path. |
|[http.acl].&lt;username&gt;=&lt;acl_rule_json&gt; | string | &lt;required&gt; | `admin={"password":"123","rules":[{"path":"^/(.*)","permit": "rw"}]}` | Access controller list configuration, the example indicates that the user `user1` is allowed to request resources that satisfy the path `^/dir1/(.*)` and the permissions are `r` and `w`, **Tips**: only when it has the 'w' permission The upload file button will appear. More example see: [config/server.ini](config/server.ini)|
|[fs.rendering].mime_types | string | /etc/simple_httpfs/mime_types | ./config/index.tpl | HttpFS rendering template file. |
|[fs.rendering].tpl_file | string | /etc/simple_httpfs/index.tpl | ./config/index.tpl | HttpFS rendering template file. |
|[fs.data].data_dir | string | &lt;work_dir&gt; | /mnt/disk1/httpfs | The directory where the actual files of HttpFS. |

- If you need to use https, you can use openssl self-signed certificate: `openssl req -new -x509 -keyout ./httpfs_server.pem -out ./httpfs_server.pem -days 365 -nodes -subj "/C=/ST=/O=/OU=/CN="`
