# ngx_http_auth_file_module

It amis to provide the power of authenticate for nginx. For example, it can work together with these module such as [ngx_http_barcode](https://github.com/x-v8/ngx_http_barcode)、 [ngx_http_qrcode_module](https://github.com/x-v8/ngx_http_qrcode_module)、any http module which work on nginx content phase and so on. By the way, it can change auth file on the fly without reload nginx.

Example:
````
http {
    ...

    server {
        server_name www1.example.com;
        auth_file auth/www1.example.com;
    }
}

#www1.example.com
3iVrBX/Sg6II6yC1nQR/QQSaums6xRU31etxyv+ESUs=
EGDi98j1e3CwlXOz1NuHXSLA8Xq3Vo55mzeoFFOWr+o=
0xE+6IKEMaUUpyeCbd0hHt3IPYY7W1bckG8E6LtdObQ=
````

we can access the server www1.example.com by 
````bash
curl -H "Authorization:  0xE+6IKEMaUUpyeCbd0hHt3IPYY7W1bckG8E6LtdObQ=" http://www1.example.com 
````
If you want to change the auth file, just do the op as the following:
````bash
>openssl rand -base64 32
pNGJQfDjyAgbqmMeydhsgNZ8lEkW88RfDWTtJXMmHrU
#when adding the password to auth/www1.example.com then send reopen signal to nginx

>/opt/nginx/sbin/nginx -s reopen
````

Table of Contents
-----------------
* [Direction](#direction)
* [Contributing](#contributing)
* [Author](#author)
* [License](#license)


#Direction

Syntax:	auth_file file             
Default:	-           
Context:	http, server, location            

Example:
````
http {
    auth_file auth/global;
    ...

    server {
        server_name www1.example.com;
        auth_file auth/www1.example.com;
    }
}
````


Contributing
------------

To contribute to ngx_http_auth_file_module, clone this repo locally and commit your code on a separate branch.


Author
------

> GitHub [@detailyang](https://github.com/detailyang)


License
-------
ngx_http_auth_file_module is licensed under the [MIT] license.

[MIT]: https://github.com/detailyang/ybw/blob/master/licenses/MIT
