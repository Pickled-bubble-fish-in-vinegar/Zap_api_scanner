
from zapv2 import ZAPv2
import argparse
import json
import requests
import re

parser = argparse.ArgumentParser()
parser.add_argument("-l", "--level", type=str, help='select level', default="low", choices=["low", "medium", "high"])
args = parser.parse_args()

######## Parameter Area ########
api_key = "a2n6pvs5kar6cdr9q54rkl53v6"
cookies = f"Cookie: i18n_redirected=zh; _ga=GA1.1.1937568691.1728503845; _ga_ZD59S22S8Y=GS1.1.1728503848.1.1.1728503867.41.0.0; PHPSESSID=avqs8tch8utoqafgv3o9ec6o0t; security={args.level}"
retry_times = 5
################################

# 初始化ZAP连接
zap = ZAPv2(apikey=api_key, proxies={
    'http': 'http://localhost:8080',
    'https': 'http://localhost:8080'
})

with open("./config/payload_dvwa.json", "r") as f:
    test_cases = json.load(f)


def attack(case):
    try:
        # build requests
        request = f"{case['method']} {case['url']} HTTP/1.1\r\n"
        request += f"Host: {case['url'].split('/')[2]}\r\n"
        request += "User-Agent: ZAP-Custom-Scanner\r\n"
        request += "Accept: */*\r\n"
        request += cookies + "\r\n"

        user_token = None
        # support for high level CSRF
        if case.get("user_token_url") and args.level == "high":
            res = requests.get(case["url"], headers={"Cookie": cookies})
            res = re.search("name='user_token' value='(.*?)'", res.text)
            user_token = res.group(1)

        if case.get('headers'):
            request += '\r\n'.join([f"{k}: {v}" for k, v in case['headers'].items()]) + '\r\n'

        # add params
        if case.get('params'):
            # support for high level CSRF
            if user_token is not None:
                case['params'].update({"user_token": user_token})

            query = '&'.join([f"{k}={v}" for k, v in case['params'].items()])
            request = request.replace(f"{case['url']}", f"{case['url']}?{query}")

        # add post data
        if case['method'] == 'POST' and case.get('data'):
            body = '&'.join([f"{k}={v}" for k, v in case['data'].items()])
            request += f"Content-Type: application/x-www-form-urlencoded\r\n"
            request += f"Content-Length: {len(body)}\r\n"
            request += "\r\n"
            request += body
        else:
            request += "\r\n"

        # 发送请求
        print(f"\nsend request => {case['method']} {request}")
        response_id = zap.core.send_request(request)
        response_body = response_id[0]["responseBody"]
        for k in case["evidence"]:
            if k in response_body:
                print(f"discovered evidence: {k}")
                message_id = int(response_id[0]["id"])
                zap.alert.add_alert(message_id, case["type"], 3, 1, case["type"], attack=case["url"], evidence=k)
                break
        return 0
    except Exception as e:
        print(f"encountered error: {e}")
        return -1


# execute cases
for case in test_cases:
    code = attack(case)
    retry_count = 0
    while code != 0 and retry_count < retry_times:
        print(f"retrying {retry_count + 1} times")
        code = attack(case)
        retry_count += 1





# generate report
with open(f'zap_report_dvwa_{args.level}.html', 'w', encoding='utf-8') as f:
    f.write(zap.core.htmlreport())

with open(f'zap_report_dvwa_{args.level}.json', 'w', encoding='utf-8') as f:
    f.write(zap.core.jsonreport())