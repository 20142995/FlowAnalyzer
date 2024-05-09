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
