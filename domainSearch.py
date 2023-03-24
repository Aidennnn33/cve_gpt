from time import sleep

class domain:
    ### Domain or Url Search
    # Find scan_id using by domain scan

    def domain_search(self, api, query):
        vulnerability_ip_list = set()
        scan_result = api.criminal_domain_scan(query)
        scan_id = scan_result['data']['scan_id']

        # Find ip using by domain search
        if scan_id != '':
            sleep(5)
            i = 1
            scan_ip = ''
            try:
                while(True):
                    report_result = api.criminal_domain_report(scan_id)
                    # Find Data using by scan_id
                    if (i < 30):
                        ++i
                        if 'No Search Data' in report_result['message']:
                            continue
                        else:
                            report_result_list = report_result['data']['mapped_ip']
                            for list in report_result_list:
                                scan_ip = list['ip']
                                # print(scan_ip)
                                vulnerability_ip_list.add(scan_ip)
                            break
                            
                    break
                return vulnerability_ip_list
            except Exception as e:
                print('[domain_search Error]')
                print(e)
        else:
            print("Cannot find Scan_id")
