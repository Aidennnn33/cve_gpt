from time import sleep

import sys
import apiCall
import multiprocessing
import domainSearch as ds
import keywordSearch as ks

class cveGpt():

    def __init__(self):
        self.result_list = set()
    

    if (len(sys.argv)) < 2:
        print("Usage : python cveGpt.py")
        print("##### Example #####")
        print("Choose option : 2")
        print("Input Criminal API Key : <criminal api key>")
        print("Input Search Query : ssh")
        print("Input Offset Number : 0")

    def init_setting(self, choice):

        Criminal_API_KEY = input("Criminal API Key > ")
        query = input("What Search > ")
        if choice == '1':
            offset = None
        elif choice == '2':
            offset = input("Offset Number > ")

        api = apiCall.CriminalIP(Criminal_API_KEY)

        return api, query, offset

    # Main()
    # Collect domain information and cve_id and cve_description values exposed to the ip through the scanned ip
    def main(self):

        print("==============================================================")
        print(" _____        _             _                _   _____ ______")
        print("/  __ \      (_)           (_)              | | |_   _|| ___ \\" )
        print("| /  \/ _ __  _  _ __ ___   _  _ __    __ _ | |   | |  | |_/ /")
        print("| |    | '__|| || '_ ` _ \ | || '_ \  / _` || |   | |  |  __/ ")
        print("| \__/\| |   | || | | | | || || | | || (_| || |  _| |_ | |    ")
        print(" \____/|_|   |_||_| |_| |_||_||_| |_| \__,_||_|  \___/ \_|    ")
        print("==============================================================")
        print()
                                                                                                                            
        print("=" * 20, end='')
        print(" Select Option 1 or 2 ", end='')
        print("=" * 20)
        print(""" 1. Domain or Url 2. Keyword""")
        choice = input("> ")

        api, query, offset = self.init_setting(choice)

        if choice == '1':
            # self.domain_search(api, query)
            self.result_list = ds.domain.domain_search(self, api, query)
        elif choice == '2':
            # self.keyword_search(api, query, int(offset))
            self.result_list = ks.keyword.keyword_search(self, api, query, int(offset))
        else:
            raise Exception
        
        process_name = multiprocessing.current_process().name

        if len(self.result_list) > 0:
            print('[Main Process Start] ' + process_name)
            for ip in self.result_list:
                try:
                    scan_result = api.criminal_asset_data(ip)
                    # cve_id deduplication
                    reduce_list = list({result['cve_id']: result for result in scan_result['vulnerability']['data']}.values())

                    if len(scan_result['domain']['data']) > 0:
                        for domain in scan_result['domain']['data']:
                            ip_domain_list = {}
                            ip_domain_list['ip'] = ip
                            ip_domain_list['domain'] = domain['domain']
                            print("*" * 30)
                            print("ip & domain info: ", end='')
                            print(ip_domain_list)
                            print()
                            
                            if len(reduce_list) > 0:
                                for cve_id in reduce_list:
                                    print('cve_id: ' + cve_id['cve_id'])
                                    print('description: ' + cve_id['cve_description'])
                                print("*" * 30)
                            else:
                                print('No Vulnerability Data')
                    if len(scan_result['hostname']['data']) > 0:
                        for domain in scan_result['hostname']['data']:
                            ip_domain_list = {}
                            ip_domain_list['ip'] = ip
                            ip_domain_list['domain'] = domain['domain_name_full']
                            print("*" * 30)
                            print("ip & domain info: ", end='')
                            print(ip_domain_list)
                            print()

                            if len(reduce_list) > 0:
                                for cve_id in reduce_list:
                                    print('cve_id: ' + cve_id['cve_id'])
                                    print('description: ' + cve_id['cve_description'])
                                print("*" * 30)
                            else:
                                print('No Vulnerability Data')
                    else:
                        print("*" * 30)
                        print('No Domain info & ip info: ' + ip)

                        if len(reduce_list) > 0:
                            for cve_id in reduce_list:
                                print('cve_id: ' + cve_id['cve_id'])
                                print('description: ' + cve_id['cve_description'])
                            print("*" * 30)
                        else:
                            print('No Vulnerability Data')

                except Exception as e:
                    print(e)

if __name__ == '__main__':
    scan = cveGpt()
    scan.main()
