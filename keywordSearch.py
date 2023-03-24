
class keyword:
    ### Keyword Seaerch
    # Find ip using by banner Search

    def keyword_search(self, api, query, offset):
        vulnerability_ip_list = set()
        try:
            banner_result = api.criminal_banner_search(query, offset)

            for has_cve in banner_result['data']['result']:
                if has_cve['has_cve']:
                    find_ip = has_cve['ip_address']
                    vulnerability_ip_list.add(find_ip)
            return vulnerability_ip_list
        except Exception as e:
            print('[keyword_search Error]')
            print(e)
