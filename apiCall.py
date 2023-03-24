"""
CriminalIP.client

This module implements the CriminalIP API
"""

from exception import APIError

import requests
import time
import json

class CriminalIP:
    
    def __init__(self, cip_key=None):
        self.cip_key = cip_key
        self.api_url = 'https://api.criminalip.io'
        self.api_query_time = None
        self.api_limit_rate = 1
        self.session = requests.Session()
        self.session.proxies = None
        self.basestring = str
        self.baseint = int
    
    def _request(self, function, params=None, method='get'):
        
        base_url = self.api_url
        headers = {"x-api-key" : self.cip_key}

        # Wait for API rate limit
        if self.api_query_time is not None and self.api_limit_rate > 0:
            while(1.0 / self.api_limit_rate) + self.api_query_time >= time.time():
                time.sleep(0.1 / self.api_limit_rate)

        # Send Requets
        try:
            method = method.lower()
            
            if method == 'post':
                data = self.session.post(base_url + function, params, headers=headers)
            elif method == 'put':
                data = self.session.put(base_url + function, params=params)
            elif method =='delete':
                data = self.session.delete(base_url + function, params=params)
            else:
                data = self.session.get(base_url + function, params=params, headers=headers)
            self.api_query_time = time.time()
        except Exception as e:
            print("Occur Api Error")
            raise APIError("Unable to connect to CriminalIP") 

        # Check that the API key wasn't rejected
        if data.status_code == 401:
            try:
                # Return the actual error message if the API returned valid JSON
                error = data.json()['error']
            except Exception as e:
                # If the response looks like HTML then it's probably the 401 page that nginx returns
                # for 401 responses by default
                if data.text.startswith('<'):
                    error = 'Invalid API key'
                else:
                    # Otherwise lets raise the error message
                    error = u'{}'.format(e)

            raise APIError(error)
        elif data.status_code == 403:
            raise APIError('Access denied (403 Forbidden)')
        elif data.status_code == 502:
            raise APIError('Bad Gateway (502)')

        # Parse the text into JSON
        try:
            #data = data.json()
            data = json.loads(data.text)
        except ValueError:
            raise APIError('Unable to parse JSON response')

        # Raise an exception if an error occurred
        if type(data) == dict and 'error' in data:
            raise APIError(data['error'])

        # Return the data
        # print("data: " + json.dumps(data))
        #   return json.dumps(data)
        return data
        
    def criminal_domain_scan(self, domain):
        #Get all available data

        if isinstance(domain, self.basestring):
            params = {}
            params['query'] = domain
        return self._request('/v1/domain/scan', params, method='post')


    def criminal_domain_report(self, scan_id):
        #Get all available data

        if isinstance(scan_id, self.baseint):
            params = {}
            params['id'] = scan_id
        return self._request('/v1/domain/report/%d' %params['id'])
    
    def criminal_asset_data(self, scan_ip):
        #Get all available data

        if isinstance(scan_ip, self.basestring):
            params = {}
            params['ip'] = scan_ip
        return self._request('/v1/ip/data', params)
    
    def criminal_banner_search(self, banner_name, offset):
        #Get all available data

        if isinstance(banner_name, self.basestring):
            params = {}
            params['query'] = banner_name
            params['offset'] = offset
        return self._request('/v1/banner/search', params)
