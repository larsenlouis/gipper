import requests
from utils.country_codes import CountryCodes
import re


class IPRangeGrabber(object):
    """
    grab the latest ip ranges of countries/regions
    """
    def __init__(self, countries):
        self._cidr_collection = []
        for country in countries:
            if country not in CountryCodes.LIST:
                print('Country code \'{}\' is invalid. Skipped...'.format(country))
                continue
            headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive',
                'Referer': 'http://ipblock.chacuo.net/view/c_{}'.format(country)
            }
            r = requests.get(
                'http://ipblock.chacuo.net/down/t_file=c_{}'.format(country), headers=headers)
            ip_file = r.content.decode('utf-8')
            cidrs = re.findall(
                r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d|(?:\.\d))", ip_file)
            self._cidr_collection.append(' '.join(cidrs))

    @property
    def collection(self):
        return self._cidr_collection
