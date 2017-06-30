import re
from utils.cert_ops import X509


class LogReader(object):
    """
    read ips and certs from masscan grepable log
    """
    GVS = 0
    GWS = 1

    def __init__(self, log_file):
        self._ip_pool_gws = []
        self._ip_pool_gvs = []
        self._cursor = None
        self._cert_handler = X509()
        self._trusted_gws_common_names = ["*.google.com", "google.com"]
        self._trusted_gvs_common_names = ["*.googlevideo.com"]
        self._trusted_common_names = self._trusted_gws_common_names + self._trusted_gvs_common_names

        with open(log_file, 'r') as f:
            reg = re.compile(
                r'^Host: (?P<ip>(\d{1,3}\.){3}\d{1,3}) \(\)\tPort: 443\tService: X509\tBanner: (?P<cert>(.*))$')
            for line in f:
                match = reg.match(line)
                if match:
                    ip = match.group('ip')
                    cert = match.group('cert')
                    try:
                        self._cert_handler.load_certificate(cert)
                        cert_common_name = self._cert_handler.commonName
                        if cert_common_name in self._trusted_common_names:
                            # matched GCE servers
                            if cert_common_name in self._trusted_gvs_common_names:
                                # gvs
                                if self._cert_handler.isLegit:
                                    self._ip_pool_gvs.append(ip)
                            else:
                                # gws
                                if self._cert_handler.isLegit:
                                    self._ip_pool_gws.append(ip)
                            # print(ip, self._cert_handler.commonName)
                            pass
                    except Exception as e:
                        # has some strange load_certificate errors, just ignore
                        # [('asn1 encoding routines', 'ASN1_get_object', 'too long'), ('asn1 encoding routines', 'ASN1_CHECK_TLEN', 'bad object header'), ('asn1 encoding routines', 'ASN1_ITEM_EX_D2I', 'nested asn1 error'), ('PEM routines', 'PEM_ASN1_read_bio', 'ASN1 lib')]
                        continue

    def __iter__(self):
        self._cursor = 0
        return self

    def __next__(self):
        if self._cursor < len(self._ip_pool_gws):
            ip_gws = self._ip_pool_gws[self._cursor]
            self._cursor += 1
            return (ip_gws, self.GWS)
        elif self._cursor - len(self._ip_pool_gws) < len(self._ip_pool_gvs):
            ip_gvs = self._ip_pool_gvs[self._cursor - len(self._ip_pool_gws)]
            self._cursor += 1
            return (ip_gvs, self.GVS)
        else:
            raise StopIteration

    @property
    def gws_pool(self):
        return self._ip_pool_gws

    @property
    def gvs_pool(self):
        return self._ip_pool_gvs

    @property
    def ip_pool(self):
        return self._ip_pool_gws + self._ip_pool_gvs
