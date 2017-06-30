from OpenSSL import crypto
import pem as pem_reader


class X509(object):
    """
    Ops for info display and validation of X.509 certificates.
    """

    def __init__(self, pem_folder='certs'):
        self._pem_folder = pem_folder
        self._validate_init()
        self._pem = None
        self._pem_subject = None

    def load_certificate(self, unaffixed_pem_string):
        self._pem = crypto.load_certificate(
            crypto.FILETYPE_PEM, self._affix_pem_string(unaffixed_pem_string))
        self._pem_subject = self._pem.get_subject()

    def validate(self):
        # Create a X590StoreContext with the cert and trusted certs
        # and verify the the chain of trust
        store_ctx = crypto.X509StoreContext(self._trusted_pem_store, self._pem)
        # Returns None if certificate can be validated
        result = store_ctx.verify_certificate()

        if result is None:
            return True
        else:
            return False

    def _validate_init(self):
        # original validation related stuff
        # http://www.yothenberg.com/validate-x509-certificate-in-python/
        # here is a wrapper in class
        trusted_cert_pems = []
        # load ROOT CA
        trusted_cert_pems.append(self._load_pem_from_file('cacert.pem'))
        # load intermediate ca Google Internet Authority G2
        trusted_cert_pems.append(self._load_pem_from_file('GIAG2.pem'))

        # Create and fill a X509Sore with trusted certs
        self._trusted_pem_store = crypto.X509Store()
        for trusted_cert_pem in trusted_cert_pems:
            for pem in pem_reader.parse(trusted_cert_pem):
                trusted_cert = crypto.load_certificate(
                    crypto.FILETYPE_PEM, str(pem))
                self._trusted_pem_store.add_cert(trusted_cert)

    def _load_pem_from_file(self, filename):
        with open('{0}/{1}'.format(self._pem_folder, filename), 'r') as fp:
            return fp.read().encode('utf-8')

    def _load_pem_from_string(self, pem_string, unaffixed=True):
        if unaffixed:
            pem_string = self._affix_pem_string(pem_string)
        return bytes(pem_string, 'utf-8')

    def _affix_pem_string(self, unaffixed_pem_string):
        # makes pem 64-char wide
        unaffixed_pem_string = '\n'.join(unaffixed_pem_string[pos:pos+64] for pos in range(0, len(unaffixed_pem_string), 64))
        # add delimiter lines
        pem_prefix = '-----BEGIN CERTIFICATE-----'
        pem_suffix = '-----END CERTIFICATE-----'
        return '\n'.join((pem_prefix, unaffixed_pem_string, pem_suffix))

    # from self
    @property
    def isLegit(self):
        return self.validate()

    # from OpenSSL.crypto.X509Name
    @property
    def countryName(self):
        return self._pem_subject.countryName

    @property
    def stateOrProvinceName(self):
        return self._pem_subject.stateOrProvinceName

    @property
    def localityName(self):
        return self._pem_subject.localityName

    @property
    def organizationName(self):
        return self._pem_subject.organizationName

    @property
    def organizationalUnitName(self):
        return self._pem_subject.organizationalUnitName

    @property
    def commonName(self):
        return self._pem_subject.commonName

    @property
    def emailAddress(self):
        return self._pem_subject.emailAddress

    # from OpenSSL.crypto.X509
    @property
    def notAfter(self):
        return self._pem.get_notAfter()

    @property
    def notBefore(self):
        return self._pem.get_notBefore()

    @property
    def serial_number(self):
        return self._pem.get_serial_number()

    @property
    def signature_algorithm(self):
        return self._pem.get_signature_algorithm()

    @property
    def version(self):
        return self._pem.get_version()

    @property
    def has_expired(self):
        return self._pem.has_expired()

    @property
    def extension(self):
        exts = {}
        count = self._pem.get_extension_count()
        for i in range(count):
            ext = self._pem.get_extension(i)
            # not pythonic, upstream api problem
            exts[ext.get_short_name().decode(
                'utf-8')] = ext.__str__().replace('\n', '').strip()
        return exts

    # there's also some other attributes
    # too tedious, didn't implement
