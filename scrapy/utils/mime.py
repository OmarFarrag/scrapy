"""
This module is used to extract MIME types from resources according to standard
mentioned in 'https://mimesniff.spec.whatwg.org/#javascript-mime-type'

STILL IN PROGRESS
"""

import re
from mimetypes import MimeTypes as MT
from scrapy.utils.python import to_bytes, to_native_str


class MimeTypes(object):

    _WHITESSPACE_BYTES = [0x09, 0x0A, 0x0C, 0x0D, 0x20]
    _PATTERN_TYPES = [
        ([0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54, 0x59, 0x50, 0x45, 0x20, 0x48, 0x54, 0x4D, 0x4C, 0x20],
        [0xFF, 0xFF, 0xDF, 0xDF, 0xDF, 0xDF, 0xDF, 0xDF, 0xDF, 0xFF, 0xDF, 0xDF, 0xDF, 0xDF, 0xFF], _WHITESSPACE_BYTES, 'text/html' ),
        ([0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54, 0x59, 0x50, 0x45, 0x20, 0x48, 0x54, 0x4D, 0x4C, 0x3E],
        [0xFF, 0xFF, 0xDF, 0xDF, 0xDF, 0xDF, 0xDF, 0xDF, 0xDF, 0xFF, 0xDF, 0xDF, 0xDF, 0xDF, 0xFF], _WHITESSPACE_BYTES, 'text/html' ),
        ([0x3C, 0x48, 0x54, 0x4D, 0x4C, 0x20], [0xFF, 0xDF, 0xDF, 0xDF, 0xDF, 0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C, 0x48, 0x54, 0x4D, 0x4C, 0x3E], [0xFF, 0xDF, 0xDF, 0xDF, 0xDF, 0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C, 0x48, 0x45, 0x41, 0x44, 0x20], [0xFF, 0xDF, 0xDF, 0xDF, 0xDF, 0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C, 0x48, 0x45, 0x41, 0x44, 0x3E], [0xFF, 0xDF, 0xDF, 0xDF, 0xDF, 0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C, 0x53, 0x43, 0x52, 0x49, 0x50, 0x54, 0x20], [0xFF, 0xDF, 0xDF, 0xDF, 0xDF, 0xDF, 0xDF, 0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C, 0x53, 0x43, 0x52, 0x49, 0x50, 0x54, 0x3E], [0xFF, 0xDF, 0xDF, 0xDF, 0xDF, 0xDF, 0xDF, 0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C, 0x49, 0x46, 0x52, 0x41, 0x4D, 0x45, 0x20], [0xFF, 0xDF, 0xDF, 0xDF, 0xDF, 0xDF, 0xDF, 0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C, 0x49, 0x46, 0x52, 0x41, 0x4D, 0x45, 0x3E], [0xFF, 0xDF, 0xDF, 0xDF, 0xDF, 0xDF, 0xDF, 0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x48 ,0x31 ,0x20], [0xFF,0xDF,0xFF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x48 ,0x31 ,0x3E], [0xFF,0xDF,0xFF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x44 ,0x49 ,0x56 ,0x20], [0xFF,0xDF,0xDF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x44 ,0x49 ,0x56 ,0x3E], [0xFF,0xDF,0xDF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x46 ,0x4F ,0x4E ,0x54 ,0x20], [0xFF,0xDF,0xDF,0xDF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x46 ,0x4F ,0x4E ,0x54 ,0x3E], [0xFF,0xDF,0xDF,0xDF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x54 ,0x41 ,0x42 ,0x4C ,0x45 ,0x20], [0xFF,0xDF,0xDF,0xDF,0xDF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x54 ,0x41 ,0x42 ,0x4C ,0x45 ,0x3E], [0xFF,0xDF,0xDF,0xDF,0xDF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x41 ,0x20], [0xFF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x41 ,0x3E], [0xFF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x53 ,0x54 ,0x59 ,0x4C ,0x45 ,0x20], [0xFF,0xDF,0xDF,0xDF,0xDF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x53 ,0x54 ,0x59 ,0x4C ,0x45 ,0x3E], [0xFF,0xDF,0xDF,0xDF,0xDF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x54 ,0x49 ,0x54 ,0x4C ,0x45 ,0x20], [0xFF,0xDF,0xDF,0xDF,0xDF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x54 ,0x49 ,0x54 ,0x4C ,0x45 ,0x3E], [0xFF,0xDF,0xDF,0xDF,0xDF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x42 ,0x20], [0xFF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x42 ,0x3E], [0xFF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x42 ,0x4F ,0x44 ,0x59 ,0x20], [0xFF,0xDF,0xDF,0xDF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x42 ,0x4F ,0x44 ,0x59 ,0x3E], [0xFF,0xDF,0xDF,0xDF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x42 ,0x52 ,0x20], [0xFF,0xDF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x42 ,0x52 ,0x3E], [0xFF,0xDF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x50 ,0x20], [0xFF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x50 ,0x3E], [0xFF,0xDF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x21 ,0x2D ,0x2D ,0x20], [0xFF,0xFF,0xFF,0xFF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x21 ,0x2D ,0x2D ,0x3E], [0xFF,0xFF,0xFF,0xFF,0xFF], _WHITESSPACE_BYTES, 'text/html'),
        ([0x3C ,0x3F ,0x78 ,0x6D ,0x6C], [0xFF,0xFF,0xFF,0xFF,0xFF], _WHITESSPACE_BYTES, 'text/xml'),
        ([0x25 ,0x50 ,0x44 ,0x46 ,0x2D], [0xFF,0xFF,0xFF,0xFF,0xFF], [], 'application/pdf'),
        ([0x25 ,0x21 ,0x50 ,0x53, 0x2D, 0x41, 0x64, 0x6F, 0x62 ,0x65 ,0x2D], [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], [], 'application/postscript'),
        ([0xFE ,0xFF ,0x00 ,0x00], [0xFF ,0xFF ,0x00 ,0x00], [], 'text/plain'),
        ([0xFF ,0xFE ,0x00 ,0x00], [0xFF ,0xFF ,0x00 ,0x00], [], 'text/plain'),	
        ([0xEF ,0xBB ,0xBF ,0x00], [0xFF ,0xFF ,0xFF ,0x00], [], 'text/plain'),
    ]
    _EXTENSIONS = {
        'text/html': '.html',
        'text/xml': '.xml' ,
        'text/*': '.txt', 
        'text/json': '.txt',
        'application/xml': '.xml', 
        'application/x-xml': '.xml',
        'application/atom+xml': '.xml',
        'application/rdf+xml': '.xml',
        'application/rss+xml': '.xml',
        'application/xhtml+xml': '.html',
        'application/vnd.wap.xhtml+xml': '.html',
        'application/json': '.txt',
        'application/x-json': '.txt',
        'application/json-amazonui-streaming': '.txt',
        'application/javascript': '.txt',
        'application/x-javascript': '.txt',
        'application/pdf': '.pdf'
    }

    def from_response(self, response):
        """ Returns the MIME type for a response
        """
        protocol = response.url.split(':')[0]
        supplied_mime = self.get_supplied_mime(protocol,response.headers)
        if supplied_mime is None or supplied_mime.split(';')[0] in ['unkonown/unknown', 'application/unknown', '*/*']:
            computed_mime = self._compute_mime_type(response.body, getattr(response, 'encoding', None))
            return computed_mime
        else:
            return supplied_mime

    def get_supplied_mime(self, protocol, headers=None):
        supplied_type = None
        if protocol.upper() in ['HTTP', 'HTTPS'] and headers is not None:
            supplied_type = headers.get('Content-Type')
        # TODO: Add support here for other protocols 
        if self._is_mime_type(supplied_type):
            return supplied_type
        else:
            return None

    def _is_mime_type(self, type):
        """ Checks that a given string is a valid MIME type string.
        Valid strings are as mentioned in 'https://tools.ietf.org/html/rfc7231#section-3.1.1.1'
        """
        type = to_native_str(type)
        return True if re.match("^({0}/{1}+)(;\s?({0}+=(\"{2}+\"|{2}+)))?$".format("[a-zA-Z-*\._]", "[a-zA-Z-*\._+]", "[a-zA-Z-*\._0-9]"),type) else False

    def _compute_mime_type(self, resource, encoding=None):
        """ Tries to match the given resource with pre-defined byte patterns
        If matches any, returns the corresponding MIME type
        """
        header_bytes = self._get_resource_header(resource, encoding)
        for pattern in self._PATTERN_TYPES:
            if self._match_pattern(header_bytes, pattern[0], pattern[1], pattern[2]):
                return pattern[3]
        return None

    def _get_resource_header(self, resource, encoding=None):
        """ Reading resource header as stated in 'https://mimesniff.spec.whatwg.org/#read-the-resource-header'.
        Mainly the resource is the body of the response
        """
        resource_to_parse = resource[:1445]    # So as not to process the whole resource
        return to_bytes(resource_to_parse, encoding=encoding)[:1445]

    def _match_pattern(self, byte_sequence, byte_pattern, pattern_mask, bytes_to_ignore):
        """ Determines if a given bytes sequence matches a specific bytes pattern
        """
        assert len(byte_pattern) == len(pattern_mask) , "Pattern's length is not equal to mask's length"
        if len(byte_sequence) < len(byte_pattern):
            return False

        try:
            s = next(x[0] for x in enumerate(byte_sequence) if x[1] not in bytes_to_ignore)
        except StopIteration:
            return False
        
        p = 0
        while p < len(byte_pattern) :
            masked_data = byte_sequence[s] & pattern_mask[p]
            if masked_data != byte_pattern[p]:
                return False
            s+=1
            p+=1
        return True

    def get_extension(self, type):
        """ Returns the file extension for the MIME type passed.
        If type is unknown, returns default '.txt' extension
        """
        ext = self._EXTENSIONS[type]
        if ext:
            return ext
        else:
            raise TypeError("Unsupported MIME type: %s" %
                        type)

        

