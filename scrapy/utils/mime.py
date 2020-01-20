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
    _SCRIPTABLE_PATTERNS = [
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
        ([0x25 ,0x50 ,0x44 ,0x46 ,0x2D], [0xFF,0xFF,0xFF,0xFF,0xFF], [], 'application/pdf')
    ]
    _NON_SCRIPTABLE_PATTERNS = [
        ([0x25 ,0x21 ,0x50 ,0x53, 0x2D, 0x41, 0x64, 0x6F, 0x62 ,0x65 ,0x2D], 
        [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], [], 'application/postscript'),
        ([0xFE ,0xFF ,0x00 ,0x00], [0xFF ,0xFF ,0x00 ,0x00], [], 'text/plain'),
        ([0xFF ,0xFE ,0x00 ,0x00], [0xFF ,0xFF ,0x00 ,0x00], [], 'text/plain'),	
        ([0xEF ,0xBB ,0xBF ,0x00], [0xFF ,0xFF ,0xFF ,0x00], [], 'text/plain')
    ]
    _IMAGE_PATTERNS = [
        ([0x00, 0x00, 0x01, 0x00], [0xFF, 0xFF, 0xFF, 0xFF], [], 'image/x-icon'),
        ([0x00, 0x00, 0x02, 0x00], [0xFF, 0xFF, 0xFF, 0xFF], [], 'image/x-icon'),
        ([0x42, 0x4D], [0xFF, 0xFF], [], 'image/bmp'),
        ([0x47, 0x49, 0x46, 0x38, 0x37, 0x61], [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], [], 'image/gif'),
        ([0x47, 0x49, 0x46, 0x38, 0x39, 0x61], [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], [], 'image/gif'),
        ([0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50, 0x56, 0x50],
            [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], [], 'image/webp'),
        ([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], [], 'image/png'),
        ([0xFF, 0xD8, 0xFF], [0xFF, 0xFF, 0xFF], [], 'image/jpeg')
    ]
    _AUDIO_VIDEO_PATTERNS = [
        ([0x2E, 0x73, 0x6E, 0x64], [0xFF, 0xFF, 0xFF, 0xFF], [], 'audio/basic'),
        ([0x46, 0x4F, 0x52, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x41, 0x49, 0x46, 0x46],
            [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF], [], 'audio/aiff'),
        ([0x49, 0x44, 0x33], [0xFF, 0xFF, 0xFF], [], 'audio/mpeg'),
        ([0x4F, 0x67, 0x67, 0x53, 0x00], [0xFF, 0xFF, 0xFF, 0xFF, 0xFF], [], 'application/ogg'),
        ([0x4D, 0x54, 0x68, 0x64, 0x00, 0x00, 0x00, 0x06], [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], [], 'audio/midi'),
        ([0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x41, 0x56, 0x49, 0x20],
            [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF], [], 'video/avi'),
        ([0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45], [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF], [], 'audio/wave')
    ]
    _ARCHIVE_PATTERNS = [
        ([0x1F, 0x8B, 0x08], [0xFF, 0xFF, 0xFF], [], 'application/x-gzip'),
        ([0x50, 0x4B, 0x03, 0x04], [0xFF, 0xFF, 0xFF, 0xFF], [], 'application/zip'),
        ([0x52, 0x61, 0x72, 0x20, 0x1A, 0x07, 0x00], [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], [], 'application/x-rar-compressed')
    ]
    _BINARY_DATA_TYPES = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1C,
        0x1D, 0x1E, 0x1F
    ]
    _TYPES_TO_CHECK_APACHE_BUG = [
        'text/plain',
        'text/plain; charset=ISO-8859-1',
        'text/plain; charset=iso-8859-1',
        'text/plain; charset=UTF-8'
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

    def from_response(self, response, no_sniff_flag = False ):
        """ Returns the MIME type for a response
        """
        self.no_sniff_flag = no_sniff_flag
        protocol = response.url.split(':')[0]
        supplied_mime = self.get_supplied_mime(protocol, response.headers)
        #1
        if supplied_mime is None or self.get_mime_essence(supplied_mime) in ['unkonown/unknown', 'application/unknown', '*/*']:
            self._sniff_scriptable_flag = not self.no_sniff_flag
            return self._compute_mime_type(response.body, getattr(response, 'encoding', None))
        #2
        if self.no_sniff_flag:
            return supplied_mime
        #3
        if self._check_for_apache_bug_flag:
            return self._text_or_binary(response)
        #4
        if self._is_xml_mime_type(supplied_mime):
            return supplied_mime
        #5
        if self.get_mime_essence(supplied_mime) == "text/html":
            return self._feed_or_html(response, supplied_mime)
        return supplied_mime     

    def _is_xml_mime_type(self, type):
        return True if self._is_mime_type(type) and\
            re.match(".*\+xml|text/xml|application/xml", type) else False
    
    def _feed_or_html(self, resource, supplied_mime):
        """Determine whether a feed has been mislabeled as HTML, and
        returns the appropriate MIME type
        """
        sequence = self._get_resource_header(resource)
        length = len(sequence)
        s = 0
        if length >= 3 and sequence[:3] == bytearray([0xEF, 0xBB, 0xBF]):  
            s += 3
        while s < length:
            try:
                while True:
                    if sequence[s] == to_bytes('<'): # 0x3C
                        s+=1
                        break
                    if sequence[s] not in self._WHITESSPACE_BYTES:
                        return supplied_mime
                    s += 1
                    
                while True:   
                    break_outer = False   
                    if length >= s+3 and sequence[s:s+3] == to_bytes('!--'): # 0x21 0x2D 0x2D
                        s += 3
                        while True:
                            if length >= s+3 and sequence[s:s+3] == to_bytes('-->'): # 0x2D 0x2D 0x3E
                                s += 3
                                break_outer = True
                                break
                            s += 1            
                    if break_outer: break

                    if length >= s+1 and sequence[s] == to_bytes('!') : # 0x21
                        s += 1
                        while True:
                            if length >= s+1 and sequence[s] == to_bytes('>'): # 0x3E
                                s += 1
                                break_outer = True
                                break
                            s += 1
                    if break_outer: break

                    if length >= s+1 and sequence[s] == to_bytes('?'): # "?"
                        s += 1
                        while True:
                            if length >= s+2 and sequence[s:s+2] == to_bytes('?>'): # 0x3F 0x3E
                                s += 2
                                break_outer = True
                                break
                            s += 1
                    if break_outer: break

                    if length >= s+3 and sequence[s:s+3] == to_bytes('rss'):  # 0x72 0x73 0x73
                        return "application/rss+xml"

                    if length >= s+4 and sequence[s:s+4] == to_bytes('feed'):  # 0x66 0x65 0x6 0x64
                        return "application/atom+xml"

                    if length >= s+7 and sequence[s:s+7] == to_bytes('rdf:RDF'): # 0x72 0x64 0x66 0x3A 0x52 0x44 0x46  
                        s += 7   
                        while True:  
                            if length >= s+24 and sequence[s:s+24] == to_bytes('http://purl.org/rss/1.0/'):
                                s += 24
                                while True:
                                    if length >= 43 and sequence[s:s+43] == to_bytes('http://www.w3.org/1999/02/22-rdf-syntax-ns#'):
                                        return 'application/rss+xml'
                                    s += 1
                            if length >= 24 and sequence[s:s+24] == to_bytes('http://www.w3.org/1999/02/22-rdf-syntax-ns#'):
                                s += 24
                                while True:
                                    if length >= 43 and sequence[s:s+43] == to_bytes('"http://purl.org/rss/1.0/"'):
                                        return 'application/rss+xml'
                                    s += 1
                            s += 1
                        
                    return supplied_mime
            except IndexError:
                return supplied_mime             
        return supplied_mime       
               
    def _text_or_binary(self, resource):
        """ Determine whether a binary resource has been mislabeled as plain text
        """
        header_bytes = self._get_resource_header(resource)
        length = len(header_bytes)
        if ((length >= 2 and header_bytes in [bytearray([0xFE,0xFF]), bytearray([0xFF,0xFE])]) or
            (length >= 3 and header_bytes in [bytearray([0xEF,0xBB, 0xBF]), bytearray([0xFF,0xFE])]) or
            not self._has_binary_byte(header_bytes)):
            return 'text/plain'
        return 'application/octet-stream'
    
    def get_supplied_mime(self, protocol, headers=None):
        """ Extracts the MIME type supplied with the resource from its provider (eg. server)
        """
        supplied_type = None
        if protocol.upper() in ['HTTP', 'HTTPS'] and headers is not None:
            supplied_type = headers.get('Content-Type')
            self._check_for_apache_bug(supplied_type)
        # TODO: Add support here for other protocols 
        if self._is_mime_type(supplied_type):
            return supplied_type
        else:
            return None

    def _check_for_apache_bug(self, type):
        """ Checks if the MIME type extracted from headers is a one that 
        might be mistakenly set as a result of Apache's bug
        """
        self._check_for_apache_bug_flag = False
        if type in self._TYPES_TO_CHECK_APACHE_BUG:
            self._check_for_apache_bug_flag = True

    def _is_mime_type(self, type):
        """ Checks that a given string is a valid MIME type string.
        Valid strings are as mentioned in 'https://tools.ietf.org/html/rfc7231#section-3.1.1.1'
        """
        if not type:
            return False
        type = to_native_str(type)
        return True if re.match("^({0}/{1}+)(;\s?({0}+=(\"{2}+\"|{2}+)))?$".format("[a-zA-Z-*\._]", "[a-zA-Z-*\._+]", "[a-zA-Z-*\._0-9]"),type)\
            else False

    def _compute_mime_type(self, resource, encoding=None):
        """ Tries to match the given resource with pre-defined byte patterns
        If matches any, returns the corresponding MIME type
        If doesn't match any, and has no binary data types, return 'text/plain'
        Returns 'application/octet-stream' otherwise
        """
        header_bytes = self._get_resource_header(resource, encoding)
        if self._sniff_scriptable_flag:
            mime_type_tmp = self._match_group_pattern(header_bytes, self._SCRIPTABLE_PATTERNS)
        mime_type = mime_type_tmp\
                or self._match_group_pattern(header_bytes, self._NON_SCRIPTABLE_PATTERNS)\
                or self._match_group_pattern(header_bytes, self._IMAGE_PATTERNS)\
                or self._match_audio_video_pattern(header_bytes)\
                or self._match_group_pattern(header_bytes, self._ARCHIVE_PATTERNS)
        if mime_type:
            return mime_type
        if not self._has_binary_byte(header_bytes):
            return "text/plain"
        return "application/octet-stream"

    def _get_resource_header(self, resource, encoding=None):
        """ Reading resource header as stated in 'https://mimesniff.spec.whatwg.org/#read-the-resource-header'.
        Mainly the resource is the body of the response
        """
        resource_to_parse = resource[:1445]    # So as not to process the whole resource
        return to_bytes(resource_to_parse, encoding=encoding)[:1445]

    def _match_pattern(self, byte_sequence, byte_pattern, pattern_mask, bytes_to_ignore):
        """ Determines if a given bytes sequence matches a specific bytes pattern
        If so, return the MIME type for that pattern
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

    def _match_group_pattern(self, byte_sequence, group):
        """ Determine if a given byte sequence matches any pattern from a specific group
        If so, return the MIME type for that pattern
        """
        for pattern in group:
            if self._match_pattern(byte_sequence, pattern[0], pattern[1], pattern[2]):
                return pattern[3]
        return None

    def _match_audio_video_pattern(self, byte_sequence):
        """ Determine if a given byte sequence matches any pattern from a audio video group
        If so, return the MIME type for that pattern

        This is separated as it has additional steps
        """
        for pattern in self._AUDIO_VIDEO_PATTERNS:
            if self._match_pattern(byte_sequence, pattern[0], pattern[1], pattern[2]):
                return pattern[3]
        #TODO: Add matching MP4, WebM, MP3
         
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

    def get_mime_essence(self, mime):
        """ MIME type essence is the type followed by '/'
        followerd by subtype
        """
        return mime.split(';')[0]

    def _has_binary_byte(self, bytes_seq):
        """ Checks if a byte sequence contains any binary data type.
        Binary data types mentioned in 'https://mimesniff.spec.whatwg.org/#binary-data-byte'
        """
        for byte in bytes_seq:
            if byte in self._BINARY_DATA_TYPES:
                return True
        return False
