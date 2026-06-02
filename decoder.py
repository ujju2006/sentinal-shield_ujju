import urllib.parse
import html

class PayloadDecoder:
    """
    Decodes and normalizes incoming HTTP payloads (URLs, headers, bodies).
    Addresses URL encoding, Hex encoding, and HTML entities.
    """
    @staticmethod
    def decode(value):
        if not isinstance(value, str):
            return value
            
        decoded = value
        # Multi-layer decoding loop to handle double encoding
        for _ in range(3):
            previous = decoded
            # 1. URL decode (handles %20, %27, etc. and hex encoded %xX)
            decoded = urllib.parse.unquote(decoded)
            decoded = urllib.parse.unquote_plus(decoded)
            
            # 2. HTML Entity decode (handles &lt;, &quot;, &#x27;)
            decoded = html.unescape(decoded)
            
            if decoded == previous:
                break
                
        return decoded.strip()
