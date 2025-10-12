# -*- coding: utf-8 -*-
from javax.swing import JMenu, JMenuItem
from java.util import ArrayList
from burp_utils.grpc_scan import extract_all_grpc_messages_and_endpoints

def GetMenuItems(BurpExtender, invocation):
    menu_list = ArrayList()

    # Create a single menu item (no submenu)
    def onClick(e, invocation=invocation):
        scan_grpc_web_endpoints(invocation, "scan_grpc_web_endpoints", BurpExtender._helpers)

    item1 = JMenuItem("Scan gRPC-Web Endpoints", actionPerformed=onClick)

    # Add directly to the menu list
    menu_list.add(item1)

    return menu_list


def scan_grpc_web_endpoints(invocation, option, helpers):
    messages = invocation.getSelectedMessages()
    for message in messages:
        try:
            # get raw request bytes
            request = message.getRequest()
            # get the Http service (host/port/protocol)
            service = message.getHttpService()

            # If we have service info, use the two-arg analyzeRequest to get a full URL
            if service is not None:
                req_info = helpers.analyzeRequest(service, request)
                try:
                    url = req_info.getUrl()            # java.net.URL
                    print("Request URL: %s" % url.toString())
                except Exception, e:
                    # defensive: getUrl might still fail for weird requests
                    print("Request URL not available (getUrl() failed): %s" % e)
                    # fallback: print host/port/method/path if available
                    try:
                        print("Host: %s, Port: %s, Protocol: %s" % (service.getHost(), service.getPort(), service.getProtocol()))
                    except Exception, _:
                        pass
            else:
                # no service info on this message — try to extract host header / path manually
                req_info = helpers.analyzeRequest(request)
                headers = req_info.getHeaders()
                host_hdr = None
                for h in headers:
                    if h.lower().startswith("host:"):
                        host_hdr = h.split(":",1)[1].strip()
                        break
                print("No IHttpService available. Host header:", host_hdr)

            # get response body (decompressed if your get_response_body_string does that)
            body_str = get_response_body_string(helpers, message)
            # call extractor
            try:
                extract_all_grpc_messages_and_endpoints(body_str)
            except Exception, e:
                print("Error occurred in extracting gRPC messages:")
                print(e)

        except Exception, e:
            # top-level protection for unexpected Java/Py errors
            print("Unexpected error processing message:")
            print(e)

def get_response_body_string(helpers, message):
    response = message.getResponse()
    if response is None:
        return None                # no response (e.g. request-only rows)

    # find body offset
    resp_info = helpers.analyzeResponse(response)
    body_offset = resp_info.getBodyOffset()

    # get body bytes (Java byte[] slice)
    body_bytes = response[body_offset:len(response)]

    # check for gzip content-encoding
    content_encoding = None
    for h in resp_info.getHeaders():
        if h.lower().startswith("content-encoding:"):
            content_encoding = h.split(":", 1)[1].strip().lower()
            break

    # if gzip, try Python zlib/gzip first (simple), else fallback to Java decompression
    if content_encoding == "gzip":
        # Try Python zlib (works in many Jython environments)
        try:
            import zlib
            # 16 + MAX_WBITS tells zlib to expect gzip header
            decompressed = zlib.decompress(body_bytes, 16 + zlib.MAX_WBITS)
            return helpers.bytesToString(decompressed)
        except Exception:
            # Fallback to Java GZIPInputStream
            from java.io import ByteArrayInputStream, ByteArrayOutputStream
            from java.util.zip import GZIPInputStream

            bais = ByteArrayInputStream(body_bytes)
            gis  = GZIPInputStream(bais)
            baos = ByteArrayOutputStream()
            buf_size = 4096
            buf = bytearray(buf_size)
            while True:
                read = gis.read(buf, 0, buf_size)
                if read == -1:
                    break
                baos.write(buf, 0, read)
            decompressed = baos.toByteArray()
            return helpers.bytesToString(decompressed)

    # not gzip — convert body bytes to string using Burp helper
    return helpers.bytesToString(body_bytes)
