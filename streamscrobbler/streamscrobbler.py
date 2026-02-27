# -*- coding: utf-8 -*-
import re
import ssl
import urllib.request
import urllib.error
import urllib.parse


# this is the function you should call with the url to get all data sorted as a object in the return
# `verify` controls TLS certificate validation (default True). callers can pass False to disable
# verification when connecting to servers with self-signed/expired certs.
def get_server_info(url, tls_verify: bool = True):
    if urllib.parse.urlparse(url).path.endswith(".pls"):
        address = check_pls(url, tls_verify=tls_verify)
    else:
        address = url
    if isinstance(address, str):
        meta_interval = get_all_data(address, tls_verify=tls_verify)
    else:
        meta_interval = {"status": 0, "metadata": None}

    return meta_interval


def get_all_data(address, tls_verify: bool = True):
    status = 0

    request = urllib.request.Request(address)
    user_agent = "iTunes/9.1.1"
    request.add_header("User-Agent", user_agent)
    request.add_header("icy-metadata", 1)
    try:
        ctx = ssl.create_default_context()
        if not tls_verify:
            ctx = ssl._create_unverified_context()
            ctx.set_ciphers("DEFAULT@SECLEVEL=1")

        response = urllib.request.urlopen(request, timeout=6, context=ctx)
        headers = dict(response.info())
        # Headers are case-insensitive
        headers = {key.lower(): value for key, value in headers.items()}

        if "server" in headers:
            shoutcast = headers["server"]
        elif "x-powered-by" in headers:
            shoutcast = headers["x-powered-by"]
        elif "icy-notice1" in headers:
            shoutcast = headers["icy-notice2"]
        else:
            shoutcast = True

        if isinstance(shoutcast, bool) and shoutcast:
            status = 1
            metadata = shoutcast_check(response, headers, True)
        elif "SHOUTcast" in shoutcast:
            status = 1
            metadata = shoutcast_check(response, headers, False)
        elif "Icecast" or "137" or "StreamMachine" in shoutcast:
            status = 1
            metadata = shoutcast_check(response, headers, True)
        else:
            metadata = False
        response.close()
        return {"status": status, "metadata": metadata}

    except urllib.error.HTTPError as e:
        print(("    Error, HTTPError = " + str(e.code)))
        return {"status": status, "metadata": None}

    except urllib.error.URLError as e:
        print(("    Error, URLError: " + str(e.reason)))
        return {"status": status, "metadata": None}

    except Exception as err:
        print(("    Error: " + str(err)))
        return {"status": status, "metadata": None}


def check_pls(address, tls_verify: bool =  True):
    try:
        stream = None
        # handle optional TLS verification
        ctx = ssl.create_default_context()
        if not tls_verify:
            ctx = ssl._create_unverified_context()
            ctx.set_ciphers("DEFAULT@SECLEVEL=1")
        response = urllib.request.urlopen(address, timeout=2, context=ctx)
        for line in response:
            if line.startswith(b"File1="):
                stream = line.decode()

        response.close()
        if stream:
            return stream[6:].strip("\n")
        else:
            return False
    except Exception:
        return False


def shoutcast_check(response, headers, is_old):
    bitrate = None
    contenttype = None

    if "icy-br" in headers:
        if is_old:
            bitrate = headers["icy-br"].split(",")[0]
        else:
            bitrate = headers["icy-br"]
        bitrate = bitrate.rstrip()

    if "icy-metaint" in headers:
        icy_metaint_header = headers["icy-metaint"]
    else:
        icy_metaint_header = None

    if "content-type" in headers:
        contenttype = headers["content-type"].rstrip()
    else:
        contenttype = None

    if icy_metaint_header:
        metaint = int(icy_metaint_header)
        # Maximum metadata frame size is 255*16=4080
        # Total buffer = music frame (metaint) + 1 byte (metadata length) + 4080 (255*16)
        read_buffer = metaint + 4081
        content = response.read(read_buffer)
        # Metadata true end is music frame + 1 byte + 16 * first byte after music frame
        metadata_end = metaint + 1 + int.from_bytes(content[metaint:metaint+1]) * 16

        end = ";"

        try:
            raw_metadata = (
                re.search(bytes("(.*)%s" % (end), "utf-8"), content[metaint+1:metadata_end])
                .group(1)
                .decode("utf-8")
            )

            metadata = {}
            for meta in raw_metadata.split(';'):
                meta = meta.strip().split('=')
                metadata[meta[0]] = meta[1].strip("'")

            title = metadata['StreamTitle']
        except Exception as err:
            print(("songtitle error: " + str(err)))
            title = content[metaint+1:metadata_end].split(b"'")[1]

        return {"song": title, "bitrate": bitrate, "contenttype": contenttype}
    else:
        print("No metaint")
        return False


def strip_tags(text):
    finished = 0
    while not finished:
        finished = 1
        start = text.find("<")
        if start >= 0:
            stop = text[start:].find(">")
            if stop >= 0:
                text = text[:start] + text[start + stop + 1 :]
                finished = 0
    return text
