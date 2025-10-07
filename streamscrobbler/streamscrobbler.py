# -*- coding: utf-8 -*-
import re
import urllib.parse
from aiohttp import ClientSession


# this is the function you should call with the url to get all data sorted as a object in the return
async def get_server_info(url):
    if urllib.parse.urlparse(url).path.endswith(".pls"):
        address = await check_pls(url)
    else:
        address = url
    if isinstance(address, str):
        meta_interval = await get_all_data(address)
    else:
        meta_interval = {"status": 0, "metadata": None}

    return meta_interval


async def get_all_data(address):
    status = 0

    user_agent = "iTunes/9.1.1"
    headers = {
        "User-Agent": user_agent,
        "icy-metadata": "1"
    }


    try:
        async with ClientSession(headers=headers) as session:
            async with session.get(address) as response:
                headers = dict(response.headers)
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
                    metadata = await shoutcast_check(response, headers, True)
                elif "SHOUTcast" in shoutcast:
                    status = 1
                    metadata = await shoutcast_check(response, headers, False)
                elif "Icecast" or "137" or "StreamMachine" in shoutcast:
                    status = 1
                    metadata = await shoutcast_check(response, headers, True)
                else:
                    metadata = False
                return {"status": status, "metadata": metadata}

    except Exception as err:
        print(("    Error: " + str(err)))
        return {"status": status, "metadata": None}


async def check_pls(address):
    try:
        async with ClientSession() as session:
            async with session.get(address) as response:
                stream = None
                for line in response.content:
                    if line.startswith(b"File1="):
                        stream = line.decode()

                if stream:
                    return stream[6:].strip("\n")
                else:
                    return False
    except Exception:
        return False


async def shoutcast_check(response, headers, is_old):
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
        content = await response.content.readexactly(read_buffer)
        # Metadata true end is music frame + 1 byte + 16 * first byte after music frame
        metadata_end = metaint + 1 + int.from_bytes(content[metaint:metaint+1]) * 16

        start = "StreamTitle='"
        end = "';"

        try:
            title = (
                re.search(bytes("%s(.*)%s" % (start, end), "utf-8"), content[metaint+1:metadata_end])
                .group(1)
                .decode("utf-8")
            )
            title = (
                re.sub("StreamUrl='.*?';", "", title)
                .replace("';", "")
                .replace("StreamUrl='", "")
            )
            title = re.sub("&artist=.*", "", title)
            title = re.sub("http://.*", "", title)
            title.rstrip()
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
