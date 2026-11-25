"""DKIM 正文规范化与验签桩。

本模块是唯一的实现文件，当前恰好包含 8 个桩，全部 raise
NotImplementedError。实现必须满足 tests 中的精确契约，不得修改 tests。

统一约定
- 正文和规范化结果使用 bytes，签名头值使用 str。
- 规范行结束符为 CRLF；输入只含 LF 时按 CRLF 处理。
- 空正文规范化后为单个 CRLF，即 b"\r\n"。
- 摘要均为 SHA-256 的小写十六进制字符串。
"""

import hashlib
import hmac
import re


def _to_bytes(data):
    if isinstance(data, str):
        return data.encode("utf-8")
    return bytes(data)


def _split_lines(body):
    """把正文统一拆成不含行结束符的行列表（CRLF / LF 均按行结束符处理）。"""
    body = _to_bytes(body).replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return body.split(b"\n")


def split_headers(raw) -> dict:
    """拆分原始邮件的头部与正文，并还原头部折叠行。

    raw 为 bytes（也接受 str，按 UTF-8 编码处理）。头部在第一个空行处结束，
    返回 {"headers": dict, "body": bytes}。headers 的键为小写头名，值为按
    原始出现顺序保存的展开后字符串列表。以空格或制表符开头的续行必须与
    前一行还原为同一个值：去掉 CRLF，并把续行前导空白折叠为一个空格，值
    的两端空白应去掉。同名头部不得覆盖，正文必须原样保留。
    """
    raw = _to_bytes(raw)
    # 在第一个空行处拆分；正文部分原样保留。
    pos = raw.find(b"\r\n\r\n")
    if pos != -1:
        header_block, body = raw[:pos], raw[pos + 4:]
    else:
        pos = raw.find(b"\n\n")
        if pos != -1:
            header_block, body = raw[:pos], raw[pos + 2:]
        else:
            header_block, body = raw, b""

    headers = {}
    current_name = None
    for line in header_block.replace(b"\r\n", b"\n").split(b"\n"):
        if not line:
            continue
        if line[:1] in (b" ", b"\t"):
            # 续行：去掉折行，前导空白折叠为一个空格。
            if current_name is not None:
                continuation = line.decode("utf-8", "replace").strip()
                if continuation:
                    headers[current_name][-1] += " " + continuation
            continue
        name, sep, value = line.partition(b":")
        if not sep:
            continue
        current_name = name.decode("utf-8", "replace").strip().lower()
        headers.setdefault(current_name, []).append(
            value.decode("utf-8", "replace").strip()
        )
    return {"headers": headers, "body": body}


def canonicalize_body(body, mode) -> bytes:
    """按模式规范化正文。

    mode 为 relaxed 或 strict，其他值报 ValueError。
    relaxed：删除每行末尾的空格与制表符；把连续多个空行折叠为一个空行；
    删除正文末尾的全部空行；保证结果以 CRLF 结束。
    strict：保留每行末尾的空格与制表符，不折叠正文中的空行，只删除正文
    末尾的空行并保证结果以 CRLF 结束，不得执行宽松模式的行尾裁剪。
    两种模式都必须把空正文规范化为 b"\r\n"。
    """
    if mode not in ("relaxed", "strict"):
        raise ValueError("unknown canonicalization mode: %r" % (mode,))
    lines = _split_lines(body)
    if mode == "relaxed":
        # 先删行尾空白，末尾空行的判定以裁剪后的行为准。
        lines = [line.rstrip(b" \t") for line in lines]
    # 末尾拆分产生的空串即末尾空行，统一先去掉末尾空行。
    while lines and lines[-1] == b"":
        lines.pop()
    if mode == "relaxed":
        collapsed = []
        for line in lines:
            if line == b"" and collapsed and collapsed[-1] == b"":
                continue
            collapsed.append(line)
        lines = collapsed
    if not lines:
        return b"\r\n"
    return b"\r\n".join(lines) + b"\r\n"


def apply_length_tag(body, length) -> bytes:
    """按长度标签截断已经规范化的正文。

    body 必须已经是规范化后的 bytes。length 为整数，合法范围是
    0 到 len(body)（含两端）；返回 body[:length]。length 为负数、超过正文
    长度或不是整数时必须报 ValueError，不得静默返回空串。
    """
    if isinstance(length, bool) or not isinstance(length, int):
        raise ValueError("length must be an integer")
    body = _to_bytes(body)
    if length < 0 or length > len(body):
        raise ValueError("length %r out of range for body of %d bytes"
                         % (length, len(body)))
    return body[:length]


def body_hash(body, mode, length) -> str:
    """计算正文摘要。

    必须先调用 canonicalize_body，再调用 apply_length_tag，最后对截断后的
    字节计算 SHA-256；length 为 None 表示没有长度标签、不截断。顺序颠倒会
    使截断之后的追加内容改变摘要，必须避免。
    """
    canonical = canonicalize_body(body, mode)
    if length is not None:
        canonical = apply_length_tag(canonical, length)
    return hashlib.sha256(canonical).hexdigest()


def parse_signature(header) -> dict:
    """解析 DKIM-Signature 头值。

    header 可带 DKIM-Signature 前缀，也可只含分号分隔的标签；允许折叠行，
    解析前先展开。标签名不区分大小写。返回至少包含以下键的字典：
    algorithm、domain、selector、length、headers，并同时给出
    canonicalization、body_mode、header_mode、body_hash、signature。
    algorithm 与 domain 转小写；length 无标签时为 None，否则为 int；
    headers 为按 h 标签原顺序保存的小写头名列表；c 标签按斜杠拆成正文和
    头部模式，缺省均为 simple。h 中若出现 dkim-signature（大小写不敏感），
    必须报 ValueError，避免签名头签自身形成循环依赖。缺少 v、a、d、s、h、
    bh、b 或 h 为空时同样报 ValueError。
    """
    if isinstance(header, bytes):
        header = header.decode("utf-8", "replace")
    # 展开折叠行。
    header = re.sub(r"\r?\n[ \t]+", " ", header)
    header = header.strip()
    if header.lower().startswith("dkim-signature:"):
        header = header[len("dkim-signature:"):]

    tags = {}
    for part in header.split(";"):
        part = part.strip()
        if not part:
            continue
        name, sep, value = part.partition("=")
        if not sep:
            raise ValueError("malformed tag: %r" % (part,))
        tags[name.strip().lower()] = value.strip()

    for required in ("v", "a", "d", "s", "h", "bh", "b"):
        if required not in tags or not tags[required]:
            raise ValueError("missing required tag: %s" % required)

    headers = [name.strip().lower() for name in tags["h"].split(":")]
    headers = [name for name in headers if name]
    if not headers:
        raise ValueError("empty h tag")
    if "dkim-signature" in headers:
        raise ValueError("h tag must not include dkim-signature")

    canonicalization = tags.get("c", "simple/simple") or "simple/simple"
    modes = canonicalization.split("/", 1)
    body_mode = modes[0].strip().lower() or "simple"
    header_mode = (modes[1].strip().lower() if len(modes) > 1 else "simple") or "simple"

    length = None
    if "l" in tags and tags["l"]:
        try:
            length = int(tags["l"])
        except ValueError:
            raise ValueError("invalid l tag: %r" % (tags["l"],))

    return {
        "algorithm": tags["a"].lower(),
        "domain": tags["d"].lower(),
        "selector": tags["s"],
        "length": length,
        "headers": headers,
        "canonicalization": canonicalization,
        "body_mode": body_mode,
        "header_mode": header_mode,
        "body_hash": tags["bh"],
        "signature": tags["b"],
    }


def header_hash(headers, list) -> str:
    """计算被签头部摘要。

    headers 为 split_headers 返回的小写头名到值列表的映射；list 为签名头
    h 标签给出的有序头名列表。必须严格按 list 的顺序逐个消费对应头部的
    下一次出现：同名头部重复出现时依次取第一个、第二个，不能每次都取第
    一个，也不能忽略后续项。缺失头部或出现次数不足时报 ValueError；
    list 含 dkim-signature 时也报 ValueError。

    被签头部的规范形式为：头名小写、冒号、展开后的值、CRLF；值内部的
    连续空格或制表符折叠为一个空格，两端空白去掉。把全部条目拼接后计算
    SHA-256 并返回小写十六进制字符串。
    """
    names = [name.strip().lower() for name in list]
    if "dkim-signature" in names:
        raise ValueError("header list must not include dkim-signature")

    consumed = {}
    out = []
    for name in names:
        values = headers.get(name)
        index = consumed.get(name, 0)
        if not values or index >= len(values):
            raise ValueError("missing signed header occurrence: %s" % name)
        consumed[name] = index + 1
        value = re.sub(r"[ \t]+", " ", str(values[index])).strip()
        out.append("%s:%s\r\n" % (name, value))
    return hashlib.sha256("".join(out).encode("utf-8")).hexdigest()


def verify(body, signature, key) -> bool:
    """验证一封邮件正文与一组被签头部是否匹配。

    body 为原始正文 bytes，key 为 HMAC 密钥 bytes。signature 是至少包含
    headers、header_values、body_mode、length、body_hash、header_hash、
    signature 的字典。verify 必须独立重算正文摘要和头部摘要：正文摘要使用
    signature 中的 body_mode 与 length，头部摘要使用 headers 与
    header_values。两次重算值都要与 signature 中保存的值用常数时间比较，
    任意一项不符即返回 False，因此改写正文或改写被签头部都必须失败。

    密钥绑定使用 HMAC-SHA256，消息为 header_hash 的十六进制文本、一个 LF、
    body_hash 的十六进制文本，结果的小写十六进制必须等于
    signature["signature"]。缺少字段、类型错误或摘要不匹配时返回 False，
    不要把验签失败变成异常。
    """
    try:
        headers = signature["headers"]
        header_values = signature["header_values"]
        body_mode = signature["body_mode"]
        length = signature["length"]
        expected_body_hash = signature["body_hash"]
        expected_header_hash = signature["header_hash"]
        expected_signature = signature["signature"]

        digest = body_hash(body, body_mode, length)
        signed_headers = header_hash(header_values, headers)
        if not hmac.compare_digest(digest, expected_body_hash):
            return False
        if not hmac.compare_digest(signed_headers, expected_header_hash):
            return False
        mac = hmac.new(
            _to_bytes(key),
            (signed_headers + "\n" + digest).encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(mac, expected_signature)
    except Exception:
        return False


def dkim_batch(messages, policy) -> dict:
    """批量验签，每封邮件彼此独立。

    messages 为字典序列，每项含 id、body、signature、key。policy 至少含
    trusted_domains 列表；签名域不在列表内时该封邮件判为 False。返回
    {"results": {id: bool}, "total": int, "passed": int, "failed": int}。
    单封邮件解析或验签异常只把该封记为 False，不得中断其余邮件。禁止跨
    消息复用正文规范化结果或摘要缓存：第二条消息必须使用自己的 body，否
    则两个不同正文会错误共享第一封正文的规范化结果。
    """
    trusted = {str(d).lower() for d in policy.get("trusted_domains", [])}
    results = {}
    for message in messages:
        ok = False
        try:
            signature = message["signature"]
            domain = str(signature.get("domain", "")).lower()
            if domain in trusted:
                # 每封邮件都用自己的 body 独立验签，不做任何跨消息缓存。
                ok = bool(verify(message["body"], signature, message["key"]))
        except Exception:
            ok = False
        results[message.get("id")] = ok
    passed = sum(1 for ok in results.values() if ok)
    return {
        "results": results,
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
    }
