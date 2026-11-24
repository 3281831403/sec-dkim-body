"""正文规范化的 5 条边界测试。

覆盖严格模式原样正文、宽松模式追加行尾空白、长度标签之后的追加正文、头部
改写以及两批独立验签。当前 8 个桩全部抛 NotImplementedError，因此 5 条全红。
"""

import hashlib
import hmac

from dkim.body import body_hash, canonicalize_body, dkim_batch, header_hash, verify


def _make_signature(body, headers, header_names, key, body_mode="relaxed", length=None):
    """用公开函数构造一个可供 verify 使用的签名字典。"""
    header_values = {name: list(values) for name, values in headers.items()}
    digest = body_hash(body, body_mode, length)
    signed_headers = header_hash(header_values, header_names)
    mac = hmac.new(
        key,
        (signed_headers + "\n" + digest).encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "algorithm": "rsa-sha256",
        "domain": "example.com",
        "selector": "sel1",
        "headers": list(header_names),
        "header_values": header_values,
        "length": length,
        "body_mode": body_mode,
        "header_mode": "relaxed",
        "body_hash": digest,
        "header_hash": signed_headers,
        "signature": mac,
    }


def test_strict_signature_verifies_original_body():
    """严格模式下，保留行尾空白的原样正文必须通过验签。"""
    key = b"strict-key"
    body = b"alpha \t\r\nbeta\t \r\n"
    headers = {"from": ["alice@example.com"], "subject": ["strict body"]}
    signature = _make_signature(
        body, headers, ["from", "subject"], key, body_mode="strict"
    )
    assert signature["body_hash"] == hashlib.sha256(body).hexdigest()
    assert verify(body, signature, key) is True


def test_relaxed_signature_accepts_appended_trailing_whitespace():
    """宽松模式下，追加行尾空白和多余空行不能改变正文摘要。"""
    key = b"relaxed-key"
    base = b"alpha\r\nbeta\r\n"
    headers = {"from": ["alice@example.com"], "subject": ["relaxed body"]}
    signature = _make_signature(
        base, headers, ["from", "subject"], key, body_mode="relaxed"
    )
    appended = base + b" \t\r\n\r\n\t \r\n"
    assert canonicalize_body(appended, "relaxed") == canonicalize_body(
        base, "relaxed"
    )
    assert verify(appended, signature, key) is True


def test_length_tag_signature_accepts_appended_body_content():
    """长度标签截断后追加正文，不能影响基于截断前缀的签名。"""
    key = b"length-key"
    base = b"alpha\r\nbeta\r\n"
    length = len(base)
    headers = {"from": ["alice@example.com"], "subject": ["length body"]}
    signature = _make_signature(
        base,
        headers,
        ["from", "subject"],
        key,
        body_mode="strict",
        length=length,
    )
    assert signature["length"] == length
    assert signature["body_hash"] == hashlib.sha256(base[:length]).hexdigest()
    assert verify(base + b"appended\r\n", signature, key) is True


def test_header_tampering_invalidates_signature():
    """被签头部改写后验签必须失败，不能只校验正文。"""
    key = b"header-key"
    body = b"alpha\r\nbeta\r\n"
    headers = {
        "from": ["alice@example.com"],
        "subject": ["original"],
        "to": ["bob@example.com"],
    }
    signature = _make_signature(body, headers, ["from", "subject"], key)
    assert verify(body, signature, key) is True

    tampered = dict(signature)
    tampered_headers = {name: list(values) for name, values in headers.items()}
    tampered_headers["subject"] = ["rewritten"]
    tampered["header_values"] = tampered_headers
    assert verify(body, tampered, key) is False


def test_two_batches_match_individual_verification():
    """分两批与合并成一批，每封邮件的结论必须与单独验签一致。"""
    key = b"batch-key"
    headers = {"from": ["alice@example.com"], "subject": ["batch body"]}
    first_body = b"alpha\r\n"
    second_body = b"beta\r\n"
    signature = _make_signature(first_body, headers, ["from", "subject"], key)
    first = {"id": "m1", "body": first_body, "signature": signature, "key": key}
    second = {"id": "m2", "body": second_body, "signature": signature, "key": key}
    policy = {"trusted_domains": ["example.com"]}

    only_first = dkim_batch([first], policy)
    only_second = dkim_batch([second], policy)
    combined = dkim_batch([first, second], policy)

    individual_first = verify(first_body, signature, key)
    individual_second = verify(second_body, signature, key)
    assert only_first["results"] == {"m1": True}
    assert only_second["results"] == {"m2": False}
    assert combined["results"] == {"m1": True, "m2": False}
    assert combined["results"]["m1"] == individual_first
    assert combined["results"]["m2"] == individual_second
    assert individual_first is True
    assert individual_second is False