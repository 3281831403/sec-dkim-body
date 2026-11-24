"""正文规范化与前 10 个规格缺陷的契约测试。

共 10 条。当前 dkim/body.py 的 8 个桩全部抛 NotImplementedError，因此本文件
应全部失败；实现完成后，这些断言定义正确行为。每条测试对应题面中的一个缺陷。
"""

import hashlib
import hmac

import pytest

from dkim.body import (
    apply_length_tag,
    body_hash,
    canonicalize_body,
    dkim_batch,
    header_hash,
    parse_signature,
    split_headers,
    verify,
)


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


def test_relaxed_removes_trailing_spaces_and_tabs():
    """缺陷 1：宽松模式必须同时删除行尾空格和制表符，不能只删空格。"""
    body = b"alpha \t\r\nbeta\t \r\n"
    assert canonicalize_body(body, "relaxed") == b"alpha\r\nbeta\r\n"


def test_relaxed_collapses_blank_lines_and_trims_body_end():
    """缺陷 2：宽松模式必须折叠正文中的重复空行并删除末尾空行。"""
    body = b"alpha\r\n\r\n\r\nbeta\r\n\r\n\r\n"
    assert canonicalize_body(body, "relaxed") == b"alpha\r\n\r\nbeta\r\n"
    assert canonicalize_body(b"", "relaxed") == b"\r\n"
    assert canonicalize_body(b"\r\n\r\n\r\n", "relaxed") == b"\r\n"


def test_strict_preserves_trailing_whitespace():
    """缺陷 3：严格模式不得做宽松模式的行尾裁剪。"""
    body = b"alpha \t\r\nbeta\t \r\n"
    assert canonicalize_body(body, "strict") == body


def test_length_tag_is_applied_after_canonicalization():
    """缺陷 4：长度标签必须在规范化之后、摘要之前截断正文。"""
    body = b"alpha\r\nbeta\r\n"
    length = len(b"alpha\r\n")
    extended = body + b"injected\r\n"
    expected = hashlib.sha256(b"alpha\r\n").hexdigest()
    assert body_hash(body, "strict", length) == expected
    assert body_hash(extended, "strict", length) == expected


def test_length_tag_rejects_negative_and_overlong_values():
    """缺陷 5：负长度和超过正文长度的标签必须报错，不能静默截为零。"""
    with pytest.raises(ValueError):
        apply_length_tag(b"abc", -1)
    with pytest.raises(ValueError):
        apply_length_tag(b"abc", 4)
    assert apply_length_tag(b"abc", 3) == b"abc"
    assert apply_length_tag(b"abc", 0) == b""


def test_split_headers_unfolds_header_continuations():
    """缺陷 6：续行必须还原到同一个头值，不能把折行留给被签内容。"""
    raw = (
        b"From: alice@example.com\r\n"
        b"Subject: first\r\n"
        b"\tsecond\r\n"
        b"X-Trace: one\r\n"
        b"\r\n"
        b"body line\r\n"
    )
    parsed = split_headers(raw)
    assert parsed["headers"]["subject"] == ["first second"]
    assert parsed["headers"]["x-trace"] == ["one"]
    assert parsed["body"] == b"body line\r\n"


def test_header_hash_uses_every_duplicate_in_order():
    """缺陷 7：重复头部必须按出现次序逐个消费，不能始终取第一个。"""
    headers = {"from": ["alice@example.com"], "x-tag": ["first", "second"]}
    names = ["from", "x-tag", "x-tag"]
    expected = hashlib.sha256(
        b"from:alice@example.com\r\nx-tag:first\r\nx-tag:second\r\n"
    ).hexdigest()
    assert header_hash(headers, names) == expected

    changed = {"from": ["alice@example.com"], "x-tag": ["first", "poison"]}
    assert header_hash(changed, names) != expected


def test_parse_signature_rejects_self_reference():
    """缺陷 8：h 列表不得包含 dkim-signature 自身，否则形成循环依赖。"""
    bh = "a" * 64
    b = "b" * 64
    parsed = parse_signature(
        "DKIM-Signature: v=1; a=RSA-SHA256; d=Example.COM; s=sel1; "
        "c=relaxed/strict; h=From:Subject; l=12; bh=" + bh + "; b=" + b
    )
    assert parsed["algorithm"] == "rsa-sha256"
    assert parsed["domain"] == "example.com"
    assert parsed["selector"] == "sel1"
    assert parsed["length"] == 12
    assert parsed["headers"] == ["from", "subject"]
    assert parsed["body_mode"] == "relaxed"
    assert parsed["header_mode"] == "strict"

    with pytest.raises(ValueError):
        parse_signature(
            "v=1; a=rsa-sha256; d=example.com; s=sel1; "
            "h=From:DKIM-Signature; bh=" + bh + "; b=" + b
        )


def test_verify_binds_headers_across_shared_body_signatures():
    """缺陷 9：验签必须绑定头部；共享正文的多签名互不干扰且各用各的模式。"""
    key = b"shared-secret"
    body = b"alpha\r\nbeta\r\n"
    headers = {
        "from": ["alice@example.com"],
        "subject": ["hello"],
        "to": ["bob@example.com"],
    }
    subject_signature = _make_signature(
        body, headers, ["from", "subject"], key, body_mode="relaxed"
    )
    recipient_signature = _make_signature(
        body, headers, ["from", "to"], key, body_mode="strict"
    )
    assert subject_signature["body_hash"] == recipient_signature["body_hash"]
    assert verify(body, subject_signature, key) is True
    assert verify(body, recipient_signature, key) is True

    changed_headers = {name: list(values) for name, values in headers.items()}
    changed_headers["subject"] = ["changed"]
    tampered_signature = dict(subject_signature)
    tampered_signature["header_values"] = changed_headers
    assert verify(body, tampered_signature, key) is False
    assert verify(body, recipient_signature, key) is True

    appended = body + b" \t\r\n\r\n"
    assert verify(appended, subject_signature, key) is True
    assert verify(appended, recipient_signature, key) is False


def test_batch_does_not_reuse_first_message_body():
    """缺陷 10：批量验签必须逐封使用自己的正文，不能沿用第一封的规范化结果。"""
    key = b"batch-secret"
    headers = {"from": ["alice@example.com"], "subject": ["batch"]}
    first_body = b"alpha\r\n"
    second_body = b"beta\r\n"
    signature = _make_signature(first_body, headers, ["from", "subject"], key)
    first = {"id": "m1", "body": first_body, "signature": signature, "key": key}
    second = {"id": "m2", "body": second_body, "signature": signature, "key": key}

    result = dkim_batch([first, second], {"trusted_domains": ["example.com"]})
    assert result["results"] == {"m1": True, "m2": False}
    assert result["total"] == 2
    assert result["passed"] == 1
    assert result["failed"] == 1