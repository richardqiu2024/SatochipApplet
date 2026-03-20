#!/usr/bin/env python3

import argparse
import hashlib
import hmac
import importlib.util
import logging
import sys
from pathlib import Path


LOG = logging.getLogger("test_satochip_regression")

CARD_EDGE_CLA = 0xB0
INS_VERIFY_PIN = 0x42
INS_BIP32_IMPORT_SEED = 0x6C
INS_BIP32_GET_EXTENDED_KEY = 0x6D
INS_SIGN_MESSAGE = 0x6E
INS_BIP32_GET_AUTHENTIKEY = 0x73
INS_BIP32_RESET_SEED = 0x77
INS_SIGN_TRANSACTION_HASH = 0x7A
INS_EXPORT_AUTHENTIKEY = 0xAD

OP_INIT = 0x01
OP_FINALIZE = 0x03

SW_BIP32_UNINITIALIZED_SEED = 0x9C14
SW_BIP32_INITIALIZED_SEED = 0x9C17

SECP256K1_ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)


def parse_args():
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent
    sibling_applet_repo = repo_root.parent / "SatochipApplet"
    local_applet_repo = repo_root
    if (local_applet_repo / "scripts" / "test_ed25519.py").exists():
        default_applet_repo = local_applet_repo
    else:
        default_applet_repo = sibling_applet_repo
    default_pysatochip = repo_root.parent / "pysatochip-src"

    parser = argparse.ArgumentParser(
        description="Run an integrated regression suite for legacy Satochip flows and Ed25519 flows."
    )
    parser.add_argument(
        "--applet-repo",
        default=str(default_applet_repo),
        help="Path to the SatochipApplet checkout containing scripts/test_ed25519.py.",
    )
    parser.add_argument(
        "--pysatochip-src",
        default=str(default_pysatochip),
        help="Path to the local pysatochip source checkout.",
    )
    parser.add_argument("--list-readers", action="store_true", help="List PC/SC readers and exit.")
    parser.add_argument("--reader", help="Reader name, or a unique substring of the reader name.")
    parser.add_argument("--reader-index", type=int, help="Reader index from --list-readers output.")
    parser.add_argument("--pin", default="123456", help="PIN used for setup and verification.")
    parser.add_argument("--setup", action="store_true", help="Initialize the card if setup has not been performed yet.")
    parser.add_argument("--reset-before", action="store_true", help="Reset BIP32 and Ed25519 seeds before the suite.")
    parser.add_argument("--reset-after", action="store_true", help="Reset BIP32 and Ed25519 seeds after the suite.")
    parser.add_argument("--skip-bip32", action="store_true", help="Skip the legacy BIP32/Satochip smoke tests.")
    parser.add_argument("--skip-ed25519", action="store_true", help="Skip the Ed25519 smoke tests.")
    parser.add_argument(
        "--bip32-seed-hex",
        default="000102030405060708090a0b0c0d0e0f",
        help="Hex-encoded BIP32 seed.",
    )
    parser.add_argument(
        "--bip32-path",
        default="m/44'/0'/0'",
        help="BIP32 path used for the legacy derivation tests.",
    )
    parser.add_argument(
        "--bip32-message",
        default="satochip regression message",
        help="UTF-8 message used for the legacy signMessage smoke test.",
    )
    parser.add_argument("--bip32-message-hex", help="Hex-encoded legacy signMessage payload.")
    parser.add_argument(
        "--ed25519-seed-hex",
        default="000102030405060708090a0b0c0d0e0f",
        help="Hex-encoded Ed25519 master seed.",
    )
    parser.add_argument(
        "--ed25519-path",
        default="m/44'/0'/0'/0'",
        help="Hardened-only SLIP-0010 path used for Ed25519 tests.",
    )
    parser.add_argument(
        "--ed25519-message",
        default="hello from satochip ed25519",
        help="UTF-8 message used for the Ed25519 sign smoke test.",
    )
    parser.add_argument("--ed25519-message-hex", help="Hex-encoded Ed25519 message payload.")
    parser.add_argument("--no-reference", action="store_true", help="Skip software-side Ed25519 comparison.")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging.")
    return parser.parse_args()


def load_helper_module(applet_repo):
    helper_path = applet_repo / "scripts" / "test_ed25519.py"
    if not helper_path.exists():
        raise RuntimeError("Helper script not found: {0}".format(helper_path))

    module_name = "satochip_test_ed25519_helper"
    spec = importlib.util.spec_from_file_location(module_name, str(helper_path))
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load helper module from {0}".format(helper_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bootstrap_pysatochip(pysatochip_src):
    if not pysatochip_src.exists():
        raise RuntimeError("pysatochip source not found: {0}".format(pysatochip_src))
    path = str(pysatochip_src)
    if path not in sys.path:
        sys.path.insert(0, path)

    from pysatochip.SecureChannel import SecureChannel
    from pysatochip.ecc import (
        ECPubkey,
        InvalidECPointException,
        generator,
        msg_magic,
        sig_string_from_der_sig,
    )

    return {
        "SecureChannel": SecureChannel,
        "ECPubkey": ECPubkey,
        "InvalidECPointException": InvalidECPointException,
        "generator": generator,
        "msg_magic": msg_magic,
        "sig_string_from_der_sig": sig_string_from_der_sig,
    }


def normalize_hex(value):
    return "".join(value.split()).lower()


def parse_message(text_value, hex_value):
    if hex_value:
        return bytes.fromhex(normalize_hex(hex_value))
    return text_value.encode("utf-8")


def parse_bip32_path(path):
    path = path.strip()
    if path in ("m", "M", ""):
        return 0, b"", []
    if not (path.startswith("m/") or path.startswith("M/")):
        raise RuntimeError("Invalid BIP32 path: {0}".format(path))

    encoded = bytearray()
    indexes = []
    for raw_component in path[2:].split("/"):
        component = raw_component.strip()
        if not component:
            raise RuntimeError("Invalid empty path component in {0}".format(path))

        hardened = False
        if component[-1] in ("'", "h", "H"):
            hardened = True
            component = component[:-1]

        value = int(component, 10)
        if value < 0 or value >= 0x80000000:
            raise RuntimeError("Invalid BIP32 index: {0}".format(raw_component))

        index = value | 0x80000000 if hardened else value
        indexes.append(index)
        encoded.extend(index.to_bytes(4, "big"))
    return len(indexes), bytes(encoded), indexes


def derive_bip32_reference(seed, indexes, generator_fn):
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    private_value = int.from_bytes(digest[:32], "big")
    chain_code = digest[32:]
    if private_value <= 0 or private_value >= SECP256K1_ORDER:
        raise RuntimeError("Invalid BIP32 master key produced from seed")

    for index in indexes:
        if index & 0x80000000:
            data = b"\x00" + private_value.to_bytes(32, "big") + index.to_bytes(4, "big")
        else:
            public_key = (generator_fn() * private_value).get_public_key_bytes(compressed=True)
            data = public_key + index.to_bytes(4, "big")
        digest = hmac.new(chain_code, data, hashlib.sha512).digest()
        factor = int.from_bytes(digest[:32], "big")
        if factor >= SECP256K1_ORDER:
            raise RuntimeError("Invalid BIP32 child factor")
        private_value = (private_value + factor) % SECP256K1_ORDER
        if private_value == 0:
            raise RuntimeError("Derived invalid zero BIP32 private key")
        chain_code = digest[32:]

    public_key = generator_fn() * private_value
    return {
        "private_value": private_value,
        "chain_code": chain_code,
        "public_key": public_key,
        "coordx": public_key.get_public_key_bytes(compressed=True)[1:],
    }


def parse_size_prefixed_blob(buffer, offset, label, expected_len=None):
    if len(buffer) < offset + 2:
        raise RuntimeError("{0} response too short".format(label))
    size = ((buffer[offset] & 0xFF) << 8) | (buffer[offset + 1] & 0xFF)
    start = offset + 2
    end = start + size
    if len(buffer) < end:
        raise RuntimeError("{0} response length mismatch".format(label))
    blob = bytes(buffer[start:end])
    if expected_len is not None and size != expected_len:
        raise RuntimeError(
            "{0} has unexpected size {1}, expected {2}".format(label, size, expected_len)
        )
    return blob, end


def parse_authentikey_response(response):
    coordx, offset = parse_size_prefixed_blob(response, 0, "coordx", 32)
    signature, offset = parse_size_prefixed_blob(response, offset, "signature")
    if offset != len(response):
        raise RuntimeError("Unexpected trailing data in authentikey response")
    return {
        "coordx": coordx,
        "signature": signature,
        "message": bytes(response[: 34]),
    }


def parse_extended_key_response(response):
    if len(response) < 32:
        raise RuntimeError("Extended key response too short")
    chain_code = bytes(response[:32])
    coordx, offset = parse_size_prefixed_blob(response, 32, "extended key coordx", 32)
    self_sig, offset = parse_size_prefixed_blob(response, offset, "extended key self-signature")
    auth_sig, offset = parse_size_prefixed_blob(response, offset, "extended key authentikey signature")
    if offset != len(response):
        raise RuntimeError("Unexpected trailing data in extended key response")
    return {
        "chain_code": chain_code,
        "coordx": coordx,
        "self_signature": self_sig,
        "auth_signature": auth_sig,
        "self_message": bytes(response[:66]),
        "auth_message": bytes(response[: 68 + len(self_sig)]),
    }


def verify_recoverable_signature(helper, ecc_modules, message, coordx, signature_der):
    pubkey = helper.recover_pubkey_from_signature(
        ecc_modules["ECPubkey"],
        ecc_modules["InvalidECPointException"],
        coordx,
        message,
        signature_der,
    )
    if bytes(pubkey.get_public_key_bytes(compressed=True)[1:]) != bytes(coordx):
        raise RuntimeError("Recovered pubkey does not match coordx")
    sig_string = ecc_modules["sig_string_from_der_sig"](signature_der)
    pubkey.verify_message_hash(sig_string, hashlib.sha256(message).digest())
    return pubkey


def ensure_pin_verified(session, helper, pin_text, context):
    response, sw1, sw2 = session.verify_pin(pin_text)
    helper.ensure_sw(sw1, sw2, context)
    return response


def maybe_setup_card(session, helper, args):
    raw_status, sw1, sw2, status = session.get_status()
    if (sw1, sw2) not in ((0x90, 0x00), (0x9C, 0x04)):
        raise RuntimeError("card_get_status failed with SW={0}".format(helper.format_sw(sw1, sw2)))

    if status.get("needs_secure_channel"):
        session.initiate_secure_channel()
        raw_status, sw1, sw2, status = session.get_status()
        helper.ensure_sw(sw1, sw2, "card_get_status after secure channel")

    if not status.get("setup_done", False):
        if not args.setup:
            raise RuntimeError("Card is not set up. Rerun with --setup to initialize it.")
        response, sw1, sw2 = session.setup(args.pin)
        helper.ensure_sw(sw1, sw2, "INS_SETUP")
        LOG.info("Card setup completed: %s", response.hex())
        raw_status, sw1, sw2, status = session.get_status()
        helper.ensure_sw(sw1, sw2, "card_get_status after setup")

    helper.print_status(raw_status, status)
    if status.get("needs2FA"):
        raise RuntimeError("2FA is enabled. This script does not support the extra HMAC.")
    return raw_status, status


def reset_bip32_if_needed(session, helper, pin_text):
    pin_bytes = pin_text.encode("utf-8")
    response, sw1, sw2 = session.transmit(
        [CARD_EDGE_CLA, INS_BIP32_RESET_SEED, len(pin_bytes), 0x00, len(pin_bytes)] + list(pin_bytes)
    )
    sw = (sw1 << 8) | sw2
    if sw != SW_BIP32_UNINITIALIZED_SEED:
        helper.ensure_sw(sw1, sw2, "INS_BIP32_RESET_SEED")
    ensure_pin_verified(session, helper, pin_text, "INS_VERIFY_PIN after BIP32 reset")
    return response, sw


def reset_ed25519_if_needed(session, helper, pin_text):
    pin_bytes = pin_text.encode("utf-8")
    response, sw1, sw2 = session.transmit(
        [CARD_EDGE_CLA, helper.INS_ED25519_RESET_SEED, len(pin_bytes), 0x00, len(pin_bytes)]
        + list(pin_bytes)
    )
    sw = (sw1 << 8) | sw2
    if sw != helper.SW_ED25519_UNINITIALIZED_SEED:
        helper.ensure_sw(sw1, sw2, "INS_ED25519_RESET_SEED")
    ensure_pin_verified(session, helper, pin_text, "INS_VERIFY_PIN after Ed25519 reset")
    return response, sw


def run_bip32_suite(session, helper, ecc_modules, seed, depth, path_bytes, path_indexes, message_bytes):
    results = {}

    response, sw1, sw2 = session.transmit([CARD_EDGE_CLA, INS_EXPORT_AUTHENTIKEY, 0x00, 0x00])
    helper.ensure_sw(sw1, sw2, "INS_EXPORT_AUTHENTIKEY")
    export_auth = parse_authentikey_response(response)
    export_auth_pub = verify_recoverable_signature(
        helper, ecc_modules, export_auth["message"], export_auth["coordx"], export_auth["signature"]
    )
    results["export_authentikey_coordx"] = export_auth["coordx"]

    response, sw1, sw2 = session.transmit(
        [CARD_EDGE_CLA, INS_BIP32_IMPORT_SEED, len(seed), 0x00, len(seed)] + list(seed)
    )
    if ((sw1 << 8) | sw2) == SW_BIP32_INITIALIZED_SEED:
        raise RuntimeError("BIP32 seed is already initialized. Use --reset-before for repeatable runs.")
    helper.ensure_sw(sw1, sw2, "INS_BIP32_IMPORT_SEED")
    import_auth = parse_authentikey_response(response)
    import_auth_pub = verify_recoverable_signature(
        helper, ecc_modules, import_auth["message"], import_auth["coordx"], import_auth["signature"]
    )
    if import_auth_pub.get_public_key_bytes(compressed=False) != export_auth_pub.get_public_key_bytes(compressed=False):
        raise RuntimeError("Authentikey changed unexpectedly after INS_BIP32_IMPORT_SEED")

    response, sw1, sw2 = session.transmit([CARD_EDGE_CLA, INS_BIP32_GET_AUTHENTIKEY, 0x00, 0x00])
    helper.ensure_sw(sw1, sw2, "INS_BIP32_GET_AUTHENTIKEY")
    get_auth = parse_authentikey_response(response)
    get_auth_pub = verify_recoverable_signature(
        helper, ecc_modules, get_auth["message"], get_auth["coordx"], get_auth["signature"]
    )
    if get_auth_pub.get_public_key_bytes(compressed=False) != export_auth_pub.get_public_key_bytes(compressed=False):
        raise RuntimeError("INS_BIP32_GET_AUTHENTIKEY does not match exported authentikey")

    response, sw1, sw2 = session.transmit(
        [CARD_EDGE_CLA, INS_BIP32_GET_EXTENDED_KEY, depth, 0x00, len(path_bytes)] + list(path_bytes)
    )
    helper.ensure_sw(sw1, sw2, "INS_BIP32_GET_EXTENDED_KEY")
    extended = parse_extended_key_response(response)
    derived_pub = verify_recoverable_signature(
        helper, ecc_modules, extended["self_message"], extended["coordx"], extended["self_signature"]
    )
    auth_pub_from_extended = verify_recoverable_signature(
        helper, ecc_modules, extended["auth_message"], export_auth["coordx"], extended["auth_signature"]
    )
    if auth_pub_from_extended.get_public_key_bytes(compressed=False) != export_auth_pub.get_public_key_bytes(compressed=False):
        raise RuntimeError("Extended-key authentikey signature does not match exported authentikey")

    reference = derive_bip32_reference(seed, path_indexes, ecc_modules["generator"])
    if extended["chain_code"] != reference["chain_code"]:
        raise RuntimeError("BIP32 chaincode mismatch between card and software reference")
    if extended["coordx"] != reference["coordx"]:
        raise RuntimeError("BIP32 public key mismatch between card and software reference")

    init_payload = len(message_bytes).to_bytes(4, "big")
    response, sw1, sw2 = session.transmit(
        [CARD_EDGE_CLA, INS_SIGN_MESSAGE, 0xFF, OP_INIT, len(init_payload)] + list(init_payload)
    )
    helper.ensure_sw(sw1, sw2, "INS_SIGN_MESSAGE init")
    finalize_payload = len(message_bytes).to_bytes(2, "big") + message_bytes
    response, sw1, sw2 = session.transmit(
        [CARD_EDGE_CLA, INS_SIGN_MESSAGE, 0xFF, OP_FINALIZE, len(finalize_payload)] + list(finalize_payload)
    )
    helper.ensure_sw(sw1, sw2, "INS_SIGN_MESSAGE finalize")
    message_signature = bytes(response)
    message_digest = hashlib.sha256(ecc_modules["msg_magic"](message_bytes)).digest()
    message_hash = hashlib.sha256(message_digest).digest()
    derived_pub.verify_message_hash(
        ecc_modules["sig_string_from_der_sig"](message_signature), message_hash
    )

    tx_hash = hashlib.sha256(b"regression hash:" + message_bytes).digest()
    response, sw1, sw2 = session.transmit(
        [CARD_EDGE_CLA, INS_SIGN_TRANSACTION_HASH, 0xFF, 0x00, len(tx_hash)] + list(tx_hash)
    )
    helper.ensure_sw(sw1, sw2, "INS_SIGN_TRANSACTION_HASH")
    hash_signature = bytes(response)
    derived_pub.verify_message_hash(
        ecc_modules["sig_string_from_der_sig"](hash_signature), tx_hash
    )

    results["authentikey_pub"] = export_auth_pub
    results["derived_pub"] = derived_pub
    results["extended"] = extended
    results["message_signature"] = message_signature
    results["hash_signature"] = hash_signature
    results["reference"] = reference
    return results


def run_bip32_postcheck(session, helper, previous, depth, path_bytes, message_bytes, ecc_modules):
    response, sw1, sw2 = session.transmit(
        [CARD_EDGE_CLA, INS_BIP32_GET_EXTENDED_KEY, depth, 0x00, len(path_bytes)] + list(path_bytes)
    )
    helper.ensure_sw(sw1, sw2, "INS_BIP32_GET_EXTENDED_KEY post-check")
    extended = parse_extended_key_response(response)
    derived_pub = verify_recoverable_signature(
        helper, ecc_modules, extended["self_message"], extended["coordx"], extended["self_signature"]
    )
    if extended["chain_code"] != previous["extended"]["chain_code"]:
        raise RuntimeError("BIP32 chaincode changed after Ed25519 operations")
    if extended["coordx"] != previous["extended"]["coordx"]:
        raise RuntimeError("BIP32 derived public key changed after Ed25519 operations")

    tx_hash = hashlib.sha256(b"regression hash:" + message_bytes).digest()
    response, sw1, sw2 = session.transmit(
        [CARD_EDGE_CLA, INS_SIGN_TRANSACTION_HASH, 0xFF, 0x00, len(tx_hash)] + list(tx_hash)
    )
    helper.ensure_sw(sw1, sw2, "INS_SIGN_TRANSACTION_HASH post-check")
    derived_pub.verify_message_hash(
        ecc_modules["sig_string_from_der_sig"](bytes(response)), tx_hash
    )


def run_ed25519_suite(session, helper, seed, depth, path_bytes, path_indexes, message_bytes, no_reference):
    results = {}
    backend = None if no_reference else helper.load_reference_backend()
    if not no_reference and backend is None:
        LOG.warning("No software Ed25519 backend found. Ed25519 reference comparison will be skipped.")

    response, sw1, sw2 = session.transmit(
        [CARD_EDGE_CLA, helper.INS_ED25519_IMPORT_SEED, len(seed), 0x00, len(seed)] + list(seed)
    )
    if ((sw1 << 8) | sw2) == helper.SW_ED25519_INITIALIZED_SEED:
        raise RuntimeError("Ed25519 seed is already initialized. Use --reset-before for repeatable runs.")
    helper.ensure_sw(sw1, sw2, "INS_ED25519_IMPORT_SEED")
    card_master_pub = helper.parse_blob_response(response, "Ed25519 master public key", 32)

    response, sw1, sw2 = session.transmit(
        [CARD_EDGE_CLA, helper.INS_ED25519_GET_PUBLIC_KEY, depth, 0x00, len(path_bytes)] + list(path_bytes)
    )
    helper.ensure_sw(sw1, sw2, "INS_ED25519_GET_PUBLIC_KEY")
    card_child_pub = helper.parse_blob_response(response, "Ed25519 child public key", 32)

    sign_payload = path_bytes + len(message_bytes).to_bytes(2, "big") + message_bytes
    response, sw1, sw2 = session.transmit(
        [CARD_EDGE_CLA, helper.INS_ED25519_SIGN, depth, 0x00, len(sign_payload)] + list(sign_payload)
    )
    helper.ensure_sw(sw1, sw2, "INS_ED25519_SIGN")
    card_signature = helper.parse_blob_response(response, "Ed25519 signature", 64)

    results["master_pub"] = card_master_pub
    results["child_pub"] = card_child_pub
    results["signature"] = card_signature

    if backend is not None:
        master_seed, _dummy_chain = helper.slip10_derive(seed, [])
        child_seed, _dummy_chain = helper.slip10_derive(seed, path_indexes)
        ref_master_pub = backend.public_key(master_seed)
        ref_child_pub = backend.public_key(child_seed)
        ref_signature = backend.sign(child_seed, message_bytes)
        backend.verify(ref_child_pub, card_signature, message_bytes)

        if ref_master_pub != card_master_pub:
            raise RuntimeError("Ed25519 master public key mismatch between card and software reference")
        if ref_child_pub != card_child_pub:
            raise RuntimeError("Ed25519 child public key mismatch between card and software reference")
        if ref_signature != card_signature:
            raise RuntimeError("Ed25519 signature mismatch between card and software reference")

        results["reference"] = {
            "master_pub": ref_master_pub,
            "child_pub": ref_child_pub,
            "signature": ref_signature,
        }
    return results


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s | %(name)s | %(message)s",
    )

    applet_repo = Path(args.applet_repo).resolve()
    pysatochip_src = Path(args.pysatochip_src).resolve()
    helper = load_helper_module(applet_repo)
    ecc_modules = bootstrap_pysatochip(pysatochip_src)

    readers = helper.list_readers()
    chosen_reader = helper.select_reader(args.reader, args.reader_index)
    if args.list_readers:
        for index, reader in enumerate(readers):
            marker = "*" if str(reader) == str(chosen_reader) else " "
            print("[{0}] {1}: {2}".format(marker, index, reader))
        return 0

    bip32_seed = bytes.fromhex(normalize_hex(args.bip32_seed_hex))
    if len(bip32_seed) == 0 or len(bip32_seed) > 64:
        raise RuntimeError("BIP32 seed length must be between 1 and 64 bytes")
    bip32_message = parse_message(args.bip32_message, args.bip32_message_hex)
    bip32_depth, bip32_path_bytes, bip32_indexes = parse_bip32_path(args.bip32_path)

    ed25519_seed = bytes.fromhex(normalize_hex(args.ed25519_seed_hex))
    if len(ed25519_seed) < 16 or len(ed25519_seed) > 64:
        raise RuntimeError("Ed25519 seed length must be between 16 and 64 bytes")
    ed25519_message = parse_message(args.ed25519_message, args.ed25519_message_hex)
    ed25519_depth, ed25519_path_bytes, ed25519_indexes = helper.parse_hardened_path(args.ed25519_path)

    connection = chosen_reader.createConnection()
    connection.connect()
    session = helper.CardSession(
        connection,
        ecc_modules["SecureChannel"],
        ecc_modules["ECPubkey"],
        ecc_modules["InvalidECPointException"],
        logging.DEBUG if args.debug else logging.INFO,
    )

    summary = []
    bip32_results = None

    try:
        session.select_applet()
        print("Reader: {0}".format(chosen_reader))
        print("ATR   : {0}".format(bytes(connection.getATR()).hex()))

        maybe_setup_card(session, helper, args)
        ensure_pin_verified(session, helper, args.pin, "INS_VERIFY_PIN")
        summary.append("PASS secure_channel/setup/pin")

        if args.reset_before:
            reset_bip32_if_needed(session, helper, args.pin)
            summary.append("PASS reset_before_bip32")
            reset_ed25519_if_needed(session, helper, args.pin)
            summary.append("PASS reset_before_ed25519")

        raw_status, sw1, sw2, status = session.get_status()
        helper.ensure_sw(sw1, sw2, "card_get_status before suite")
        helper.print_status(raw_status, status)

        if not args.skip_bip32:
            bip32_results = run_bip32_suite(
                session,
                helper,
                ecc_modules,
                bip32_seed,
                bip32_depth,
                bip32_path_bytes,
                bip32_indexes,
                bip32_message,
            )
            summary.append("PASS bip32_smoke")

        if not args.skip_ed25519:
            ed25519_results = run_ed25519_suite(
                session,
                helper,
                ed25519_seed,
                ed25519_depth,
                ed25519_path_bytes,
                ed25519_indexes,
                ed25519_message,
                args.no_reference,
            )
            summary.append("PASS ed25519_smoke")
            print("Ed25519 master pubkey : {0}".format(ed25519_results["master_pub"].hex()))
            print("Ed25519 child pubkey  : {0}".format(ed25519_results["child_pub"].hex()))
            print("Ed25519 signature     : {0}".format(ed25519_results["signature"].hex()))

        if bip32_results is not None and not args.skip_ed25519:
            run_bip32_postcheck(
                session,
                helper,
                bip32_results,
                bip32_depth,
                bip32_path_bytes,
                bip32_message,
                ecc_modules,
            )
            summary.append("PASS bip32_postcheck_after_ed25519")

        if bip32_results is not None:
            print("Authentikey coordx    : {0}".format(bip32_results["export_authentikey_coordx"].hex()))
            print("BIP32 child coordx    : {0}".format(bip32_results["extended"]["coordx"].hex()))
            print("BIP32 chaincode       : {0}".format(bip32_results["extended"]["chain_code"].hex()))
            print("BIP32 msg signature   : {0}".format(bip32_results["message_signature"].hex()))
            print("BIP32 hash signature  : {0}".format(bip32_results["hash_signature"].hex()))

        raw_status, sw1, sw2, status = session.get_status()
        helper.ensure_sw(sw1, sw2, "card_get_status after suite")
        helper.print_status(raw_status, status)

        if args.reset_after:
            if not args.skip_bip32:
                reset_bip32_if_needed(session, helper, args.pin)
                summary.append("PASS reset_after_bip32")
            if not args.skip_ed25519:
                reset_ed25519_if_needed(session, helper, args.pin)
                summary.append("PASS reset_after_ed25519")

        print("Summary:")
        for line in summary:
            print("  {0}".format(line))
        print("Result: PASS")
        return 0
    finally:
        try:
            connection.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        LOG.error("%s", exc)
        raise SystemExit(1)
