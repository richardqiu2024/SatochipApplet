#!/usr/bin/env python3

import argparse
import hmac
import importlib.util
import logging
import sys
from hashlib import sha1
from pathlib import Path


LOG = logging.getLogger("test_sensitive_failure_paths")

CARD_EDGE_CLA = 0xB0
INS_VERIFY_PIN = 0x42
INS_BIP32_IMPORT_SEED = 0x6C
INS_BIP32_GET_EXTENDED_KEY = 0x6D
INS_SIGN_MESSAGE = 0x6E
INS_SIGN_TRANSACTION = 0x6F
INS_BIP32_RESET_SEED = 0x77
INS_SIGN_TRANSACTION_HASH = 0x7A
INS_PROCESS_SECURE_CHANNEL = 0x82
INS_ED25519_IMPORT_SEED = 0x7B
INS_ED25519_RESET_SEED = 0x7C
INS_ED25519_GET_PUBLIC_KEY = 0x7D
INS_ED25519_SIGN = 0x7E

OP_INIT = 0x01
OP_FINALIZE = 0x03

SW_WRONG_LENGTH = 0x6700
SW_INCORRECT_INITIALIZATION = 0x9C13
SW_INCORRECT_TXHASH = 0x9C15
SW_BIP32_UNINITIALIZED_SEED = 0x9C14
SW_ED25519_UNINITIALIZED_SEED = 0x9C50
SW_SECURE_CHANNEL_REQUIRED = 0x9C20
SW_SECURE_CHANNEL_UNINITIALIZED = 0x9C21
SW_SECURE_CHANNEL_WRONG_IV = 0x9C22
SW_SECURE_CHANNEL_WRONG_MAC = 0x9C23


def parse_args():
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent
    default_pysatochip = repo_root.parent / "pysatochip-src"

    parser = argparse.ArgumentParser(
        description="Run failure-path regression checks for sensitive BIP32 and Ed25519 handlers."
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
    parser.add_argument(
        "--bip32-seed-hex",
        default="000102030405060708090a0b0c0d0e0f",
        help="Hex-encoded BIP32 seed.",
    )
    parser.add_argument(
        "--bip32-path",
        default="m/44'/0'/0'",
        help="BIP32 path used for the valid temporary extended-key step.",
    )
    parser.add_argument(
        "--bip32-message",
        default="satochip failure-path regression",
        help="UTF-8 message used for the BIP32 sign regression.",
    )
    parser.add_argument(
        "--ed25519-seed-hex",
        default="000102030405060708090a0b0c0d0e0f",
        help="Hex-encoded Ed25519 seed.",
    )
    parser.add_argument(
        "--ed25519-path",
        default="m/44'/0'/0'/0'",
        help="Hardened-only SLIP-0010 path used for Ed25519 checks.",
    )
    parser.add_argument(
        "--ed25519-message",
        default="failure-path check",
        help="UTF-8 message used for the Ed25519 sign regression.",
    )
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging.")
    return parser.parse_args()


def load_helper_module():
    helper_path = Path(__file__).resolve().parent / "test_ed25519.py"
    module_name = "satochip_test_ed25519_helper_failure_paths"
    spec = importlib.util.spec_from_file_location(module_name, str(helper_path))
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load helper module from {0}".format(helper_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def normalize_hex(value):
    return "".join(value.split()).lower()


def format_sw(sw1, sw2):
    return "0x{0:02X}{1:02X}".format(sw1, sw2)


def parse_bip32_path(path):
    path = path.strip()
    if path in ("m", "M", ""):
        return 0, b""
    if not (path.startswith("m/") or path.startswith("M/")):
        raise RuntimeError("Invalid BIP32 path: {0}".format(path))

    encoded = bytearray()
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
        encoded.extend(index.to_bytes(4, "big"))
    return len(encoded) // 4, bytes(encoded)


def expect_sw(sw1, sw2, expected_sw, context):
    actual = (sw1 << 8) | sw2
    if actual != expected_sw:
        raise RuntimeError(
            "{0} failed with SW={1}, expected 0x{2:04X}".format(context, format_sw(sw1, sw2), expected_sw)
        )


def verify_pin_apdu(pin_text):
    pin_bytes = pin_text.encode("utf-8")
    return [CARD_EDGE_CLA, INS_VERIFY_PIN, 0x00, 0x00, len(pin_bytes)] + list(pin_bytes)


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
        LOG.info("Card setup completed: %s", bytes(response).hex())
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
        [CARD_EDGE_CLA, INS_ED25519_RESET_SEED, len(pin_bytes), 0x00, len(pin_bytes)] + list(pin_bytes)
    )
    sw = (sw1 << 8) | sw2
    if sw != SW_ED25519_UNINITIALIZED_SEED:
        helper.ensure_sw(sw1, sw2, "INS_ED25519_RESET_SEED")
    ensure_pin_verified(session, helper, pin_text, "INS_VERIFY_PIN after Ed25519 reset")
    return response, sw


def sign_message(session, helper, key_nb, message_bytes):
    init_payload = len(message_bytes).to_bytes(4, "big")
    response, sw1, sw2 = session.transmit(
        [CARD_EDGE_CLA, INS_SIGN_MESSAGE, key_nb, OP_INIT, len(init_payload)] + list(init_payload)
    )
    helper.ensure_sw(sw1, sw2, "INS_SIGN_MESSAGE init")

    finalize_payload = len(message_bytes).to_bytes(2, "big") + message_bytes
    response, sw1, sw2 = session.transmit(
        [CARD_EDGE_CLA, INS_SIGN_MESSAGE, key_nb, OP_FINALIZE, len(finalize_payload)] + list(finalize_payload)
    )
    return bytes(response), sw1, sw2


def expect_sign_message_rejected(session, key_nb, message_bytes, expected_sw, context):
    init_payload = len(message_bytes).to_bytes(4, "big")
    response, sw1, sw2 = session.transmit(
        [CARD_EDGE_CLA, INS_SIGN_MESSAGE, key_nb, OP_INIT, len(init_payload)] + list(init_payload)
    )
    expect_sw(sw1, sw2, expected_sw, context)
    return bytes(response), sw1, sw2


def expect_sign_transaction_sw(session, key_nb, tx_hash_bytes, expected_sw, context):
    response, sw1, sw2 = session.transmit(
        [CARD_EDGE_CLA, INS_SIGN_TRANSACTION, key_nb, 0x00, len(tx_hash_bytes)] + list(tx_hash_bytes)
    )
    expect_sw(sw1, sw2, expected_sw, context)
    return bytes(response), sw1, sw2


def assemble_secure_channel_wrapper(iv_bytes, ciphertext, mac_bytes):
    data = bytearray(iv_bytes)
    data.extend(len(ciphertext).to_bytes(2, "big"))
    data.extend(ciphertext)
    data.extend(len(mac_bytes).to_bytes(2, "big"))
    data.extend(mac_bytes)
    return [CARD_EDGE_CLA, INS_PROCESS_SECURE_CHANNEL, 0x00, 0x00, len(data)] + list(data)


def build_secure_channel_wrapper(session, plain_apdu, iv=None, mac=None):
    iv_bytes, ciphertext, mac_bytes = session.sc.encrypt_secure_channel(bytes(plain_apdu))
    if iv is not None:
        iv_bytes = bytes(iv)
    if mac is not None:
        mac_bytes = bytes(mac)
    return assemble_secure_channel_wrapper(iv_bytes, ciphertext, mac_bytes)


def compute_secure_channel_mac(session, iv_bytes, ciphertext):
    data_to_mac = bytes(iv_bytes) + len(ciphertext).to_bytes(2, "big") + bytes(ciphertext)
    return hmac.new(session.sc.mac_key, data_to_mac, sha1).digest()


def build_tampered_secure_channel_wrapper(session, plain_apdu, mutate_iv=None, mutate_mac=None):
    iv_bytes, ciphertext, mac_bytes = session.sc.encrypt_secure_channel(bytes(plain_apdu))
    if mutate_iv is not None:
        iv_bytes = bytes(mutate_iv(bytearray(iv_bytes)))
    if mutate_mac is not None:
        mac_bytes = bytes(mutate_mac(bytearray(mac_bytes)))
    else:
        mac_bytes = compute_secure_channel_mac(session, iv_bytes, ciphertext)
    return assemble_secure_channel_wrapper(iv_bytes, ciphertext, mac_bytes)


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s | %(name)s | %(message)s",
    )

    helper = load_helper_module()
    SecureChannel, ECPubkey, InvalidECPointException = helper.bootstrap_modules(
        Path(args.pysatochip_src).resolve()
    )

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
    bip32_message = args.bip32_message.encode("utf-8")
    bip32_depth, bip32_path_bytes = parse_bip32_path(args.bip32_path)

    ed25519_seed = bytes.fromhex(normalize_hex(args.ed25519_seed_hex))
    if len(ed25519_seed) < 16 or len(ed25519_seed) > 64:
        raise RuntimeError("Ed25519 seed length must be between 16 and 64 bytes")
    ed25519_message = args.ed25519_message.encode("utf-8")
    ed25519_depth, ed25519_path_bytes, _dummy_indexes = helper.parse_hardened_path(args.ed25519_path)

    connection = chosen_reader.createConnection()
    connection.connect()
    session = helper.CardSession(
        connection,
        SecureChannel,
        ECPubkey,
        InvalidECPointException,
        logging.DEBUG if args.debug else logging.INFO,
    )

    summary = []

    try:
        session.select_applet()
        print("Reader: {0}".format(chosen_reader))
        print("ATR   : {0}".format(bytes(connection.getATR()).hex()))

        response, sw1, sw2 = session.transmit_raw([CARD_EDGE_CLA, INS_VERIFY_PIN, 0x00, 0x00, 0x00])
        expect_sw(sw1, sw2, SW_SECURE_CHANNEL_REQUIRED, "Protected command without secure channel")
        summary.append("PASS secure_channel_rejects_raw_protected_command")

        response, sw1, sw2 = session.transmit_raw([CARD_EDGE_CLA, INS_PROCESS_SECURE_CHANNEL, 0x00, 0x00, 0x00])
        expect_sw(sw1, sw2, SW_SECURE_CHANNEL_UNINITIALIZED, "INS_PROCESS_SECURE_CHANNEL before init")
        summary.append("PASS secure_channel_rejects_uninitialized_process")

        maybe_setup_card(session, helper, args)
        if session.sc is None:
            session.initiate_secure_channel()
        ensure_pin_verified(session, helper, args.pin, "INS_VERIFY_PIN")
        summary.append("PASS secure_channel/setup/pin")

        if args.reset_before:
            reset_bip32_if_needed(session, helper, args.pin)
            reset_ed25519_if_needed(session, helper, args.pin)
            summary.append("PASS reset_before")

        response, sw1, sw2 = session.transmit_raw(
            [CARD_EDGE_CLA, INS_PROCESS_SECURE_CHANNEL, 0x00, 0x00, 18] + ([0x00] * 18)
        )
        expect_sw(sw1, sw2, SW_WRONG_LENGTH, "INS_PROCESS_SECURE_CHANNEL truncated envelope")
        summary.append("PASS secure_channel_rejects_truncated_envelope")

        wrong_mac_wrapper = build_tampered_secure_channel_wrapper(
            session,
            verify_pin_apdu(args.pin),
            mutate_mac=lambda mac_bytes: mac_bytes[:-1] + bytearray([(mac_bytes[-1] ^ 0x01) & 0xFF]),
        )
        response, sw1, sw2 = session.transmit_raw(wrong_mac_wrapper)
        expect_sw(sw1, sw2, SW_SECURE_CHANNEL_WRONG_MAC, "INS_PROCESS_SECURE_CHANNEL wrong MAC")
        summary.append("PASS secure_channel_rejects_wrong_mac")

        even_iv_wrapper = build_tampered_secure_channel_wrapper(
            session,
            verify_pin_apdu(args.pin),
            mutate_iv=lambda iv_bytes: iv_bytes[:-1] + bytearray([iv_bytes[-1] & 0xFE]),
        )
        response, sw1, sw2 = session.transmit_raw(even_iv_wrapper)
        expect_sw(sw1, sw2, SW_SECURE_CHANNEL_WRONG_IV, "INS_PROCESS_SECURE_CHANNEL even IV")
        summary.append("PASS secure_channel_rejects_even_iv")

        replay_wrapper = build_secure_channel_wrapper(session, verify_pin_apdu(args.pin))
        response, sw1, sw2 = session.transmit_raw(replay_wrapper)
        helper.ensure_sw(sw1, sw2, "INS_PROCESS_SECURE_CHANNEL valid wrapped VERIFY_PIN")
        if len(response) != 0:
            session.decrypt_response(response)
        response, sw1, sw2 = session.transmit_raw(replay_wrapper)
        expect_sw(sw1, sw2, SW_SECURE_CHANNEL_WRONG_IV, "INS_PROCESS_SECURE_CHANNEL replayed IV")
        ensure_pin_verified(session, helper, args.pin, "INS_VERIFY_PIN after secure-channel tamper")
        summary.append("PASS secure_channel_recovers_after_tamper")

        session.select_applet()
        response, sw1, sw2 = session.transmit(verify_pin_apdu(args.pin))
        expect_sw(sw1, sw2, SW_SECURE_CHANNEL_UNINITIALIZED, "Wrapped command after applet reselect")
        summary.append("PASS secure_channel_rejects_stale_session_after_reselect")
        session.initiate_secure_channel()
        ensure_pin_verified(session, helper, args.pin, "INS_VERIFY_PIN after secure-channel reselect recovery")
        summary.append("PASS secure_channel_recovers_after_reselect")

        response, sw1, sw2 = session.transmit([CARD_EDGE_CLA, INS_BIP32_IMPORT_SEED, 65, 0x00, 0x00])
        expect_sw(sw1, sw2, SW_WRONG_LENGTH, "INS_BIP32_IMPORT_SEED invalid length")
        summary.append("PASS bip32_import_rejects_bad_length")

        response, sw1, sw2 = session.transmit(
            [CARD_EDGE_CLA, INS_BIP32_IMPORT_SEED, len(bip32_seed), 0x00, len(bip32_seed)] + list(bip32_seed)
        )
        helper.ensure_sw(sw1, sw2, "INS_BIP32_IMPORT_SEED valid seed")

        _response, sw1, sw2 = expect_sign_message_rejected(
            session, 0xFF, bip32_message, SW_INCORRECT_INITIALIZATION, "INS_SIGN_MESSAGE without derived key"
        )
        summary.append("PASS bip32_sign_rejects_missing_extended_key")

        tx_hash = bytes(range(1, 33))
        response, sw1, sw2 = expect_sign_transaction_sw(
            session, 0xFF, tx_hash, SW_INCORRECT_INITIALIZATION, "INS_SIGN_TRANSACTION without derived key"
        )
        summary.append("PASS bip32_tx_sign_rejects_missing_extended_key")

        response, sw1, sw2 = session.transmit(
            [CARD_EDGE_CLA, INS_SIGN_TRANSACTION_HASH, 0xFF, 0x00, len(tx_hash)] + list(tx_hash)
        )
        expect_sw(sw1, sw2, SW_INCORRECT_INITIALIZATION, "INS_SIGN_TRANSACTION_HASH without derived key")
        summary.append("PASS bip32_hash_sign_rejects_missing_extended_key")

        response, sw1, sw2 = session.transmit(
            [CARD_EDGE_CLA, INS_BIP32_GET_EXTENDED_KEY, bip32_depth, 0x00, len(bip32_path_bytes)]
            + list(bip32_path_bytes)
        )
        helper.ensure_sw(sw1, sw2, "INS_BIP32_GET_EXTENDED_KEY valid path")

        response, sw1, sw2 = sign_message(session, helper, 0xFF, bip32_message)
        helper.ensure_sw(sw1, sw2, "INS_SIGN_MESSAGE after derivation")
        if len(response) == 0:
            raise RuntimeError("INS_SIGN_MESSAGE returned an empty signature after valid derivation")
        summary.append("PASS bip32_sign_succeeds_after_derivation")

        response, sw1, sw2 = expect_sign_transaction_sw(
            session, 0xFF, tx_hash, SW_INCORRECT_TXHASH, "INS_SIGN_TRANSACTION after derivation"
        )
        summary.append("PASS bip32_tx_sign_reaches_txhash_check_after_derivation")

        reset_bip32_if_needed(session, helper, args.pin)
        response, sw1, sw2 = session.transmit(
            [CARD_EDGE_CLA, INS_BIP32_IMPORT_SEED, len(bip32_seed), 0x00, len(bip32_seed)] + list(bip32_seed)
        )
        helper.ensure_sw(sw1, sw2, "INS_BIP32_IMPORT_SEED after reset")

        _response, sw1, sw2 = expect_sign_message_rejected(
            session,
            0xFF,
            bip32_message,
            SW_INCORRECT_INITIALIZATION,
            "INS_SIGN_MESSAGE after reset without derivation",
        )
        summary.append("PASS bip32_reset_clears_cached_extended_key")

        response, sw1, sw2 = expect_sign_transaction_sw(
            session,
            0xFF,
            tx_hash,
            SW_INCORRECT_INITIALIZATION,
            "INS_SIGN_TRANSACTION after reset without derivation",
        )
        summary.append("PASS bip32_reset_clears_cached_extended_key_for_tx_sign")

        short_seed = bytes(range(8))
        response, sw1, sw2 = session.transmit(
            [CARD_EDGE_CLA, INS_ED25519_IMPORT_SEED, len(short_seed), 0x00, len(short_seed)] + list(short_seed)
        )
        expect_sw(sw1, sw2, SW_WRONG_LENGTH, "INS_ED25519_IMPORT_SEED invalid length")
        summary.append("PASS ed25519_import_rejects_bad_length")

        response, sw1, sw2 = session.transmit(
            [CARD_EDGE_CLA, INS_ED25519_IMPORT_SEED, len(ed25519_seed), 0x00, len(ed25519_seed)]
            + list(ed25519_seed)
        )
        helper.ensure_sw(sw1, sw2, "INS_ED25519_IMPORT_SEED valid seed")

        malformed_sign_payload = ed25519_path_bytes + (len(ed25519_message) + 5).to_bytes(2, "big") + ed25519_message
        response, sw1, sw2 = session.transmit(
            [CARD_EDGE_CLA, INS_ED25519_SIGN, ed25519_depth, 0x00, len(malformed_sign_payload)]
            + list(malformed_sign_payload)
        )
        expect_sw(sw1, sw2, SW_WRONG_LENGTH, "INS_ED25519_SIGN malformed payload")
        summary.append("PASS ed25519_sign_rejects_bad_length")

        response, sw1, sw2 = session.transmit(
            [CARD_EDGE_CLA, INS_ED25519_GET_PUBLIC_KEY, ed25519_depth, 0x00, len(ed25519_path_bytes)]
            + list(ed25519_path_bytes)
        )
        helper.ensure_sw(sw1, sw2, "INS_ED25519_GET_PUBLIC_KEY after failed sign")
        pubkey = helper.parse_blob_response(response, "Ed25519 public key", 32)
        if len(pubkey) != 32:
            raise RuntimeError("Unexpected Ed25519 public key length after failure recovery")

        valid_sign_payload = ed25519_path_bytes + len(ed25519_message).to_bytes(2, "big") + ed25519_message
        response, sw1, sw2 = session.transmit(
            [CARD_EDGE_CLA, INS_ED25519_SIGN, ed25519_depth, 0x00, len(valid_sign_payload)]
            + list(valid_sign_payload)
        )
        helper.ensure_sw(sw1, sw2, "INS_ED25519_SIGN after failed sign")
        signature = helper.parse_blob_response(response, "Ed25519 signature", 64)
        if len(signature) != 64:
            raise RuntimeError("Unexpected Ed25519 signature length after failure recovery")
        summary.append("PASS ed25519_recovers_after_failed_sign")

        raw_status, sw1, sw2, status = session.get_status()
        helper.ensure_sw(sw1, sw2, "card_get_status after failure-path suite")
        helper.print_status(raw_status, status)

        if args.reset_after:
            reset_bip32_if_needed(session, helper, args.pin)
            reset_ed25519_if_needed(session, helper, args.pin)
            summary.append("PASS reset_after")

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
    sys.exit(main())
