#!/usr/bin/env python3

import argparse
import hashlib
import hmac
import logging
import os
import sys
from pathlib import Path


LOG = logging.getLogger("test_ed25519")

CARD_EDGE_CLA = 0xB0
INS_SETUP = 0x2A
INS_VERIFY_PIN = 0x42
INS_GET_STATUS = 0x3C
INS_INIT_SECURE_CHANNEL = 0x81
INS_PROCESS_SECURE_CHANNEL = 0x82

INS_ED25519_IMPORT_SEED = 0x7B
INS_ED25519_RESET_SEED = 0x7C
INS_ED25519_GET_PUBLIC_KEY = 0x7D
INS_ED25519_SIGN = 0x7E

SW_ED25519_UNINITIALIZED_SEED = 0x9C50
SW_ED25519_INITIALIZED_SEED = 0x9C51

SELECT = [0x00, 0xA4, 0x04, 0x00]
SATOCHIP_AIDS = [
    bytes.fromhex("5361746F4368697000"),
    bytes.fromhex("5361746F43686970"),
]

STATUS_ED25519_READY_OFFSET = 16
STATUS_ED25519_SEEDED_OFFSET = 17
STATUS_ED25519_LAST_INIT_SW_OFFSET = 18
STATUS_ED25519_INIT_ATTEMPTS_OFFSET = 20
STATUS_ED25519_ALLOCATOR_OFFSET = 21
STATUS_ED25519_BUFFER_STRATEGY_OFFSET = 22


def parse_args():
    repo_root = Path(__file__).resolve().parents[1]
    default_pysatochip = repo_root.parent / "pysatochip-src"

    parser = argparse.ArgumentParser(
        description="Exercise the custom Ed25519 APDUs in the modified Satochip applet."
    )
    parser.add_argument(
        "--pysatochip-src",
        default=str(default_pysatochip),
        help="Path to the local pysatochip source checkout.",
    )
    parser.add_argument("--list-readers", action="store_true", help="List PC/SC readers and exit.")
    parser.add_argument("--reader", help="Reader name, or a unique substring of the reader name.")
    parser.add_argument("--reader-index", type=int, help="Reader index from --list-readers output.")
    parser.add_argument("--pin", default="123456", help="PIN used for verification and optional Ed25519 reset.")
    parser.add_argument("--setup", action="store_true", help="Initialize the card if setup has not been performed yet.")
    parser.add_argument(
        "--seed-hex",
        default="000102030405060708090a0b0c0d0e0f",
        help="Master seed to import for the Ed25519 test.",
    )
    parser.add_argument(
        "--path",
        default="m/44'/0'/0'/0'",
        help="Hardened-only SLIP-0010 path used for derive/sign tests.",
    )
    parser.add_argument("--message", default="hello from satochip ed25519", help="UTF-8 message to sign.")
    parser.add_argument("--message-hex", help="Hex-encoded message to sign. Overrides --message.")
    parser.add_argument("--reset-before", action="store_true", help="Reset the Ed25519 seed before importing.")
    parser.add_argument("--reset-after", action="store_true", help="Reset the Ed25519 seed after the test completes.")
    parser.add_argument("--no-reference", action="store_true", help="Skip software-side Ed25519 comparison.")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging.")
    return parser.parse_args()


def bootstrap_modules(pysatochip_src):
    if not pysatochip_src.exists():
        raise RuntimeError("pysatochip source not found: {0}".format(pysatochip_src))
    sys.path.insert(0, str(pysatochip_src))
    from pysatochip.SecureChannel import SecureChannel
    from pysatochip.ecc import ECPubkey, InvalidECPointException
    return SecureChannel, ECPubkey, InvalidECPointException


def load_reference_backend():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )

        class CryptoBackend(object):
            @staticmethod
            def public_key(seed):
                private_key = Ed25519PrivateKey.from_private_bytes(seed)
                return private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )

            @staticmethod
            def sign(seed, message):
                return Ed25519PrivateKey.from_private_bytes(seed).sign(message)

            @staticmethod
            def verify(public_key, signature, message):
                Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)

        return CryptoBackend
    except ImportError:
        pass

    try:
        from nacl.signing import SigningKey, VerifyKey

        class NaclBackend(object):
            @staticmethod
            def public_key(seed):
                return bytes(SigningKey(seed).verify_key)

            @staticmethod
            def sign(seed, message):
                return SigningKey(seed).sign(message).signature

            @staticmethod
            def verify(public_key, signature, message):
                VerifyKey(public_key).verify(message, signature)

        return NaclBackend
    except ImportError:
        return None


def list_readers():
    try:
        from smartcard.System import readers
    except ImportError:
        raise RuntimeError(
            "PySCard is not installed. Install it first, for example: pip install pyscard"
        )
    return list(readers())


def select_reader(reader_name, reader_index):
    available = list_readers()
    if not available:
        raise RuntimeError("No PC/SC readers found.")

    if reader_name is not None and reader_index is not None:
        raise RuntimeError("Use either --reader or --reader-index, not both.")

    if reader_index is not None:
        if reader_index < 0 or reader_index >= len(available):
            raise RuntimeError("Reader index {0} out of range.".format(reader_index))
        return available[reader_index]

    if reader_name is None:
        return available[0]

    exact_matches = [reader for reader in available if str(reader) == reader_name]
    if len(exact_matches) == 1:
        return exact_matches[0]

    partial_matches = [reader for reader in available if reader_name in str(reader)]
    if len(partial_matches) == 1:
        return partial_matches[0]
    if not partial_matches:
        raise RuntimeError("Reader not found: {0}".format(reader_name))
    raise RuntimeError(
        "Reader name is ambiguous: {0}. Use --list-readers and --reader-index.".format(
            reader_name
        )
    )


def format_sw(sw1, sw2):
    return "0x{0:02X}{1:02X}".format(sw1, sw2)


def normalize_hex(value):
    return "".join(value.split()).lower()


def parse_message(args):
    if args.message_hex:
        return bytes.fromhex(normalize_hex(args.message_hex))
    return args.message.encode("utf-8")


def parse_hardened_path(path):
    path = path.strip()
    if path in ("m", "M", ""):
        return 0, b"", []
    if not (path.startswith("m/") or path.startswith("M/")):
        raise RuntimeError("Invalid path: {0}".format(path))

    encoded = bytearray()
    indexes = []
    for raw_component in path[2:].split("/"):
        component = raw_component.strip()
        if not component:
            raise RuntimeError("Invalid empty path component in {0}".format(path))
        if component[-1] not in ("'", "h", "H"):
            raise RuntimeError("Ed25519 path must be hardened-only: {0}".format(path))
        value = int(component[:-1], 10)
        if value < 0 or value >= 0x80000000:
            raise RuntimeError("Invalid hardened index: {0}".format(component))
        hardened = value | 0x80000000
        indexes.append(hardened)
        encoded.extend(hardened.to_bytes(4, "big"))
    return len(indexes), bytes(encoded), indexes


def slip10_derive(seed, indexes):
    digest = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    key = digest[:32]
    chain_code = digest[32:]
    for index in indexes:
        digest = hmac.new(
            chain_code,
            b"\x00" + key + index.to_bytes(4, "big"),
            hashlib.sha512,
        ).digest()
        key = digest[:32]
        chain_code = digest[32:]
    return key, chain_code


def parse_blob_response(response, label, expected_len=None):
    if len(response) < 2:
        raise RuntimeError("{0} response too short: {1}".format(label, bytes(response).hex()))
    size = ((response[0] & 0xFF) << 8) | (response[1] & 0xFF)
    blob = bytes(response[2 : 2 + size])
    if len(blob) != size:
        raise RuntimeError(
            "{0} response length mismatch: declared {1}, got {2}".format(
                label, size, len(blob)
            )
        )
    if expected_len is not None and size != expected_len:
        raise RuntimeError(
            "{0} has unexpected size {1}, expected {2}".format(
                label, size, expected_len
            )
        )
    return blob


def decode_extended_status(raw_status):
    decoded = {}
    if len(raw_status) > STATUS_ED25519_READY_OFFSET:
        decoded["ed25519_service_ready"] = raw_status[STATUS_ED25519_READY_OFFSET] != 0
    if len(raw_status) > STATUS_ED25519_SEEDED_OFFSET:
        decoded["ed25519_seeded"] = raw_status[STATUS_ED25519_SEEDED_OFFSET] != 0
    if len(raw_status) > STATUS_ED25519_LAST_INIT_SW_OFFSET + 1:
        decoded["ed25519_last_init_sw"] = (
            (raw_status[STATUS_ED25519_LAST_INIT_SW_OFFSET] << 8)
            | raw_status[STATUS_ED25519_LAST_INIT_SW_OFFSET + 1]
        )
    if len(raw_status) > STATUS_ED25519_INIT_ATTEMPTS_OFFSET:
        decoded["ed25519_init_attempts"] = raw_status[STATUS_ED25519_INIT_ATTEMPTS_OFFSET]
    if len(raw_status) > STATUS_ED25519_ALLOCATOR_OFFSET:
        decoded["ed25519_allocator_strategy"] = raw_status[STATUS_ED25519_ALLOCATOR_OFFSET]
    if len(raw_status) > STATUS_ED25519_BUFFER_STRATEGY_OFFSET:
        decoded["ed25519_buffer_strategy"] = raw_status[STATUS_ED25519_BUFFER_STRATEGY_OFFSET]
    return decoded


def print_status(raw_status, status):
    decoded = decode_extended_status(raw_status)
    print("Status:")
    print("  raw_status            : {0}".format(raw_status.hex()))
    print("  protocol_version      : {0}".format(status.get("protocol_version")))
    print(
        "  applet_version        : {0}.{1}".format(
            status.get("applet_major_version"), status.get("applet_minor_version")
        )
    )
    print("  setup_done            : {0}".format(status.get("setup_done")))
    print("  needs_secure_channel  : {0}".format(status.get("needs_secure_channel")))
    print("  needs_2FA             : {0}".format(status.get("needs2FA")))
    print("  bip32_is_seeded       : {0}".format(status.get("is_seeded")))
    print("  PIN0_remaining_tries  : {0}".format(status.get("PIN0_remaining_tries")))
    if decoded:
        print("  ed25519_ready         : {0}".format(decoded.get("ed25519_service_ready")))
        print("  ed25519_seeded        : {0}".format(decoded.get("ed25519_seeded")))
        if decoded.get("ed25519_last_init_sw") is not None:
            print("  ed25519_last_init_sw  : 0x{0:04X}".format(decoded.get("ed25519_last_init_sw")))
        print("  ed25519_init_attempts : {0}".format(decoded.get("ed25519_init_attempts")))
        print("  ed25519_allocator     : {0}".format(decoded.get("ed25519_allocator_strategy")))
        if decoded.get("ed25519_buffer_strategy") is not None:
            print("  ed25519_buf_strategy  : {0}".format(decoded.get("ed25519_buffer_strategy")))


def parse_status(response):
    status = {}
    if len(response) >= 4:
        status["protocol_major_version"] = response[0]
        status["protocol_minor_version"] = response[1]
        status["applet_major_version"] = response[2]
        status["applet_minor_version"] = response[3]
        status["protocol_version"] = (response[0] << 8) + response[1]
    if len(response) >= 8:
        status["PIN0_remaining_tries"] = response[4]
        status["PUK0_remaining_tries"] = response[5]
        status["PIN1_remaining_tries"] = response[6]
        status["PUK1_remaining_tries"] = response[7]
    if len(response) >= 9:
        status["needs2FA"] = response[8] != 0
    else:
        status["needs2FA"] = False
    if len(response) >= 10:
        status["is_seeded"] = response[9] != 0
    if len(response) >= 11:
        status["setup_done"] = response[10] != 0
    else:
        status["setup_done"] = True
    if len(response) >= 12:
        status["needs_secure_channel"] = response[11] != 0
    else:
        status["needs_secure_channel"] = False
    return status


def parse_to_compact_sig(sigin, recid, compressed):
    sigout = bytearray(65 * [0])
    if sigin[0] != 0x30:
        raise ValueError("Wrong first byte in DER signature")
    lt = sigin[1]
    if sigin[2] != 0x02:
        raise ValueError("Wrong DER marker for R")
    lr = sigin[3]
    for index in range(32):
        if lr >= (index + 1):
            sigout[32 - index] = sigin[4 + lr - 1 - index]
        else:
            sigout[32 - index] = 0
    if sigin[4 + lr] != 0x02:
        raise ValueError("Wrong DER marker for S")
    ls = sigin[5 + lr]
    if lt != (lr + ls + 4):
        raise ValueError("Wrong DER total length")
    for index in range(32):
        if ls >= (index + 1):
            sigout[64 - index] = sigin[5 + lr + ls - index]
        else:
            sigout[64 - index] = 0
    sigout[0] = 27 + recid + (4 if compressed else 0)
    return sigout


def recover_pubkey_from_signature(ECPubkey, InvalidECPointException, coordx, data, der_sig):
    digest = hashlib.sha256()
    digest.update(bytes(data))
    msg_hash = digest.digest()

    for recid in range(4):
        compsig = parse_to_compact_sig(bytearray(der_sig), recid, True)[1:]
        try:
            pubkey = ECPubkey.from_sig_string(compsig, recid, msg_hash)
        except InvalidECPointException:
            continue
        pubkey_bytes = pubkey.get_public_key_bytes(compressed=True)[1:]
        if bytes(pubkey_bytes) == bytes(coordx):
            return pubkey
    raise RuntimeError("Unable to recover card secure-channel public key")


class CardSession(object):
    def __init__(self, connection, secure_channel_cls, ecc_pubkey_cls, invalid_point_exc, loglevel):
        self.connection = connection
        self.SecureChannel = secure_channel_cls
        self.ECPubkey = ecc_pubkey_cls
        self.InvalidECPointException = invalid_point_exc
        self.loglevel = loglevel
        self.needs_secure_channel = False
        self.sc = None
        self.selected_aid = None

    def transmit_raw(self, apdu):
        LOG.debug("raw >> %s", bytes(apdu).hex())
        response, sw1, sw2 = self.connection.transmit(apdu)
        LOG.debug("raw << %s %s", bytes(response).hex(), format_sw(sw1, sw2))
        return bytes(response), sw1, sw2

    def encrypt_apdu(self, apdu):
        iv, ciphertext, mac = self.sc.encrypt_secure_channel(bytes(apdu))
        data = bytearray(iv)
        data.extend(len(ciphertext).to_bytes(2, "big"))
        data.extend(ciphertext)
        data.extend(len(mac).to_bytes(2, "big"))
        data.extend(mac)
        return [CARD_EDGE_CLA, INS_PROCESS_SECURE_CHANNEL, 0x00, 0x00, len(data)] + list(data)

    def decrypt_response(self, response):
        if len(response) == 0:
            return bytes()
        if len(response) < 18:
            raise RuntimeError("Encrypted response too short")
        iv = bytes(response[0:16])
        size = (response[16] << 8) | response[17]
        ciphertext = bytes(response[18:])
        if len(ciphertext) != size:
            raise RuntimeError("Encrypted response length mismatch")
        plaintext = self.sc.decrypt_secure_channel(iv, ciphertext)
        return bytes(plaintext)

    def transmit(self, plain_apdu):
        ins = plain_apdu[1]
        if self.needs_secure_channel and ins not in [0xA4, INS_GET_STATUS, INS_INIT_SECURE_CHANNEL, INS_PROCESS_SECURE_CHANNEL, 0xFF]:
            wrapped = self.encrypt_apdu(plain_apdu)
            response, sw1, sw2 = self.transmit_raw(wrapped)
            if (sw1, sw2) == (0x90, 0x00):
                return self.decrypt_response(response), sw1, sw2
            return response, sw1, sw2
        return self.transmit_raw(plain_apdu)

    def select_applet(self):
        for aid in SATOCHIP_AIDS:
            apdu = SELECT + [len(aid)] + list(aid)
            response, sw1, sw2 = self.transmit(apdu)
            if (sw1, sw2) == (0x90, 0x00):
                self.selected_aid = aid
                return response, sw1, sw2
        raise RuntimeError("Unable to select Satochip applet with known AIDs")

    def get_status(self):
        response, sw1, sw2 = self.transmit([CARD_EDGE_CLA, INS_GET_STATUS, 0x00, 0x00])
        return response, sw1, sw2, parse_status(response)

    def initiate_secure_channel(self):
        self.sc = self.SecureChannel(self.loglevel)
        pubkey = list(self.sc.sc_pubkey_serialized)
        apdu = [CARD_EDGE_CLA, INS_INIT_SECURE_CHANNEL, 0x00, 0x00, len(pubkey)] + pubkey
        response, sw1, sw2 = self.transmit_raw(apdu)
        if (sw1, sw2) != (0x90, 0x00):
            raise RuntimeError("INS_INIT_SECURE_CHANNEL failed with SW={0}".format(format_sw(sw1, sw2)))

        data_size = (response[0] << 8) | response[1]
        coordx = response[2 : 2 + data_size]
        msg_size = 2 + data_size
        msg = response[:msg_size]
        sig_size = (response[msg_size] << 8) | response[msg_size + 1]
        sig = response[msg_size + 2 : msg_size + 2 + sig_size]
        pubkey_obj = recover_pubkey_from_signature(
            self.ECPubkey,
            self.InvalidECPointException,
            coordx,
            msg,
            sig,
        )
        self.sc.initiate_secure_channel(pubkey_obj.get_public_key_bytes(compressed=False))
        self.needs_secure_channel = True
        return pubkey_obj

    def verify_pin(self, pin_text):
        pin_bytes = pin_text.encode("utf-8")
        apdu = [CARD_EDGE_CLA, INS_VERIFY_PIN, 0x00, 0x00, len(pin_bytes)] + list(pin_bytes)
        response, sw1, sw2 = self.transmit(apdu)
        return response, sw1, sw2

    def setup(self, pin_text):
        pin0 = list(pin_text.encode("utf-8"))
        ublk0 = list(os.urandom(16))
        pin1 = list(os.urandom(16))
        ublk1 = list(os.urandom(16))
        default_pin = [0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30]
        pin_tries0 = 0x05
        ublk_tries0 = 0x01
        pin_tries1 = 0x01
        ublk_tries1 = 0x01
        memsize = 32
        memsize2 = 0
        create_object_acl = 0x01
        create_key_acl = 0x01
        create_pin_acl = 0x01

        data = []
        data += [len(default_pin)] + default_pin
        data += [pin_tries0, ublk_tries0, len(pin0)] + pin0 + [len(ublk0)] + ublk0
        data += [pin_tries1, ublk_tries1, len(pin1)] + pin1 + [len(ublk1)] + ublk1
        data += [memsize >> 8, memsize & 0xFF, memsize2 >> 8, memsize2 & 0xFF]
        data += [create_object_acl, create_key_acl, create_pin_acl]
        apdu = [CARD_EDGE_CLA, INS_SETUP, 0x00, 0x00, len(data)] + data
        return self.transmit(apdu)


def ensure_sw(sw1, sw2, context):
    if (sw1, sw2) != (0x90, 0x00):
        raise RuntimeError("{0} failed with SW={1}".format(context, format_sw(sw1, sw2)))


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s | %(name)s | %(message)s",
    )

    readers = list_readers()
    chosen_reader = select_reader(args.reader, args.reader_index)
    if args.list_readers:
        for index, reader in enumerate(readers):
            marker = "*" if str(reader) == str(chosen_reader) else " "
            print("[{0}] {1}: {2}".format(marker, index, reader))
        return 0

    pysatochip_src = Path(args.pysatochip_src).resolve()
    SecureChannel, ECPubkey, InvalidECPointException = bootstrap_modules(pysatochip_src)

    backend = None if args.no_reference else load_reference_backend()
    if not args.no_reference and backend is None:
        LOG.warning(
            "No software Ed25519 backend found. Install 'cryptography' or 'PyNaCl', or rerun with --no-reference."
        )

    seed = bytes.fromhex(normalize_hex(args.seed_hex))
    if len(seed) < 16 or len(seed) > 64:
        raise RuntimeError("Seed length must be between 16 and 64 bytes.")

    message = parse_message(args)
    depth, path_bytes, path_indexes = parse_hardened_path(args.path)

    connection = chosen_reader.createConnection()
    connection.connect()
    session = CardSession(
        connection,
        SecureChannel,
        ECPubkey,
        InvalidECPointException,
        logging.DEBUG if args.debug else logging.INFO,
    )

    try:
        session.select_applet()
        atr = bytes(connection.getATR()).hex()
        print("Reader: {0}".format(chosen_reader))
        print("ATR   : {0}".format(atr))

        raw_status, sw1, sw2, status = session.get_status()
        if (sw1, sw2) not in ((0x90, 0x00), (0x9C, 0x04)):
            raise RuntimeError("card_get_status failed with SW={0}".format(format_sw(sw1, sw2)))

        if status.get("needs_secure_channel"):
            session.initiate_secure_channel()
            raw_status, sw1, sw2, status = session.get_status()
            ensure_sw(sw1, sw2, "card_get_status after secure channel")

        if not status.get("setup_done", False):
            if not args.setup:
                raise RuntimeError("Card is not set up. Rerun with --setup to initialize it.")
            response, sw1, sw2 = session.setup(args.pin)
            ensure_sw(sw1, sw2, "INS_SETUP")
            LOG.info("Card setup completed: %s", response.hex())
            raw_status, sw1, sw2, status = session.get_status()
            ensure_sw(sw1, sw2, "card_get_status after setup")

        print_status(raw_status, status)

        if status.get("needs2FA"):
            raise RuntimeError("2FA is enabled. This script does not support the extra HMAC.")

        response, sw1, sw2 = session.verify_pin(args.pin)
        ensure_sw(sw1, sw2, "INS_VERIFY_PIN")

        if args.reset_before:
            pin_bytes = args.pin.encode("utf-8")
            response, sw1, sw2 = session.transmit(
                [CARD_EDGE_CLA, INS_ED25519_RESET_SEED, len(pin_bytes), 0x00, len(pin_bytes)]
                + list(pin_bytes)
            )
            if ((sw1 << 8) | sw2) != SW_ED25519_UNINITIALIZED_SEED:
                ensure_sw(sw1, sw2, "INS_ED25519_RESET_SEED")
            response, sw1, sw2 = session.verify_pin(args.pin)
            ensure_sw(sw1, sw2, "INS_VERIFY_PIN after reset-before")

        response, sw1, sw2 = session.transmit(
            [CARD_EDGE_CLA, INS_ED25519_IMPORT_SEED, len(seed), 0x00, len(seed)] + list(seed)
        )
        if ((sw1 << 8) | sw2) == SW_ED25519_INITIALIZED_SEED:
            raise RuntimeError(
                "Ed25519 seed is already initialized. Use --reset-before for a repeatable test run."
            )
        ensure_sw(sw1, sw2, "INS_ED25519_IMPORT_SEED")
        card_master_pub = parse_blob_response(response, "master public key", 32)

        raw_status, sw1, sw2, status = session.get_status()
        ensure_sw(sw1, sw2, "card_get_status after import")
        print_status(raw_status, status)

        response, sw1, sw2 = session.transmit(
            [CARD_EDGE_CLA, INS_ED25519_GET_PUBLIC_KEY, depth, 0x00, len(path_bytes)] + list(path_bytes)
        )
        ensure_sw(sw1, sw2, "INS_ED25519_GET_PUBLIC_KEY")
        card_child_pub = parse_blob_response(response, "child public key", 32)

        sign_payload = path_bytes + len(message).to_bytes(2, "big") + message
        response, sw1, sw2 = session.transmit(
            [CARD_EDGE_CLA, INS_ED25519_SIGN, depth, 0x00, len(sign_payload)] + list(sign_payload)
        )
        ensure_sw(sw1, sw2, "INS_ED25519_SIGN")
        card_signature = parse_blob_response(response, "signature", 64)

        print("Master pubkey(card)   : {0}".format(card_master_pub.hex()))
        print("Path                  : {0}".format(args.path))
        print("Child pubkey(card)    : {0}".format(card_child_pub.hex()))
        print("Signature(card)       : {0}".format(card_signature.hex()))

        if backend is not None:
            master_seed, _dummy_chain = slip10_derive(seed, [])
            ref_master_pub = backend.public_key(master_seed)
            child_seed, _dummy_chain = slip10_derive(seed, path_indexes)
            ref_child_pub = backend.public_key(child_seed)
            ref_signature = backend.sign(child_seed, message)
            backend.verify(ref_child_pub, card_signature, message)

            print("Master pubkey(ref)    : {0}".format(ref_master_pub.hex()))
            print("Child pubkey(ref)     : {0}".format(ref_child_pub.hex()))
            print("Signature(ref)        : {0}".format(ref_signature.hex()))

            if card_master_pub != ref_master_pub:
                raise RuntimeError("Master public key mismatch between card and software reference.")
            if card_child_pub != ref_child_pub:
                raise RuntimeError("Derived child public key mismatch between card and software reference.")
            if card_signature != ref_signature:
                raise RuntimeError("Signature mismatch between card and software reference.")
            print("Reference check       : PASS")
        else:
            print("Reference check       : SKIPPED")

        if args.reset_after:
            pin_bytes = args.pin.encode("utf-8")
            response, sw1, sw2 = session.transmit(
                [CARD_EDGE_CLA, INS_ED25519_RESET_SEED, len(pin_bytes), 0x00, len(pin_bytes)]
                + list(pin_bytes)
            )
            ensure_sw(sw1, sw2, "INS_ED25519_RESET_SEED")

        print("Result                : PASS")
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
