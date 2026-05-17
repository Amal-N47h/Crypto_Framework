#verifier_logger.py
import logging
from crypto_vimal.result_classifier import PacketStatus

# Setup logger
logger = logging.getLogger("VerifierLogger")
logger.setLevel(logging.DEBUG)

# File handler
file_handler = logging.FileHandler("verifier.log")
file_handler.setLevel(logging.DEBUG)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

# Formatter
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)


def log_result(result):
    if result.status == PacketStatus.VALID:
        logger.info(f"{result.packet_id} - {result.status.value} - {result.reason}")

    elif result.status in [PacketStatus.TAMPERED, PacketStatus.DECRYPTION_ERROR]:
        logger.error(f"{result.packet_id} - {result.status.value} - {result.reason}")

    else:
        logger.warning(f"{result.packet_id} - {result.status.value} - {result.reason}")