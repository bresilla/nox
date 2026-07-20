use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use bech32::FromBase32;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use sha2::{Digest, Sha256};
use yubikey::piv::{AlgorithmId, RetiredSlotId, SlotId};
use zeroize::Zeroize;

use crate::{
    sops::metadata::{PivP256Stanza, SopsAgeEntry},
    yubikey_probe::RecipientInfo,
    Result,
};

const FILE_KEY_BYTES: usize = 16;
const ENCRYPTED_FILE_KEY_BYTES: usize = 32;
const EPK_BYTES: usize = 33;
const TAG_BYTES: usize = 4;
const STANZA_KEY_LABEL: &[u8] = b"piv-p256";

pub struct UnwrappedFileKey {
    pub fingerprint: String,
}

pub fn unwrap_entry(
    entry: &SopsAgeEntry,
    yubikey_info: &RecipientInfo,
) -> Result<UnwrappedFileKey> {
    let stanza = entry
        .stanzas
        .iter()
        .find_map(|stanza| stanza.piv_p256())
        .ok_or_else(|| format!("recipient {} has no valid piv-p256 stanza", entry.recipient))?;

    let file_key = unwrap_piv_p256(&entry.recipient, stanza, yubikey_info)?;

    Ok(UnwrappedFileKey {
        fingerprint: fingerprint(&file_key),
    })
}

pub fn unwrap_piv_p256(
    recipient: &str,
    stanza: PivP256Stanza<'_>,
    yubikey_info: &RecipientInfo,
) -> Result<[u8; FILE_KEY_BYTES]> {
    let recipient_key = decode_yubikey_recipient(recipient)?;
    let parsed = ParsedPivP256Stanza::parse(stanza)?;
    if parsed.tag != static_tag(&recipient_key) {
        return Err("piv-p256 stanza tag does not match recipient public key".to_string());
    }

    let mut yubikey = open_yubikey(&yubikey_info.serial)?;
    verify_pin(&mut yubikey, &yubikey_info.serial)?;
    let slot = retired_slot(yubikey_info.slot_id)?;
    let shared_secret = yubikey::piv::decrypt_data(
        &mut yubikey,
        parsed.ephemeral_key_uncompressed.as_bytes(),
        AlgorithmId::EccP256,
        SlotId::Retired(slot),
    )
    .map_err(|err| format!("YubiKey ECDH failed: {err}"))?;

    let mut salt = Vec::with_capacity(EPK_BYTES * 2);
    salt.extend_from_slice(&parsed.ephemeral_key_compressed);
    salt.extend_from_slice(&recipient_key);

    let enc_key = hkdf(&salt, STANZA_KEY_LABEL, shared_secret.as_ref())?;
    let file_key = aead_decrypt(&enc_key, FILE_KEY_BYTES, &parsed.encrypted_file_key)
        .map_err(|_| "failed to decrypt wrapped age file key".to_string())?;
    if file_key.len() != FILE_KEY_BYTES {
        return Err(format!(
            "unexpected age file key length {}; expected {FILE_KEY_BYTES}",
            file_key.len()
        ));
    }

    file_key
        .try_into()
        .map_err(|_| "unexpected age file key length".to_string())
}

struct ParsedPivP256Stanza {
    tag: [u8; TAG_BYTES],
    ephemeral_key_compressed: [u8; EPK_BYTES],
    ephemeral_key_uncompressed: p256::EncodedPoint,
    encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES],
}

impl ParsedPivP256Stanza {
    fn parse(stanza: PivP256Stanza<'_>) -> Result<Self> {
        let tag = decode_fixed::<TAG_BYTES>(stanza.tag_arg, "piv-p256 tag")?;
        let ephemeral_key_compressed =
            decode_fixed::<EPK_BYTES>(stanza.ephemeral_key_arg, "piv-p256 ephemeral key")?;
        let encoded = p256::EncodedPoint::from_bytes(ephemeral_key_compressed)
            .map_err(|err| format!("invalid compressed ephemeral key: {err}"))?;
        if !encoded.is_compressed() {
            return Err("piv-p256 ephemeral key is not compressed".to_string());
        }
        let public_key =
            Option::<p256::PublicKey>::from(p256::PublicKey::from_encoded_point(&encoded))
                .ok_or_else(|| "piv-p256 ephemeral key is not a valid P-256 point".to_string())?;
        let ephemeral_key_uncompressed = public_key.to_encoded_point(false);
        let encrypted_file_key = stanza
            .encrypted_file_key
            .try_into()
            .map_err(|_| "invalid encrypted file-key body length".to_string())?;

        Ok(Self {
            tag,
            ephemeral_key_compressed,
            ephemeral_key_uncompressed,
            encrypted_file_key,
        })
    }
}

fn decode_yubikey_recipient(recipient: &str) -> Result<[u8; EPK_BYTES]> {
    let (hrp, data, _) =
        bech32::decode(recipient).map_err(|err| format!("invalid age recipient: {err}"))?;
    if hrp != "age1yubikey" {
        return Err(format!("recipient is not legacy age1yubikey: {recipient}"));
    }
    let bytes = Vec::<u8>::from_base32(&data)
        .map_err(|err| format!("invalid age1yubikey payload: {err}"))?;
    bytes
        .try_into()
        .map_err(|_| "age1yubikey payload is not a compressed P-256 public key".to_string())
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let bytes = STANDARD_NO_PAD
        .decode(value.as_bytes())
        .or_else(|_| STANDARD.decode(value.as_bytes()))
        .map_err(|err| format!("failed to decode {label}: {err}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} is not {N} bytes"))
}

fn open_yubikey(serial: &str) -> Result<yubikey::YubiKey> {
    let serial = serial
        .parse::<u32>()
        .map_err(|err| format!("invalid YubiKey serial '{serial}': {err}"))?;
    yubikey::YubiKey::open_by_serial(yubikey::Serial(serial))
        .map_err(|err| format!("failed to open YubiKey serial {serial}: {err}"))
}

fn verify_pin(yubikey: &mut yubikey::YubiKey, serial: &str) -> Result<()> {
    for attempt in 1..=3 {
        let prompt = format!("Enter PIN for YubiKey serial {serial}: ");
        let mut pin = rpassword::prompt_password(prompt)
            .map_err(|err| format!("failed to read PIN: {err}"))?;
        let result = yubikey.verify_pin(pin.as_bytes());
        pin.zeroize();

        match result {
            Ok(()) => return Ok(()),
            Err(yubikey::Error::WrongPin { tries }) if attempt < 3 => {
                eprintln!("Wrong PIN. Retries left: {tries}");
            }
            Err(yubikey::Error::WrongPin { tries }) => {
                return Err(format!("wrong YubiKey PIN; retries left: {tries}"));
            }
            Err(yubikey::Error::PinLocked) => return Err("YubiKey PIN is locked".to_string()),
            Err(err) => return Err(format!("YubiKey PIN verification failed: {err}")),
        }
    }

    Err("YubiKey PIN verification failed".to_string())
}

fn retired_slot(slot_id: u8) -> Result<RetiredSlotId> {
    RetiredSlotId::try_from(slot_id)
        .map_err(|_| format!("invalid retired PIV slot id 0x{slot_id:02x}"))
}

fn hkdf(salt: &[u8], label: &[u8], ikm: &[u8]) -> Result<[u8; 32]> {
    let mut okm = [0; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(label, &mut okm)
        .map_err(|err| format!("HKDF failed: {err}"))?;
    Ok(okm)
}

fn aead_decrypt(
    key: &[u8; 32],
    size: usize,
    ciphertext: &[u8],
) -> std::result::Result<Vec<u8>, ()> {
    if ciphertext.len() != size + 16 {
        return Err(());
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher.decrypt(&[0; 12].into(), ciphertext).map_err(|_| ())
}

fn static_tag(pk: &[u8]) -> [u8; TAG_BYTES] {
    Sha256::digest(pk)[0..TAG_BYTES]
        .try_into()
        .expect("slice length is fixed")
}

fn fingerprint(file_key: &[u8]) -> String {
    let digest = Sha256::digest(file_key);
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
